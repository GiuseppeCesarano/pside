const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;

const arch = @import("arch");
const kernel = @import("kernel");
pub const Task = kernel.Task;
pub const VmaRange = kernel.VmaRange;

pub const Clocks = @import("Clocks.zig");
pub const Delays = @import("Delays.zig");

pub const UserReadError = error{Fault};
pub const VmaSnapshotError = error{NoMatchingVma} || std.mem.Allocator.Error;
pub const AttachError = kernel.RegisterTraceError || kernel.PerfEvent.CreateKernelCounterError;

pub fn executableVmas(allocator: std.mem.Allocator, task: *Task, filter: [:0]const u8) VmaSnapshotError![]VmaRange {
    const filter_z: ?[*:0]const u8 = if (filter.len > 0) filter.ptr else null;

    var capacity: usize = 32;
    while (true) {
        const ranges = try allocator.alloc(VmaRange, capacity);
        errdefer allocator.free(ranges);

        const count = task.snapshotExecutableVmas(filter_z, ranges);
        if (count == 0) return VmaSnapshotError.NoMatchingVma;

        if (count <= capacity) {
            assert(allocator.resize(ranges, count));
            return ranges[0..count];
        }

        allocator.free(ranges);
        capacity = count;
    }
}

pub fn followsCall(return_address: usize) bool {
    var code: [arch.call_window_len]u8 = undefined;
    readUser(&code, return_address - code.len) catch return false;

    return arch.endsWithCall(&code);
}

fn readUser(dst: []u8, address: usize) UserReadError!void {
    if (kernel.copyFromUserNofault(dst, address) != 0) return UserReadError.Fault;
}

pub const Sample = struct {
    regs: *kernel.PtRegs,

    pub fn inUserMode(this: Sample) bool {
        return kernel.userMode(this.regs);
    }

    pub fn userIp(this: Sample) usize {
        if (this.inUserMode()) return this.regs.instructionPointer();

        const ip = kernel.currentUserIp();
        const call_site = ip - arch.syscall_instruction.len;
        var code: [arch.syscall_instruction.len]u8 = undefined;
        readUser(&code, call_site) catch return ip;

        return if (std.mem.eql(u8, &code, &arch.syscall_instruction)) call_site else ip;
    }

    pub fn readUserStack(this: Sample, words: []usize) UserReadError!void {
        const regs = if (this.inUserMode()) this.regs else kernel.currentUserRegs();
        try readUser(std.mem.sliceAsBytes(words), regs.userStackPointer());
    }
};

pub fn Handlers(comptime Context: type) type {
    return struct {
        sleep: fn (*Context, *Task) void,
        wake: fn (*Context, wakee: *Task, waker: ?*Task) void,
        fork: fn (*Context, parent: *Task, child: *Task) void,
        exit: fn (*Context, *Task) void,
        sample: fn (*Context, Sample) void,
    };
}

pub fn Probes(comptime Context: type, comptime handlers: Handlers(Context)) type {
    return struct {
        process: linux.pid_t align(std.atomic.cache_line),
        context: *Context,
        sampler: ?*kernel.PerfEvent,

        const ProbeSet = @This();

        pub const detached: ProbeSet = .{ .process = 0, .context = undefined, .sampler = null };

        pub fn attach(this: *ProbeSet, context: *Context, task: *Task, sample_frequency: u64) AttachError!void {
            assert(this.sampler == null);

            this.context = context;
            this.process = task.tgidNr();

            errdefer kernel.tracepoint.synchronizeUnregister();

            try kernel.registerTraceSchedSwitch(onSchedSwitch, this);
            errdefer kernel.unregisterTraceSchedSwitch(onSchedSwitch, this);

            try kernel.registerTraceSchedWaking(onSchedWaking, this);
            errdefer kernel.unregisterTraceSchedWaking(onSchedWaking, this);

            try kernel.registerTraceTaskNewtask(onTaskNewtask, this);
            errdefer kernel.unregisterTraceTaskNewtask(onTaskNewtask, this);

            try kernel.registerTraceSchedProcessExit(onSchedProcessExit, this);
            errdefer kernel.unregisterTraceSchedProcessExit(onSchedProcessExit, this);

            var sampler_attr: linux.perf_event_attr = .{
                .type = .SOFTWARE,
                .config = @backingInt(linux.PERF.COUNT.SW.TASK_CLOCK),
                .sample_period_or_freq = sample_frequency,
                .flags = .{
                    .freq = true,
                    .disabled = true,
                    .inherit = true,
                    .inherit_thread = true,
                    .exclude_guest = true,
                    .exclude_hv = true,
                    .exclude_idle = true,
                },
            };
            this.sampler = try kernel.PerfEvent.createKernelCounter(&sampler_attr, -1, task, onPerfOverflow, this);
            this.sampler.?.enable();
        }

        pub fn detach(this: *ProbeSet) void {
            const sampler = this.sampler orelse return;

            kernel.unregisterTraceSchedSwitch(onSchedSwitch, this);
            kernel.unregisterTraceSchedWaking(onSchedWaking, this);
            kernel.unregisterTraceSchedProcessExit(onSchedProcessExit, this);
            kernel.unregisterTraceTaskNewtask(onTaskNewtask, this);
            kernel.tracepoint.synchronizeUnregister();

            _ = sampler.releaseKernel();
            this.* = .detached;
        }

        fn isProfiled(this: *const ProbeSet, task: *Task) bool {
            return task.tgidNr() == this.process;
        }

        fn profiledWaker(this: *const ProbeSet) ?*Task {
            if (!kernel.inTask()) return null;

            const waker = Task.current();
            return if (this.isProfiled(waker)) waker else null;
        }

        fn fromData(data: ?*anyopaque) *ProbeSet {
            return @ptrCast(@alignCast(data.?));
        }

        fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *Task, _: *Task) callconv(.c) void {
            const this = fromData(data);

            if (this.isProfiled(prev) and !prev.isRunning() and !prev.isDead())
                handlers.sleep(this.context, prev);
        }

        fn onSchedWaking(data: ?*anyopaque, wakee: *Task) callconv(.c) void {
            const this = fromData(data);

            if (!this.isProfiled(wakee) or wakee.isRunning() or wakee.isDead()) return;

            handlers.wake(this.context, wakee, this.profiledWaker());
        }

        fn onTaskNewtask(data: ?*anyopaque, child: *Task, clone_flags: c_ulong) callconv(.c) void {
            const this = fromData(data);
            const parent = Task.current();

            if (!this.isProfiled(parent)) return;
            if (clone_flags & linux.CLONE.THREAD == 0) return;

            assert(this.isProfiled(child));

            handlers.fork(this.context, parent, child);
        }

        fn onSchedProcessExit(data: ?*anyopaque, task: *Task, _: bool) callconv(.c) void {
            const this = fromData(data);

            if (this.isProfiled(task)) handlers.exit(this.context, task);
        }

        fn onPerfOverflow(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
            const this: *ProbeSet = @ptrCast(@alignCast(event.overflowHandlerContext().?));

            handlers.sample(this.context, .{ .regs = regs });
        }
    };
}
