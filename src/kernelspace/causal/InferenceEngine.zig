// TODO: missing syscalls to cover:

// pthread_kill -> tgkill
//
// sigwait_wait
// sigwaitinfo
// sigtimedwait
// sigsuspend
//
// TODO: remove the thread_wait_count_map .? since they can actually be null
// TODO: create error handling with push queue
const std = @import("std");
const kernel = @import("kernel");
const thread_safe = @import("thread_safe.zig");

const Pid = std.os.linux.pid_t;
const Tid = Pid;
const FutexHandle = usize;
const ProgressPoint = usize;

const allocator = kernel.heap.atomic_allocator;

const ThreadProgressMap = thread_safe.SegmentedSparseVector(ProgressPoint, std.math.maxInt(ProgressPoint));
const ProgressTransferMap = thread_safe.AddressMap(ProgressPoint, std.math.maxInt(ProgressPoint));

const WaitProbeCtx = struct {
    lag_debit: ProgressPoint,
    futex_handle: FutexHandle,
};

const Probes = struct {
    pub const FilterAndProbe = struct {
        filter: [:0]const u8,
        probe: kernel.probe.F,
    };

    clone: FilterAndProbe,
    futex_wait: FilterAndProbe,
    futex_wake: FilterAndProbe,
    exit: FilterAndProbe,

    pub fn registerAll(this: *@This()) !void {
        inline for (std.meta.fields(@This())) |field| {
            const f = &@field(this, field.name);
            try f.probe.register(f.filter, null);
        }
    }

    pub fn unregisterAll(this: *@This()) void {
        inline for (std.meta.fields(@This())) |field| {
            const f = &@field(this, field.name);
            f.probe.unregister();
        }
    }

    pub fn enableAll(this: *@This()) void {
        inline for (std.meta.fields(@This())) |field| {
            const f = &@field(this, field.name);
            f.probe.enable();
        }
    }

    pub fn disableAll(this: *@This()) void {
        inline for (std.meta.fields(@This())) |field| {
            const f = &@field(this, field.name);
            f.probe.disable();
        }
    }
};

instrumented_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
experiment_length: std.atomic.Value(usize),

delay_per_point_us: std.atomic.Value(usize),
selected_line: std.atomic.Value(usize),

lead_progress: std.atomic.Value(ProgressPoint),
thread_points: ThreadProgressMap,
transfer_map: ProgressTransferMap,
active_threads: std.atomic.Value(usize),

profiler_thread: *kernel.Thread,
sampler: *kernel.PerfEvent,
line_selector: *kernel.PerfEvent,

probes: Probes,

const task_clock_attr = std.os.linux.perf_event_attr{
    .type = .SOFTWARE,
    .config = @intFromEnum(std.os.linux.PERF.COUNT.SW.TASK_CLOCK),
    .sample_period_or_freq = 100,
    .wakeup_events_or_watermark = 1,
    .flags = .{
        .disabled = true,
        .inherit = true,
        .exclude_host = true,
        .exclude_guest = true,
        .exclude_hv = true,
        .exclude_idle = true,
        .exclude_kernel = true,
    },
};

pub fn init() !@This() {
    return .{
        .instrumented_pid = .init(0),
        .experiment_length = .init(100 * std.time.us_per_ms),
        .delay_per_point_us = .init(0),
        .selected_line = .init(0),

        .lead_progress = .init(0),
        .thread_points = .init,
        .transfer_map = try .init(allocator),
        .active_threads = .init(1),

        .profiler_thread = undefined,
        .sampler = undefined,
        .line_selector = undefined,

        .probes = .{
            .clone = .{
                .filter = "kernel_clone",
                .probe = .{ .callbacks = .{ .post_handler = onClone } },
            },

            .futex_wait = .{
                .filter = "futex_wait",
                .probe = .{ .callbacks = .{ .pre_handler = onFutexWaitStart, .post_handler = onFutexWaitEnd }, .entry_data_size = @sizeOf(WaitProbeCtx) },
            },

            .futex_wake = .{
                .filter = "futex_wake",
                .probe = .{ .callbacks = .{ .pre_handler = onFutexWake } },
            },

            .exit = .{
                .filter = "do_exit",
                .probe = .{ .callbacks = .{ .pre_handler = onExit } },
            },
        },
    };
}

pub fn deinit(this: *@This()) void {
    this.profiler_thread.stop();

    this.line_selector.deinit();
    this.sampler.deinit();

    this.probes.unregisterAll();

    this.transfer_map.deinit(allocator);
    this.thread_points.deinit(allocator);

    std.log.info("Global virtual clock at exit: {}", .{this.lead_progress.load(.monotonic)});
}

pub fn profilePid(this: *@This(), pid: Pid) !void {
    this.thread_points.put(allocator, @intCast(pid), 0) catch {};
    this.instrumented_pid.store(pid, .release);

    try this.probes.registerAll();
    this.probes.disableAll();

    var attr = task_clock_attr;
    this.line_selector = kernel.PerfEvent.init(&attr, -1, pid, onLineSelectTick, this) catch return;

    attr.sample_period_or_freq = 1 * std.time.ns_per_ms;
    this.sampler = kernel.PerfEvent.init(&attr, -1, pid, onProfilerTick, this) catch return;

    this.profiler_thread = .run(profileLoop, this, "pside_loop");
}

fn profileLoop(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *@This() = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldThisStop()) {
        this.setExperimentParameters() catch return 0;
        const snapshot = this.takeSnapshot();

        this.sampler.enable();
        this.probes.enableAll();
        kernel.time.sleep.us(this.experiment_length.load(.monotonic));
        this.sampler.disable();
        this.probes.disableAll();

        // TODO: winddown logic
        // TODO: compute values
        _ = snapshot;
    }

    return 0;
}

fn setExperimentParameters(this: *@This()) !void {
    this.selected_line.store(0, .monotonic);
    this.line_selector.enable();

    //TODO: select dealy

    while (this.selected_line.load(.monotonic) == 0) {
        @branchHint(.unlikely);
        if (kernel.Thread.shouldThisStop()) return error.Quit;
    }
    this.line_selector.disable();
}

fn takeSnapshot(this: @This()) usize {
    _ = this;
    return 0;
}

// Perf event callabcks

fn onLineSelectTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(event.context().?));
    this.selected_line.store(regs.ip, .monotonic);
}

fn onProfilerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(event.context().?));
    if (this.selected_line.load(.monotonic) == regs.ip) this.increment();
}

// Probes callback helpers

fn increment(this: *@This()) void {
    if (this.thread_points.increment(@intCast(kernel.current_task.tid()))) |counter| {
        _ = this.lead_progress.fetchMax(counter, .monotonic);
    }
}

fn notTarget(this: *@This()) bool {
    return kernel.current_task.pid() != this.instrumented_pid.load(.monotonic);
}

fn thisFromProbe(comptime name: []const u8, probe: *kernel.probe.F) *@This() {
    const probe_ptr: *Probes.FilterAndProbe = @fieldParentPtr("probe", probe);
    return @alignCast(@fieldParentPtr("probes", @as(*Probes, @fieldParentPtr(name, probe_ptr))));
}

// Probes callbacks

fn onClone(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, _: ?*anyopaque) callconv(.c) void {
    const this = thisFromProbe("clone", probe);
    if (this.notTarget()) return;

    const parent_wait_count = this.thread_points.get(@intCast(kernel.current_task.tid())).?;
    this.thread_points.put(allocator, @intCast(regs.getReturnValue()), parent_wait_count) catch {};

    _ = this.active_threads.fetchAdd(1, .monotonic);
}

fn onFutexWaitStart(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) c_int {
    const this = thisFromProbe("futex_wait", probe);
    if (this.notTarget()) return 1; // returning 1 will cancel futexWaitEnd call

    const data: *WaitProbeCtx = @ptrCast(@alignCast(data_opaque.?));

    data.lag_debit = this.lead_progress.load(.monotonic) - this.thread_points.get(@intCast(kernel.current_task.tid())).?;
    data.futex_handle = regs.getArgument(0); // We save the handle since it gets clobbered

    return 0;
}

fn onFutexWaitEnd(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) void {
    const this = thisFromProbe("futex_wait", probe);
    if (regs.getReturnValue() != 0) return; // Not woke by other threads.

    const data: *WaitProbeCtx = @ptrCast(@alignCast(data_opaque.?));

    kernel.time.delay.us(data.lag_debit * this.delay_per_point_us.load(.monotonic));

    const waker_wait_counter = this.transfer_map.get(data.futex_handle) orelse {
        @branchHint(.cold);
        //TODO: signal error
        return;
    };

    this.thread_points.put(allocator, @intCast(kernel.current_task.tid()), waker_wait_counter) catch {};
}

fn onFutexWake(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    const this = thisFromProbe("futex_wake", probe);
    if (this.notTarget()) return 1;

    const tid: usize = @intCast(kernel.current_task.tid());

    const this_thread_wait_counter = this.thread_points.get(tid).?;
    this.transfer_map.put(allocator, regs.getArgument(0), this_thread_wait_counter) catch return 1; //TODO: should signal error;

    const wait_debit = this.lead_progress.load(.monotonic) - this_thread_wait_counter;
    kernel.time.delay.us(wait_debit * this.delay_per_point_us.load(.monotonic));

    return 0;
}

fn onExit(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, _: *kernel.probe.FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    const this = thisFromProbe("exit", probe);
    if (this.notTarget()) return 1;
    const this_thread_wait_count = this.thread_points.get(@intCast(kernel.current_task.tid())).?;

    const wait_debit = this.lead_progress.load(.monotonic) - this_thread_wait_count;
    kernel.time.delay.us(wait_debit * this.delay_per_point_us.load(.monotonic));

    _ = this.active_threads.fetchSub(1, .monotonic);

    return 0;
}
