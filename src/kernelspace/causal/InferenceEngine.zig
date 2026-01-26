// TODO: handle error and rewrite catches
// TODO: missing syscalls to cover:

// pthread_kill -> tgkill
//
// sigwait_wait
// sigwaitinfo
// sigtimedwait
// sigsuspend
const std = @import("std");
const kernel = @import("kernel");
const thread_safe = @import("thread_safe.zig");

const Pid = std.os.linux.pid_t;
const Tid = Pid;
const FutexHandle = usize;
const ProgressPoint = usize;

const atomic_allocator = kernel.heap.atomic_allocator;
const allocator = kernel.heap.allocator;

const ThreadProgressMap = thread_safe.SegmentedSparseVector(ProgressPoint, std.math.maxInt(ProgressPoint));
const ProgressTransferMap = thread_safe.AddressMap(ProgressPoint, std.math.maxInt(ProgressPoint));
const TaskWorkPool = thread_safe.Pool(kernel.Task.Work);

const WaitProbeCtx = struct {
    lag_debit: ProgressPoint,
    futex_handle: FutexHandle,
};

const ProbeAndData = struct {
    probe: kernel.probe.F,
    data: union {
        filter: [*:0]const u8,
        context: *anyopaque,
    },
};

instrumented_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
experiment_length: std.atomic.Value(usize),

profiler_thread: *kernel.Thread,

delay_per_point: std.atomic.Value(usize),
selected_line: std.atomic.Value(usize),

lead_points: std.atomic.Value(ProgressPoint),
thread_points: ThreadProgressMap,
transfer_map: ProgressTransferMap,
task_work_pool: []TaskWorkPool,

sampler: *kernel.PerfEvent,
line_selector: *kernel.PerfEvent, // TODO: We shell reuse the sampler to select the line

probes: [4]ProbeAndData,

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
    try kernel.Task.findAddWork();

    const task_work_pool = try allocator.alloc(TaskWorkPool, 1);
    for (task_work_pool) |*pool| pool.* = .empty();

    return .{
        .instrumented_pid = .init(0),
        .experiment_length = .init(100 * std.time.us_per_ms),
        .delay_per_point = .init(0),
        .selected_line = .init(0),

        .lead_points = .init(0),
        .thread_points = .init,
        .transfer_map = try .init(atomic_allocator),
        .task_work_pool = task_work_pool,

        .profiler_thread = undefined,
        .sampler = undefined,
        .line_selector = undefined,

        .probes = .{
            .{
                .data = .{ .filter = "kernel_clone" },
                .probe = .{ .callbacks = .{ .post_handler = onClone } },
            },

            .{
                .data = .{ .filter = "futex_wait" },
                .probe = .{ .callbacks = .{ .pre_handler = onFutexWaitStart, .post_handler = onFutexWaitEnd }, .entry_data_size = @sizeOf(WaitProbeCtx) },
            },

            .{
                .data = .{ .filter = "futex_wake" },
                .probe = .{ .callbacks = .{ .pre_handler = onFutexWake } },
            },

            .{
                .data = .{ .filter = "do_exit" },
                .probe = .{ .callbacks = .{ .pre_handler = onExit } },
            },
        },
    };
}

pub fn deinit(this: *@This()) void {
    this.profiler_thread.stop();

    this.line_selector.deinit();
    this.sampler.deinit();

    for (&this.probes) |*probe| probe.probe.unregister();

    this.transfer_map.deinit(atomic_allocator);
    this.thread_points.deinit(atomic_allocator);
    allocator.free(this.task_work_pool);

    std.log.info("Global virtual clock at exit: {}", .{this.lead_points.load(.monotonic)});
}

pub fn profilePid(this: *@This(), pid: Pid) !void {
    this.thread_points.put(atomic_allocator, @intCast(pid), 0) catch {};
    this.instrumented_pid.store(pid, .release);

    for (this.task_work_pool) |*pool| pool.context.store(this, .monotonic);

    for (&this.probes) |*probe| {
        const filter = probe.data.filter;
        probe.data = .{ .context = this };
        try probe.probe.register(filter, null);
    }

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
        kernel.time.sleep.us(this.experiment_length.load(.monotonic));
        this.sampler.disable();

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
    if (this.thread_points.increment(@intCast(kernel.Task.current().tid()))) |counter| {
        _ = this.lead_points.fetchMax(counter, .monotonic);
    }
}

fn notTarget(this: *@This()) bool {
    return kernel.Task.current().pid() != this.instrumented_pid.load(.monotonic);
}

fn thisFromProbe(probe: *kernel.probe.F) *@This() {
    return @ptrCast(@alignCast(@as(*ProbeAndData, @ptrCast(probe)).data.context));
}

// Probes callbacks

fn onClone(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, _: ?*anyopaque) callconv(.c) void {
    const this = thisFromProbe(probe);
    if (this.notTarget()) return;

    const parent_wait_count = this.thread_points.get(@intCast(kernel.Task.current().tid())) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onClone thread_poinst null", .{});
        return;
    };

    this.thread_points.put(atomic_allocator, @intCast(regs.getReturnValue()), parent_wait_count) catch {};
}

//TODO: We could change the causality to just one probe and two sleeps, the waker thread tasks works sleeps for it's deficit
//the waked thread task wake sleeps for the wakee deficit + it's own, this should allow us to cut down on porbes.

fn onFutexWaitStart(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) c_int {
    const this = thisFromProbe(probe);
    if (this.notTarget()) return 1; // returning 1 will cancel futexWaitEnd call

    const data: *WaitProbeCtx = @ptrCast(@alignCast(data_opaque.?));

    data.lag_debit = this.lead_points.load(.monotonic) - (this.thread_points.get(@intCast(kernel.Task.current().tid())) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onFutexWaitStart thread_poinst null", .{});
        return 1;
    });

    data.futex_handle = regs.getArgument(0); // We save the handle since it gets clobbered

    return 0;
}

fn onFutexWaitEnd(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) void {
    const this = thisFromProbe(probe);
    if (regs.getReturnValue() != 0) return; // Not woke by other threads.

    const data: *WaitProbeCtx = @ptrCast(@alignCast(data_opaque.?));

    kernel.time.delay.us(data.lag_debit * this.delay_per_point.load(.monotonic));

    const waker_wait_counter = this.transfer_map.get(data.futex_handle) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onFutexWaitEnd thread_poinst null", .{});
        return;
    };

    this.thread_points.put(atomic_allocator, @intCast(kernel.Task.current().tid()), waker_wait_counter) catch {};
}

fn onFutexWake(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    const this = thisFromProbe(probe);
    if (this.notTarget()) return 1;

    const current_tid: usize = @intCast(kernel.Task.current().tid());

    const this_thread_wait_counter = this.thread_points.get(current_tid) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onFutexWake thread_points null", .{});
        return 1;
    };
    this.transfer_map.put(atomic_allocator, regs.getArgument(0), this_thread_wait_counter) catch return 1; //TODO: should signal error;

    const wait_debit = this.lead_points.load(.monotonic) - this_thread_wait_counter;
    kernel.time.delay.us(wait_debit * this.delay_per_point.load(.monotonic));

    return 0;
}

fn onExit(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, _: *kernel.probe.FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    const this = thisFromProbe(probe);
    if (this.notTarget()) return 1;

    const work = this.task_work_pool[0].getEntry() orelse return 1; //TODO: maybe just execute the sleep.
    work.func = onSleepWork;
    kernel.Task.current().addWork(work, .signal_no_ipi) catch return 1; //TODO: maybe again just execute the sleep.

    return 0;
}

// Task Work Callbacks

fn onSleepWork(work: *kernel.Task.Work) callconv(.c) void {
    const pool = TaskWorkPool.getPoolPtrFromEntryPtr(work);
    const this: *@This() = @ptrCast(@alignCast(pool.context.load(.monotonic).?));
    const current_tid: usize = @intCast(kernel.Task.current().tid());

    const current_progress = this.thread_points.get(current_tid) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onSleepWork thread_points null", .{});
        return;
    };

    const lead_progress = this.lead_points.load(.monotonic);
    const delay_per_point = this.delay_per_point.load(.monotonic);

    const delay = (lead_progress - current_progress) * delay_per_point;

    kernel.time.sleep.us(delay);

    this.thread_points.put(atomic_allocator, current_tid, lead_progress) catch unreachable; //unreachable is safe since we know that current_tid is there.
    pool.freeEntry(work);
}
