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
    progress_debit: ProgressPoint,
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
experiment_duration_us: std.atomic.Value(usize),

profiler_thread: *kernel.Thread,

delay_per_progress_us: std.atomic.Value(usize),
selected_line: std.atomic.Value(usize),

max_progress: std.atomic.Value(ProgressPoint),
threads_progress: ThreadProgressMap,
progress_transfer_map: ProgressTransferMap,
task_work_pool: *TaskWorkPool,

sampler: *kernel.PerfEvent,

probes: [2]ProbeAndData,

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
    kernel.tracepoint.init();

    const pool = try allocator.create(TaskWorkPool);
    pool.* = .empty();

    return .{
        .instrumented_pid = .init(0),
        .experiment_duration_us = .init(100 * std.time.us_per_ms),
        .delay_per_progress_us = .init(0),
        .selected_line = .init(0),

        .max_progress = .init(0),
        .threads_progress = .init,
        .progress_transfer_map = try .init(atomic_allocator),
        .task_work_pool = pool,

        .profiler_thread = undefined,
        .sampler = undefined,

        .probes = .{
            .{
                .data = .{ .filter = "futex_wait" },
                .probe = .{ .callbacks = .{ .pre_handler = onFutexWaitStart, .post_handler = onFutexWaitEnd }, .entry_data_size = @sizeOf(WaitProbeCtx) },
            },

            .{
                .data = .{ .filter = "futex_wake" },
                .probe = .{ .callbacks = .{ .pre_handler = onFutexWake } },
            },
        },
    };
}

pub fn deinit(this: *@This()) void {
    this.profiler_thread.stop();

    this.sampler.deinit();

    kernel.tracepoint.sched_fork.unregister(onSchedFork, this);
    kernel.tracepoint.sched_exit.unregister(onSchedExit, this);
    kernel.tracepoint.sync();

    for (&this.probes) |*probe| probe.probe.unregister();

    this.progress_transfer_map.deinit(atomic_allocator);
    this.threads_progress.deinit(atomic_allocator);

    allocator.destroy(this.task_work_pool);

    std.log.info("Global virtual clock at exit: {}", .{this.max_progress.load(.monotonic)});
}

pub fn profilePid(this: *@This(), pid: Pid) !void {
    try this.threads_progress.put(atomic_allocator, @intCast(pid), 0);
    this.instrumented_pid.store(pid, .release);

    this.task_work_pool.context.store(this, .monotonic);

    try kernel.tracepoint.sched_fork.register(onSchedFork, this);
    try kernel.tracepoint.sched_exit.register(onSchedExit, this);

    for (&this.probes) |*probe| {
        const filter = probe.data.filter;
        probe.data = .{ .context = this };
        try probe.probe.register(filter, null);
    }

    var attr = task_clock_attr;
    attr.sample_period_or_freq = 1 * std.time.ns_per_ms;
    this.sampler = kernel.PerfEvent.init(&attr, -1, pid, onSamplerTick, this) catch return;

    this.profiler_thread = .run(profileLoop, this, "pside_loop");
}

fn profileLoop(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *@This() = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldThisStop()) {
        this.setExperimentParameters() catch return 0;
        const snapshot = this.takeSnapshot();

        this.sampler.enable();
        kernel.time.sleep.us(this.experiment_duration_us.load(.monotonic));
        this.sampler.disable();

        // TODO: winddown logic
        // TODO: compute values
        _ = snapshot;
    }

    return 0;
}

fn setExperimentParameters(this: *@This()) !void {
    this.selected_line.store(0, .monotonic);

    //TODO: select dealy
}

fn takeSnapshot(this: @This()) usize {
    _ = this;
    return 0;
}

// Perf event callabcks

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(event.context().?));
    const selected_line = this.selected_line.load(.monotonic);

    if (selected_line == 0) {
        @branchHint(.unlikely);
        if (this.selected_line.cmpxchgStrong(selected_line, regs.ip, .monotonic, .monotonic) == null) this.increment();
    } else if (selected_line == regs.ip) {
        this.increment();
    }
}

// callbacks helpers

fn increment(this: *@This()) void {
    if (this.threads_progress.increment(@intCast(kernel.Task.current().tid()))) |counter| {
        _ = this.max_progress.fetchMax(counter, .monotonic);
    }
}

fn shouldIgnore(this: *@This()) bool {
    return kernel.Task.current().pid() != this.instrumented_pid.load(.monotonic);
}

fn thisFromProbe(probe: *kernel.probe.F) *@This() {
    const probe_and_data: *ProbeAndData = @fieldParentPtr("probe", probe);
    return @ptrCast(@alignCast(probe_and_data.data.context));
}

fn registerForSleep(this: *@This(), task: *kernel.Task) !void {
    const work = this.task_work_pool.getEntry() orelse return; //TODO: maybe just execute the sleep.
    work.func = doSleep;
    try task.addWork(work, .signal_no_ipi);
}

// Tracepoints callbacks

fn onSchedFork(data: ?*anyopaque, parent: *kernel.Task, child: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    if (parent.pid() != this.instrumented_pid.load(.monotonic)) return;

    const parent_tid: usize = @intCast(parent.tid());
    const parent_progress = this.threads_progress.get(parent_tid) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onClone thread_poinst null", .{});
        return;
    };

    const child_tid: usize = @intCast(child.tid());
    this.threads_progress.put(atomic_allocator, child_tid, parent_progress) catch {};
}

fn onSchedExit(data: ?*anyopaque, task: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    if (task.pid() != this.instrumented_pid.load(.monotonic)) return;

    this.registerForSleep(task) catch return {}; //TODO: handle me
}

// Probes callbacks

fn onFutexWaitStart(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) c_int {
    const this = thisFromProbe(probe);
    if (this.shouldIgnore()) return 1; // returning 1 will cancel futexWaitEnd call

    const current_tid: usize = @intCast(kernel.Task.current().tid());
    const current_progress = this.threads_progress.get(current_tid) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onFutexWaitStart thread_poinst null", .{});
        return 1;
    };

    const data: *WaitProbeCtx = @ptrCast(@alignCast(data_opaque.?));
    data.progress_debit = this.max_progress.load(.monotonic) - current_progress;
    data.futex_handle = regs.getArgument(0); // We save the handle since it gets clobbered

    return 0;
}

fn onFutexWaitEnd(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) void {
    const this = thisFromProbe(probe);
    if (regs.getReturnValue() != 0) return; // Not woke by other threads.

    const data: *WaitProbeCtx = @ptrCast(@alignCast(data_opaque.?));

    const waker_progress = this.progress_transfer_map.get(data.futex_handle) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onFutexWaitEnd thread_poinst null", .{});
        return;
    };

    const current_tid: usize = @intCast(kernel.Task.current().tid());
    //TODO: we shall do something like this
    //const new_progress = waker_progress - data.progress_debit;
    const new_progress = waker_progress;
    this.threads_progress.put(atomic_allocator, current_tid, new_progress) catch {};

    this.registerForSleep(kernel.Task.current()) catch {}; //TODO: Handle me
}

fn onFutexWake(probe: *kernel.probe.F, _: c_ulong, _: c_ulong, regs: *kernel.probe.FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    const this = thisFromProbe(probe);
    if (this.shouldIgnore()) return 1;

    const current_tid: usize = @intCast(kernel.Task.current().tid());
    const current_progress = this.threads_progress.get(current_tid) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onFutexWake thread_points null", .{});
        return 1;
    };

    const futex_handle: FutexHandle = regs.getArgument(0);
    this.progress_transfer_map.put(atomic_allocator, futex_handle, current_progress) catch return 1; //TODO: should signal error;

    return 0;
}

// Task Work Callbacks

fn doSleep(work: *kernel.Task.Work) callconv(.c) void {
    const pool = TaskWorkPool.getPoolPtrFromEntryPtr(work);
    const this: *@This() = @ptrCast(@alignCast(pool.context.load(.monotonic).?));
    const current_tid: usize = @intCast(kernel.Task.current().tid());

    const current_progress = this.threads_progress.get(current_tid) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onSleepWork thread_points null", .{});
        return;
    };

    const lead_progress = this.max_progress.load(.monotonic);
    const delay_per_point = this.delay_per_progress_us.load(.monotonic);

    const delay = (lead_progress - current_progress) * delay_per_point;

    kernel.time.sleep.us(delay);

    // Unreachable is safe here since we retrived the tid before so it must be there
    // and no allocation is needed.
    this.threads_progress.put(atomic_allocator, current_tid, lead_progress) catch unreachable;
    pool.freeEntry(work);
}
