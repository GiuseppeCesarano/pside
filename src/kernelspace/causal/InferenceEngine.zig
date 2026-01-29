// TODO: handle error and rewrite catches
const std = @import("std");
const kernel = @import("kernel");
const thread_safe = @import("thread_safe.zig");

const Pid = std.os.linux.pid_t;
const Tid = Pid;
const FutexHandle = usize;
const ClockTick = usize;

const atomic_allocator = kernel.heap.atomic_allocator;
const allocator = kernel.heap.allocator;

const ThreadLocalClock = thread_safe.SegmentedSparseVector(ClockTick, std.math.maxInt(ClockTick));
const TaskWorkPool = thread_safe.Pool(kernel.Task.Work);

instrumented_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
experiment_duration: std.atomic.Value(usize),

profiler_thread: *kernel.Thread,

virtual_speedup_delay: std.atomic.Value(usize),
selected_ip: std.atomic.Value(usize),

progress: *std.atomic.Value(usize),
global_virtual_clock: std.atomic.Value(ClockTick),
thread_local_clocks: ThreadLocalClock,
task_work_pool: *TaskWorkPool,

sampler: *kernel.PerfEvent,

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

pub fn init(progress_ptr: *std.atomic.Value(usize)) !@This() {
    try kernel.Task.findAddWork();
    kernel.tracepoint.init();

    const pool = try allocator.create(TaskWorkPool);
    pool.* = .empty();

    return .{
        .instrumented_pid = .init(0),
        .experiment_duration = .init(100 * std.time.us_per_ms),
        .virtual_speedup_delay = .init(0),
        .selected_ip = .init(0),

        .progress = progress_ptr,
        .global_virtual_clock = .init(0),
        .thread_local_clocks = .init,
        .task_work_pool = pool,

        .profiler_thread = undefined,
        .sampler = undefined,
    };
}

pub fn deinit(this: *@This()) void {
    if (this.instrumented_pid.load(.monotonic) != 0) {
        this.profiler_thread.stop();
        this.sampler.deinit();

        kernel.tracepoint.sched.fork.unregister(onSchedFork, this);
        kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
        kernel.tracepoint.sched.exit.unregister(onSchedExit, this);
        kernel.tracepoint.sync();
    }

    this.thread_local_clocks.deinit(atomic_allocator);

    allocator.destroy(this.task_work_pool);

    std.log.info("Max Progress: {}", .{this.global_virtual_clock.load(.monotonic)});
}

pub fn profilePid(this: *@This(), pid: Pid) !void {
    try this.thread_local_clocks.put(atomic_allocator, @intCast(pid), 0);
    this.instrumented_pid.store(pid, .release);

    this.task_work_pool.context.store(this, .monotonic);

    try kernel.tracepoint.sched.fork.register(onSchedFork, this);
    try kernel.tracepoint.sched.waking.register(onSchedWaking, this);
    try kernel.tracepoint.sched.exit.register(onSchedExit, this);

    var attr = task_clock_attr;
    attr.sample_period_or_freq = 1 * std.time.ns_per_ms;
    this.sampler = kernel.PerfEvent.init(&attr, -1, pid, onSamplerTick, this) catch return;

    this.profiler_thread = .run(profileLoop, this, "pside_loop");
}

fn profileLoop(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *@This() = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldThisStop()) {
        this.setExperimentParameters() catch return 0;

        const baseline_virtual_clock = this.global_virtual_clock.load(.monotonic);
        const baseline_progress = this.progress.load(.monotonic);
        const start_wall_time = kernel.time.now.us();

        this.sampler.enable();
        kernel.time.sleep.us(this.experiment_duration.load(.monotonic));
        this.sampler.disable();

        // TODO: wait for all threads to pay sleep

        // Calculation
        const wall_duration = kernel.time.now.us() - start_wall_time;
        const progress_delta = this.progress.load(.monotonic) - baseline_progress;
        const virtual_ticks = this.global_virtual_clock.load(.monotonic) - baseline_virtual_clock;
        std.debug.assert(virtual_ticks >= 0);

        const virtual_throughput = @divFloor(progress_delta * std.time.us_per_ms, wall_duration - (@as(usize, @intCast(virtual_ticks)) * this.virtual_speedup_delay.load(.monotonic)));
        _ = virtual_throughput; // ops/ms
    }
    return 0;
}

fn setExperimentParameters(this: *@This()) !void {
    this.selected_ip.store(0, .monotonic);

    //TODO: select dealy
}

// Perf event callabcks

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(event.context().?));
    const selected_line = this.selected_ip.load(.monotonic);

    if (selected_line == 0) {
        @branchHint(.unlikely);
        if (this.selected_ip.cmpxchgStrong(selected_line, regs.ip, .monotonic, .monotonic) == null) this.increment();
    } else if (selected_line == regs.ip) {
        this.increment();
    }

    this.registerForSleep(kernel.Task.current()) catch return {}; //TODO: handle me
}

// callbacks helpers

fn increment(this: *@This()) void {
    if (this.thread_local_clocks.increment(@intCast(kernel.Task.current().tid()))) |counter| {
        _ = this.global_virtual_clock.fetchMax(counter, .monotonic);
    }
}

fn shouldIgnore(this: *@This()) bool {
    return kernel.Task.current().pid() != this.instrumented_pid.load(.monotonic);
}

fn registerForSleep(this: *@This(), task: *kernel.Task) !void {
    const work = this.task_work_pool.getEntry() orelse return; //TODO: maybe just execute the sleep.
    work.func = doSleep;
    try task.addWork(work, .@"resume");
}

// Tracepoints callbacks

fn onSchedFork(data: ?*anyopaque, parent: *kernel.Task, child: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    if (parent.pid() != this.instrumented_pid.load(.monotonic)) return;

    const parent_tid: usize = @intCast(parent.tid());
    const parent_clock = this.thread_local_clocks.get(parent_tid) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onClone thread_poinst null", .{});
        return;
    };

    const child_tid: usize = @intCast(child.tid());
    this.thread_local_clocks.put(atomic_allocator, child_tid, parent_clock) catch {};
}

fn onSchedWaking(data: ?*anyopaque, waked: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    const current = kernel.Task.current();
    const instrumented_pid = this.instrumented_pid.load(.monotonic);
    if (current.pid() != instrumented_pid or waked.pid() != instrumented_pid) return;

    const current_tid: usize = @intCast(current.tid());
    const current_clock = this.thread_local_clocks.get(current_tid).?;

    const waked_tid: usize = @intCast(waked.tid());
    this.thread_local_clocks.put(atomic_allocator, waked_tid, current_clock) catch {};

    //TODO: handle old clock lag
}

fn onSchedExit(data: ?*anyopaque, task: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    if (task.pid() != this.instrumented_pid.load(.monotonic)) return;

    this.registerForSleep(task) catch return {}; //TODO: handle me
}

// Task Work Callbacks

fn doSleep(work: *kernel.Task.Work) callconv(.c) void {
    const pool = TaskWorkPool.getPoolPtrFromEntryPtr(work);
    const this: *@This() = @ptrCast(@alignCast(pool.context.load(.monotonic).?));
    const current_tid: usize = @intCast(kernel.Task.current().tid());

    const clock = this.thread_local_clocks.get(current_tid) orelse {
        @branchHint(.cold);
        std.log.err("TODO: onSleepWork thread_points null", .{});
        return;
    };

    const global_clock = this.global_virtual_clock.load(.monotonic);
    const delay_per_tick = this.virtual_speedup_delay.load(.monotonic);

    const clock_delta = global_clock - clock;
    std.debug.assert(clock_delta >= 0);

    const delay = @as(usize, @intCast(clock_delta)) * delay_per_tick;

    kernel.time.sleep.us(delay);

    // Unreachable is safe here since we retrived the tid before so it must be there
    // and no allocation is needed.
    this.thread_local_clocks.put(atomic_allocator, current_tid, global_clock) catch unreachable;
    pool.freeEntry(work);
}
