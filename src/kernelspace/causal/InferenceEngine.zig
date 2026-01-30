// TODO: handle error and rewrite catches
// For this file if a time variable has no postfix indicating otherwise the default unit is us.
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

const sampler_frequency_ns = 1 * std.time.ns_per_ms;

instrumented_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
experiment_duration: std.atomic.Value(usize),

profiler_thread: *kernel.Thread,

virtual_speedup_delay: std.atomic.Value(usize),
selected_ip: std.atomic.Value(usize),

progress: *std.atomic.Value(usize),
global_virtual_clock: std.atomic.Value(ClockTick),
thread_local_clocks: ThreadLocalClock,
thread_local_clocks_lag: ThreadLocalClock,
task_work_pool: *TaskWorkPool,

sampler: *kernel.PerfEvent,

pub fn init(progress_ptr: *std.atomic.Value(usize)) !@This() {
    try kernel.Task.findAddWork();
    kernel.tracepoint.init();

    const pool = try allocator.create(TaskWorkPool);
    pool.* = .empty();

    return .{
        .instrumented_pid = .init(0),
        .experiment_duration = .init(50 * std.time.us_per_ms),
        .virtual_speedup_delay = .init(0),
        .selected_ip = .init(0),

        .progress = progress_ptr,
        .global_virtual_clock = .init(0),
        .thread_local_clocks = .init,
        .thread_local_clocks_lag = .init,
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
        kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);
        kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
        kernel.tracepoint.sched.exit.unregister(onSchedExit, this);
        kernel.tracepoint.sync();
    }

    while (this.task_work_pool.inUse()) kernel.time.sleep.us(100);

    this.thread_local_clocks.deinit(atomic_allocator);

    allocator.destroy(this.task_work_pool);
}

pub fn profilePid(this: *@This(), pid: Pid) !void {
    try this.thread_local_clocks.put(atomic_allocator, @intCast(pid), 0);
    try this.thread_local_clocks_lag.put(atomic_allocator, @intCast(pid), 0);
    this.instrumented_pid.store(pid, .release);

    this.task_work_pool.context.store(this, .monotonic);

    try kernel.tracepoint.sched.fork.register(onSchedFork, this);
    try kernel.tracepoint.sched.@"switch".register(onSchedSwitch, this);
    try kernel.tracepoint.sched.waking.register(onSchedWaking, this);
    try kernel.tracepoint.sched.exit.register(onSchedExit, this);

    var sampler_attr = std.os.linux.perf_event_attr{
        .type = .SOFTWARE,
        .config = @intFromEnum(std.os.linux.PERF.COUNT.SW.TASK_CLOCK),
        .sample_period_or_freq = sampler_frequency_ns,
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
    this.sampler = kernel.PerfEvent.init(&sampler_attr, -1, pid, onSamplerTick, this) catch return;

    this.profiler_thread = .run(profileLoop, this, "pside_loop");
}

fn profileLoop(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *@This() = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldThisStop()) {
        this.setExperimentParameters() catch return 0;

        const delay_per_tick = this.virtual_speedup_delay.load(.monotonic);
        const baseline_vclock = this.global_virtual_clock.load(.monotonic);
        const baseline_prog = this.progress.load(.monotonic);

        const start_wall = kernel.time.now.us();

        this.sampler.enable();
        kernel.time.sleep.us(this.experiment_duration.load(.monotonic));
        this.sampler.disable();

        const selected_ip = this.selected_ip.load(.monotonic);

        while (this.task_work_pool.inUse()) {
            @branchHint(.cold);
            kernel.time.sleep.us(100);
        }

        const end_wall = kernel.time.now.us();
        const wall = end_wall - start_wall;

        const v_ticks = this.global_virtual_clock.load(.monotonic) -% baseline_vclock;
        const total_delay = @as(usize, v_ticks) * delay_per_tick;

        const adjusted = wall - total_delay;

        const prog_delta = this.progress.load(.monotonic) -% baseline_prog;

        const throughput = @as(u64, prog_delta) * 1_000_000 / @as(u64, adjusted);

        std.log.info("DATA: 0x{x}, {}, {}, {}, {}", .{
            selected_ip,
            delay_per_tick,
            @as(usize, @intCast(throughput)),
            v_ticks,
            adjusted,
        });
    }
    return 0;
}

fn setExperimentParameters(this: *@This()) !void {
    const random = struct {
        var context: ?std.Random.DefaultPrng = null;
        var generator: std.Random = undefined;
    };

    if (random.context == null) {
        @branchHint(.cold);
        random.context = std.Random.DefaultPrng.init(@intCast(this.instrumented_pid.load(.monotonic)));
        random.generator = random.context.?.random();
    }

    this.selected_ip.store(0, .monotonic);

    // Like coz, ~25% bias twards 0% speedup, then linear distribution on 5% increments.
    const roll = random.generator.uintLessThan(usize, 27);
    const speedup_percent = (roll -| 6) * 5;
    const delay = @divFloor((speedup_percent * sampler_frequency_ns) / 100, std.time.ns_per_us);

    this.virtual_speedup_delay.store(delay, .monotonic);
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

fn increment(this: *@This()) void {
    const current_tid: usize = @intCast(kernel.Task.current().tid());
    if (this.thread_local_clocks.increment(current_tid)) |clock|
        _ = this.global_virtual_clock.fetchMax(clock, .monotonic);
}

fn registerForSleep(this: *@This(), task: *kernel.Task) !void {
    const work = this.task_work_pool.getEntry() orelse return; //TODO: maybe just execute the sleep.
    work.func = doSleep;
    try task.addWork(work, .signal_no_ipi);
}

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

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));

    if (prev.pid() != this.instrumented_pid.load(.monotonic)) return;

    if (prev.isRunning()) {
        const tid: usize = @intCast(prev.tid());

        const local_clock = this.thread_local_clocks.get(tid) orelse return;
        const global_clock = this.global_virtual_clock.load(.monotonic);

        const clock_delta = global_clock -| local_clock;

        this.thread_local_clocks_lag.put(atomic_allocator, tid, clock_delta) catch {
            @branchHint(.cold);
            //TODO:handle me
        };

        this.thread_local_clocks.put(atomic_allocator, tid, global_clock) catch {
            @branchHint(.cold);
            //TODO:handle me
        };
    }
}

fn onSchedWaking(data: ?*anyopaque, waked: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    const instrumented_pid = this.instrumented_pid.load(.monotonic);
    if (waked.pid() != instrumented_pid) return;

    const waked_tid: usize = @intCast(waked.tid());
    const current = kernel.Task.current();

    if (current.pid() != instrumented_pid) {
        // The sleep is not caused by program state so there is no causal effect,
        // so we advance the virtual clock to be equal to the global one to avoid
        // a slowdown that would be caused by external factors
        const global_clock = this.global_virtual_clock.load(.monotonic);
        this.thread_local_clocks.put(atomic_allocator, waked_tid, global_clock) catch {};
    } else {
        const current_tid: usize = @intCast(current.tid());
        const current_clock = this.thread_local_clocks.get(current_tid).?;

        this.thread_local_clocks.put(atomic_allocator, waked_tid, current_clock) catch {};
    }
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
    const clock_lag = this.thread_local_clocks_lag.get(current_tid) orelse 0;

    const global_clock = this.global_virtual_clock.load(.monotonic);
    const delay_per_tick = this.virtual_speedup_delay.load(.monotonic);

    const clock_delta = global_clock - clock;

    const delay = @as(usize, @intCast(clock_delta)) * delay_per_tick + clock_lag;

    kernel.time.sleep.us(delay);

    // Unreachable is safe here since we retrived the tid before so it must be there
    // and no allocation is needed.
    this.thread_local_clocks.put(atomic_allocator, current_tid, global_clock) catch unreachable;
    this.thread_local_clocks_lag.put(atomic_allocator, current_tid, 0) catch unreachable;
    pool.freeEntry(work);
}
