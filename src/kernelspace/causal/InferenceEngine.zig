// For this file if a time variable has no postfix indicating otherwise the default unit is us.

const std = @import("std");
const kernel = @import("kernel");
const thread_safe = @import("thread_safe.zig");

const Pid = std.os.linux.pid_t;
const Tid = Pid;
const FutexHandle = usize;

const atomic_allocator = kernel.heap.atomic_allocator;
const allocator = kernel.heap.allocator;

const TaskWorkPool = thread_safe.Pool(kernel.Task.Work);
const ClockTick = thread_safe.ThreadsClock.Clock.Tick;

const sampler_frequency_ns = 1 * std.time.ns_per_ms;

instrumented_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
experiment_duration: usize,

profiler_thread: ?*kernel.Thread,
sampler: ?*kernel.PerfEvent,

virtual_speedup_delay: std.atomic.Value(usize),
selected_ip: std.atomic.Value(usize),

progress: *std.atomic.Value(usize),
global_virtual_clock: std.atomic.Value(ClockTick),
threads_virtual_clock: thread_safe.ThreadsClock,
task_work_pool: *TaskWorkPool,

error_has_occurred: std.atomic.Value(bool),

pub fn init(progress_ptr: *std.atomic.Value(usize)) !@This() {
    try kernel.Task.findAddWork();
    kernel.tracepoint.init();

    const pool = try allocator.create(TaskWorkPool);
    pool.* = .empty();

    return .{
        .instrumented_pid = .init(0),
        .experiment_duration = 50 * std.time.us_per_ms,
        .virtual_speedup_delay = .init(0),
        .selected_ip = .init(0),

        .progress = progress_ptr,
        .global_virtual_clock = .init(0),
        .threads_virtual_clock = .init,
        .task_work_pool = pool,
        .error_has_occurred = .init(false),

        .profiler_thread = null,
        .sampler = null,
    };
}

pub fn deinit(this: *@This()) void {
    // If those are both true, a fatal error has occurred
    // which called deinit, so this avoids the regual deinit
    // to cause a double free.
    if (this.instrumented_pid.load(.monotonic) == 0 and this.error_has_occurred.load(.monotonic)) return;

    if (this.instrumented_pid.load(.monotonic) != 0) {
        kernel.tracepoint.sched.fork.unregister(onSchedFork, this);
        kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);
        kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
        kernel.tracepoint.sched.exit.unregister(onSchedExit, this);
        kernel.tracepoint.sync();
    }
    this.instrumented_pid.store(0, .monotonic);

    if (this.profiler_thread) |t| t.stop();
    if (this.sampler) |s| s.deinit();

    while (this.task_work_pool.inUse()) kernel.time.sleep.us(100);

    this.threads_virtual_clock.deinit(atomic_allocator);

    allocator.destroy(this.task_work_pool);
}

pub fn profilePid(this: *@This(), pid: Pid) !void {
    try this.threads_virtual_clock.put(atomic_allocator, .ticks, pid, 0);
    try this.threads_virtual_clock.put(atomic_allocator, .lag, pid, 0);
    this.instrumented_pid.store(pid, .release);

    this.task_work_pool.context.store(this, .monotonic);

    try kernel.tracepoint.sched.fork.register(onSchedFork, this);
    errdefer kernel.tracepoint.sched.fork.unregister(onSchedFork, this);

    try kernel.tracepoint.sched.@"switch".register(onSchedSwitch, this);
    errdefer kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);

    try kernel.tracepoint.sched.waking.register(onSchedWaking, this);
    errdefer kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);

    try kernel.tracepoint.sched.exit.register(onSchedExit, this);
    errdefer kernel.tracepoint.sched.exit.unregister(onSchedExit, this);

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

        this.sampler.?.enable();
        kernel.time.sleep.us(this.experiment_duration);
        var prog_delta = this.progress.load(.monotonic) -% baseline_prog;
        while (prog_delta < 5) : (prog_delta = this.progress.load(.monotonic) -% baseline_prog) {
            @branchHint(.cold);
            if (kernel.Thread.shouldThisStop()) return 0;

            this.experiment_duration *= 2;
            kernel.time.sleep.us(this.experiment_duration / 2);
        }
        this.sampler.?.disable();

        // Set false to error in next experiment.
        // if an error has occurred in the current one
        // dont register the point (the next experiment could also
        // be skewed maybe we shall also discrd it)
        if (this.error_has_occurred.swap(false, .monotonic)) {
            @branchHint(.unlikely);
            continue;
        }

        while (this.task_work_pool.inUse()) {
            @branchHint(.cold);
            kernel.time.sleep.us(100);
        }

        const end_wall = kernel.time.now.us();
        const wall = end_wall - start_wall;

        const selected_ip = this.selected_ip.load(.monotonic);

        const v_ticks = this.global_virtual_clock.load(.monotonic) - baseline_vclock;
        const total_delay = v_ticks * delay_per_tick;

        const adjusted = wall - total_delay;

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

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(event.context().?));
    const selected_line = this.selected_ip.load(.monotonic);

    if (selected_line == 0) {
        @branchHint(.unlikely);
        if (this.selected_ip.cmpxchgStrong(selected_line, regs.ip, .monotonic, .monotonic) == null) this.increment();
    } else if (selected_line == regs.ip) {
        this.increment();
    }

    this.registerForSleep(kernel.Task.current());
}

fn increment(this: *@This()) void {
    const current_tid = kernel.Task.current().tid();
    if (this.threads_virtual_clock.add(.ticks, current_tid, 1)) |clock|
        _ = this.global_virtual_clock.fetchMax(clock, .monotonic);
}

fn err(this: *@This(), s: []const u8) void {
    @branchHint(.cold);
    std.log.warn("{s}", .{s});
    this.error_has_occurred.store(true, .monotonic);
}

fn fatalErr(this: *@This(), s: []const u8) void {
    @branchHint(.cold);
    std.log.err("{s}", .{s});
    this.error_has_occurred.store(true, .monotonic);
    this.deinit();
}

fn registerForSleep(this: *@This(), task: *kernel.Task) void {
    const work = this.task_work_pool.getEntry() orelse {
        @branchHint(.cold);
        this.registerLag(task);
        return;
    };
    work.func = doSleep;

    task.addWork(work, .signal_no_ipi) catch this.fatalErr("Could not register seelp work");
}

fn registerLag(this: *@This(), task: *kernel.Task) void {
    const tid = task.tid();

    const local_clock = this.threads_virtual_clock.get(.ticks, tid) orelse return;
    const global_clock = this.global_virtual_clock.load(.monotonic);

    const clock_delta = global_clock - local_clock;

    _ = this.threads_virtual_clock.add(.lag, tid, clock_delta);
    this.threads_virtual_clock.put(atomic_allocator, .ticks, tid, global_clock) catch |e| this.fatalErr(@errorName(e));
}

fn onSchedFork(data: ?*anyopaque, parent: *kernel.Task, child: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    if (parent.pid() != this.instrumented_pid.load(.monotonic)) return;

    const parent_tid = parent.tid();
    const parent_clock = this.threads_virtual_clock.get(.ticks, parent_tid) orelse {
        this.err("Null parent clock in onSchedFork");
        return;
    };
    const parent_clock_lag = this.threads_virtual_clock.get(.lag, parent_tid) orelse {
        this.err("Null parent clock lag in onSchedFork");
        return;
    };

    const child_tid = child.tid();
    this.threads_virtual_clock.put(atomic_allocator, .ticks, child_tid, parent_clock) catch |e| this.fatalErr(@errorName(e));
    this.threads_virtual_clock.put(atomic_allocator, .lag, child_tid, parent_clock_lag) catch |e| this.fatalErr(@errorName(e));
}

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));

    if (prev.pid() != this.instrumented_pid.load(.monotonic)) return;

    if (!prev.isRunning()) this.registerLag(prev);
}

fn onSchedWaking(data: ?*anyopaque, waked: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    const instrumented_pid = this.instrumented_pid.load(.monotonic);
    if (waked.pid() != instrumented_pid) return;

    const waked_tid = waked.tid();
    const current = kernel.Task.current();

    if (current.pid() != instrumented_pid) {
        // The sleep is not caused by program state so there is no causal effect,
        // so we advance the virtual clock to be equal to the global one to avoid
        // a slowdown that would be caused by external factors
        const global_clock = this.global_virtual_clock.load(.monotonic);
        this.threads_virtual_clock.put(atomic_allocator, .ticks, waked_tid, global_clock) catch |e| this.fatalErr(@errorName(e));
    } else {
        const current_tid = current.tid();
        const current_clock = this.threads_virtual_clock.get(.ticks, current_tid) orelse {
            this.err("Null clock in sched waking tracepoint");
            return;
        };

        this.threads_virtual_clock.put(atomic_allocator, .ticks, waked_tid, current_clock) catch |e| this.fatalErr(@errorName(e));
    }
}

fn onSchedExit(data: ?*anyopaque, task: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    if (task.pid() != this.instrumented_pid.load(.monotonic)) return;

    this.registerForSleep(task);
}

fn doSleep(work: *kernel.Task.Work) callconv(.c) void {
    const pool = TaskWorkPool.getPoolPtrFromEntryPtr(work);
    const this: *@This() = @ptrCast(@alignCast(pool.context.load(.monotonic).?));
    const current_tid = kernel.Task.current().tid();

    const clock = this.threads_virtual_clock.get(.ticks, current_tid) orelse {
        this.err("Null clock in doSleep");
        return;
    };

    const clock_lag = this.threads_virtual_clock.get(.lag, current_tid) orelse 0;

    const global_clock = this.global_virtual_clock.load(.monotonic);
    const delay_per_tick = this.virtual_speedup_delay.load(.monotonic);

    const clock_delta = global_clock - clock;

    const delay = clock_delta * delay_per_tick + clock_lag;
    if (delay > 10 * std.time.us_per_s) this.fatalErr("Sleep exceded 10s");

    kernel.time.sleep.us(delay);

    this.threads_virtual_clock.put(atomic_allocator, .ticks, current_tid, global_clock) catch |e| this.fatalErr(@errorName(e));
    this.threads_virtual_clock.put(atomic_allocator, .lag, current_tid, 0) catch |e| this.fatalErr(@errorName(e));
    pool.freeEntry(work);
}
