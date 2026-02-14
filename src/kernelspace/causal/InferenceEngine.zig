// For this file if a time variable has no posmonotonictfix indicating otherwise the default unit is us.

const std = @import("std");
const kernel = @import("kernel");
const thread_safe = @import("thread_safe.zig");

const Pid = std.os.linux.pid_t;
const Tid = Pid;
const FutexHandle = usize;

const atomic_allocator = kernel.heap.atomic_allocator;
const allocator = kernel.heap.allocator;
const start_registry_len = 1024;

const TaskWorkPool = thread_safe.Pool(kernel.Task.Work);
const ClockTick = u16;

const sampler_frequency = 999; //Hz, ~1ms; not round to avoid harmonics with the scheduler

instrumented_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
experiment_duration: usize,

profiler_thread: ?*kernel.Thread,
sampler: ?*kernel.PerfEvent,

virtual_speedup_delay: std.atomic.Value(u16),
selected_ip: std.atomic.Value(usize) align(std.atomic.cache_line),
vma_start: std.atomic.Value(usize),

progress: *std.atomic.Value(usize),
global_clock: std.atomic.Value(ClockTick) align(std.atomic.cache_line),
drift_registry: thread_safe.DriftRegistry,
task_work_pool: *TaskWorkPool,

error_has_occurred: std.atomic.Value(bool),

pub fn init(progress_ptr: *std.atomic.Value(usize)) !@This() {
    try kernel.Task.findAddWork();
    kernel.tracepoint.init();

    const pool = try allocator.create(TaskWorkPool);
    errdefer allocator.destroy(pool);
    pool.* = .empty();

    return .{
        .instrumented_pid = .init(0),
        .experiment_duration = 50 * std.time.us_per_ms,
        .virtual_speedup_delay = .init(0),
        .selected_ip = .init(0),
        .vma_start = .init(0),

        .progress = progress_ptr,
        .global_clock = .init(0),
        .drift_registry = try .init(allocator, start_registry_len),
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

    this.drift_registry.ref.increment();
    const drift_len = this.drift_registry.pairs.len;
    this.drift_registry.ref.decrement();
    this.drift_registry.deinit(if (drift_len == start_registry_len) allocator else atomic_allocator);

    allocator.destroy(this.task_work_pool);
}

pub fn profilePid(this: *@This(), pid: Pid) !void {
    try this.drift_registry.put(.clock(pid), 0);
    this.instrumented_pid.store(pid, .monotonic);

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
        .sample_period_or_freq = sampler_frequency,
        .flags = .{
            .freq = true,
            .disabled = true,
            .inherit = true,
            .exclude_guest = true,
            .exclude_hv = true,
            .exclude_idle = true,
            .exclude_kernel = true,
        },
    };
    this.sampler = try kernel.PerfEvent.init(&sampler_attr, -1, pid, onSamplerTick, this);

    this.profiler_thread = .run(profileLoop, this, "pside_loop");
}

fn profileLoop(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *@This() = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldThisStop()) {
        this.setExperimentParameters();

        const delay_per_tick = this.virtual_speedup_delay.load(.monotonic);
        const baseline_vclock = this.global_clock.load(.monotonic);
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
        if (kernel.Thread.shouldThisStop() or this.error_has_occurred.swap(false, .monotonic)) {
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

        const v_ticks = this.global_clock.load(.monotonic) - baseline_vclock;
        const total_delay = v_ticks * delay_per_tick;

        const adjusted = wall - total_delay;

        const throughput = @as(u64, prog_delta) * 1_000_000 / @as(u64, adjusted);

        std.log.info("0x{x}: [{}, {}]", .{
            selected_ip - this.vma_start.load(.monotonic),
            delay_per_tick,
            throughput,
        });
    }
    return 0;
}

fn setExperimentParameters(this: *@This()) void {
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
    const delay = (speedup_percent * sampler_frequency) / 100;

    this.virtual_speedup_delay.store(@truncate(delay), .monotonic);
}

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(event.context().?));
    const selected_line = this.selected_ip.load(.monotonic);

    if (selected_line == 0) {
        @branchHint(.unlikely);
        kernel.rcu.read.lock();
        defer kernel.rcu.read.unlock();

        if (kernel.Task.current().findVma(regs.ip)) |vma| {
            @branchHint(.likely);

            const fname_ptr = vma.filename();
            if (fname_ptr != null) {
                if (this.selected_ip.cmpxchgStrong(0, regs.ip, .monotonic, .monotonic) == null) {
                    this.increment();
                    this.vma_start.store(vma.start(), .monotonic);
                }
            }
        }
    } else if (selected_line == regs.ip) {
        this.increment();
    }
}

fn increment(this: *@This()) void {
    const tid = kernel.Task.current().tid();

    const ticks = this.drift_registry.tick(.clock(tid));
    _ = this.global_clock.fetchMax(ticks, .monotonic);
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
        std.log.warn("TODO: Handle me", .{});
        return;
    };
    work.func = doSleep;

    task.addWork(work, .signal_no_ipi) catch this.fatalErr("Could not register sleep work");
}

fn onSchedFork(data: ?*anyopaque, parent: *kernel.Task, child: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    if (parent.pid() != this.instrumented_pid.load(.monotonic)) return;

    this.drift_registry.copy(.clock(parent.tid()), .clock(child.tid()));
}

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));

    if (prev.pid() != this.instrumented_pid.load(.monotonic)) return;

    const global_clock = this.global_clock.load(.monotonic);
    if (!prev.isRunning()) this.drift_registry.prepareForTransfer(.clock(prev.tid()), global_clock);
}

fn onSchedWaking(data: ?*anyopaque, woke: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    const instrumented_pid = this.instrumented_pid.load(.monotonic);

    const current = kernel.Task.current();

    if (current.pid() != instrumented_pid and woke.pid() != instrumented_pid) return;

    const global_clock = this.global_clock.load(.monotonic);
    this.drift_registry.transfer(.lag(current.tid(), woke.tid()), global_clock) catch {
        //TODO: we could allocate with atomic_allocator
    };
}

fn onSchedExit(data: ?*anyopaque, task: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    if (task.pid() != this.instrumented_pid.load(.monotonic)) return;

    this.registerForSleep(task);
}

fn doSleep(work: *kernel.Task.Work) callconv(.c) void {
    const pool = TaskWorkPool.getPoolPtrFromEntryPtr(work);

    const this: *@This() = @ptrCast(@alignCast(pool.context.?));
    const current_tid = kernel.Task.current().tid();

    const clock = this.drift_registry.get(.ticks, current_tid) orelse {
        this.err("Null clock in doSleep");
        return;
    };

    const clock_lag = this.drift_registry.get(.lag, current_tid) orelse 0;

    const global_clock = this.global_clock.load(.monotonic);
    const delay_per_tick = this.virtual_speedup_delay.load(.monotonic);

    const clock_delta = global_clock - clock;

    const delay = clock_delta * delay_per_tick + clock_lag;
    if (delay > 10 * std.time.us_per_s) {
        this.fatalErr("Sleep exceeded 10s");
        pool.freeEntry(work);
        return;
    }

    kernel.time.sleep.us(delay);

    this.drift_registry.put(atomic_allocator, .ticks, current_tid, global_clock) catch |e| {
        pool.freeEntry(work); // fatalErr will free the current engine
        // if we keep holding the pool entry the deinit
        // will spin forever
        this.fatalErr(@errorName(e));
        return;
    };
    this.drift_registry.put(atomic_allocator, .lag, current_tid, 0) catch |e| {
        pool.freeEntry(work);
        this.fatalErr(@errorName(e));
        return;
    };

    pool.freeEntry(work);
}
