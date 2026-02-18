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

const SleepTaskWork = struct {
    work: kernel.Task.Work,
    delay: std.atomic.Value(usize),
    _: usize,
};

const TaskSleepPool = thread_safe.Pool(SleepTaskWork);
const ProfiledTasksPool = thread_safe.Pool(std.atomic.Value(?*kernel.Task));
const ClockTick = u32;

const sampler_frequency = 999; //Hz, ~1ms; not round to avoid harmonics with the scheduler

profiled_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
experiment_duration: usize,

profiler_thread: ?*kernel.Thread,
sampler: ?*kernel.PerfEvent,

delay_per_tick: std.atomic.Value(u16),
selected_ip: std.atomic.Value(usize) align(std.atomic.cache_line),

progress: *std.atomic.Value(usize),
drift_registry: thread_safe.DriftRegistry,
task_sleep_pool: *TaskSleepPool,

error_has_occurred: std.atomic.Value(bool),

pub fn init(progress_ptr: *std.atomic.Value(usize)) !@This() {
    try kernel.Task.findAddWork();
    kernel.tracepoint.init();

    const sleep_pool = try allocator.create(TaskSleepPool);
    errdefer allocator.destroy(sleep_pool);
    sleep_pool.* = .empty;

    const tid_pools = try allocator.alloc(ProfiledTasksPool, 4);
    errdefer allocator.free(tid_pools);
    @memset(tid_pools, .{ .used_bitmask = .init(0), .entries = @splat(.init(null)) });

    return .{
        .profiled_pid = .init(0),
        .experiment_duration = 50 * std.time.us_per_ms,
        .delay_per_tick = .init(0),
        .selected_ip = .init(0),

        .progress = progress_ptr,
        .drift_registry = try .init(allocator, start_registry_len),
        .task_sleep_pool = sleep_pool,
        .error_has_occurred = .init(false),

        .profiler_thread = null,
        .sampler = null,
    };
}

pub fn deinit(this: *@This()) void {
    const pid = this.profiled_pid.load(.monotonic);
    const deinitted = std.math.maxInt(Pid);
    if (pid == deinitted or this.profiled_pid.cmpxchgStrong(pid, deinitted, .monotonic, .monotonic) != null) return;

    this.profiled_pid.store(0, .monotonic);
    this.error_has_occurred.store(true, .monotonic);

    if (this.sampler) |s| s.deinit();
    if (this.profiler_thread) |t| t.stop();

    kernel.tracepoint.sched.fork.unregister(onSchedFork, this);
    kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);
    kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
    kernel.tracepoint.sched.exit.unregister(onSchedExit, this);

    kernel.tracepoint.sync();

    while (this.task_sleep_pool.inUse()) kernel.time.sleep.us(100);

    this.drift_registry.ref.increment();
    const drift_len = this.drift_registry.pairs.len;
    this.drift_registry.ref.decrement();
    this.drift_registry.deinit(if (drift_len == start_registry_len) allocator else atomic_allocator);

    allocator.destroy(this.task_sleep_pool);
}

pub fn profilePid(this: *@This(), pid: Pid) !void {
    try this.drift_registry.put(.clock(pid), 0);
    this.profiled_pid.store(pid, .monotonic);

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
    this.sampler.?.enable();

    while (!kernel.Thread.shouldThisStop()) {
        this.setExperimentParameters();

        this.progress.store(0, .monotonic);
        kernel.time.sleep.us(this.experiment_duration);
        var prog_delta = this.progress.load(.monotonic);
        while (prog_delta < 5) : (prog_delta = this.progress.load(.monotonic)) {
            @branchHint(.cold);
            if (kernel.Thread.shouldThisStop()) return 0;

            this.experiment_duration *= 2;
            kernel.time.sleep.us(this.experiment_duration / 2);
        }
        // this.sampler.?.disable();
        this.drift_registry.clear();
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
        random.context = std.Random.DefaultPrng.init(@intCast(this.profiled_pid.load(.monotonic)));
        random.generator = random.context.?.random();
    }

    this.selected_ip.store(0, .monotonic);

    // Like coz, ~25% bias twards 0% speedup, then linear distribution on 5% increments.
    const roll = random.generator.uintLessThan(usize, 27);
    const speedup_percent = (roll -| 6) * 5;
    const delay = (speedup_percent * (1_000_000 / sampler_frequency)) / 100;

    this.delay_per_tick.store(@truncate(delay), .monotonic);
}

fn registerForSleep(this: *@This(), task: *kernel.Task, global_ticks: ClockTick, delay_per_tick: usize) void {
    const ticks = if (task.isRunning())
        global_ticks - this.drift_registry.get(.clock(task.tid()), .ticks)
    else
        this.drift_registry.get(.clock(task.tid()), .lag);

    const delay: usize = ticks * delay_per_tick;
    if (delay == 0) return;

    const slot = this.task_sleep_pool.getEntry() orelse {
        this.err("TODO");
        return;
    };

    slot.work.func = doSleep;
    slot.delay.store(delay, .monotonic);
    task.addWork(&slot.work, .signal_no_ipi) catch this.fatalErr("Could not register sleep work");
}

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(event.context().?));
    const selected_line = this.selected_ip.load(.monotonic);

    if (selected_line == 0) {
        @branchHint(.unlikely);
        if (this.selected_ip.cmpxchgStrong(0, regs.ip, .monotonic, .monotonic) == null) this.increment();
    } else if (selected_line == regs.ip) this.increment();
}

fn increment(this: *@This()) void {
    const tid = kernel.Task.current().tid();

    this.drift_registry.tick(.clock(tid)) catch return;
    // catch return means that we will miss a sample where the ip actually matched
    // but it is no different than simply not hitting the instruction pointer while
    // sampling; the profiler is resilient to that.
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

fn onSchedFork(data: ?*anyopaque, parent: *kernel.Task, child: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    if (parent.pid() != this.profiled_pid.load(.monotonic)) return;

    this.drift_registry.copy(.clock(parent.tid()), .clock(child.tid())) catch {}; //TODO: Let's allocate
}

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));

    if (prev.pid() != this.profiled_pid.load(.monotonic)) return;

    if (!prev.isRunning()) this.drift_registry.prepareForTransfer(.clock(prev.tid()));
}

fn onSchedWaking(data: ?*anyopaque, woke: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    const instrumented_pid = this.profiled_pid.load(.monotonic);

    const current = kernel.Task.current();

    if (current.pid() != instrumented_pid or woke.pid() != instrumented_pid) return;

    this.drift_registry.transfer(.lag(current.tid(), woke.tid())) catch {
        //TODO: we could allocate with atomic_allocator
    };
}

fn onSchedExit(data: ?*anyopaque, task: *kernel.Task) callconv(.c) void {
    const this: *@This() = @ptrCast(@alignCast(data.?));
    if (task.pid() != this.profiled_pid.load(.monotonic)) return;

    // this.registerForSleep(task, this.global_clock.load(.monotonic), this.delay_per_tick.load(.monotonic));
}

fn doSleep(work: *kernel.Task.Work) callconv(.c) void {
    const sleep_work: *SleepTaskWork = @fieldParentPtr("work", work);

    const delay = sleep_work.delay.load(.monotonic);
    TaskSleepPool.getPoolPtrFromEntryPtr(sleep_work).freeEntry(sleep_work);

    kernel.time.sleep.us(delay);
}
