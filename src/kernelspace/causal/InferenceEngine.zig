// For this file if a time variable has no postfix indicating otherwise the default unit is us.

const InferenceEngine = @This();
const std = @import("std");
const kernel = @import("kernel");
const thread_safe = @import("thread_safe.zig");

const Pid = std.os.linux.pid_t;
const Tid = Pid;

const atomic_allocator = kernel.heap.atomic_allocator;
const allocator = kernel.heap.allocator;
const clocks_starting_len = 1024;

const SleepTaskWork = struct {
    work: kernel.Task.Work,
    delay: std.atomic.Value(usize),
    this: *anyopaque,
};

const TaskSleepPool = thread_safe.Pool(SleepTaskWork);
const ProfiledTasksPool = thread_safe.Pool(std.atomic.Value(?*kernel.Task));
const ClockTicks = thread_safe.ThreadClocks.Ticks;

const sampler_frequency = 999; //Hz, ~1ms; not round to avoid harmonics with the scheduler

profiled_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
experiment_duration: usize,

profiler_thread: ?*kernel.Thread,
sampler: ?*kernel.PerfEvent,

delay_per_tick: std.atomic.Value(u16),
selected_ip: std.atomic.Value(usize) align(std.atomic.cache_line),

progress: *std.atomic.Value(usize),
clocks: thread_safe.ThreadClocks,
task_sleep_pool: *TaskSleepPool,

error_has_occurred: std.atomic.Value(bool),

pub fn init(progress_ptr: *std.atomic.Value(usize)) !InferenceEngine {
    try kernel.Task.findAddWork();
    kernel.tracepoint.init();

    const sleep_pool = try allocator.create(TaskSleepPool);
    errdefer allocator.destroy(sleep_pool);
    sleep_pool.* = .empty;

    for (&sleep_pool.entries) |*entry| entry.work.func = doSleep;

    const tid_pools = try allocator.alloc(ProfiledTasksPool, 4);
    errdefer allocator.free(tid_pools);
    @memset(tid_pools, .{ .used_bitmask = .init(0), .entries = @splat(.init(null)) });

    return .{
        .profiled_pid = .init(0),
        .experiment_duration = 45 * std.time.us_per_ms,
        .delay_per_tick = .init(0),
        .selected_ip = .init(0),

        .progress = progress_ptr,
        .clocks = try .init(allocator, clocks_starting_len),
        .task_sleep_pool = sleep_pool,
        .error_has_occurred = .init(false),

        .profiler_thread = null,
        .sampler = null,
    };
}

pub fn deinit(this: *InferenceEngine) void {
    const pid = this.profiled_pid.load(.monotonic);
    const deinitted = std.math.maxInt(Pid);
    if (pid == deinitted or this.profiled_pid.cmpxchgStrong(pid, deinitted, .monotonic, .monotonic) != null) return;

    this.profiled_pid.store(0, .monotonic);
    this.error_has_occurred.store(true, .monotonic);

    if (this.profiler_thread) |t| t.stop();
    if (this.sampler) |s| s.deinit();

    kernel.tracepoint.sched.fork.unregister(onSchedFork, this);
    kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);
    kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
    kernel.tracepoint.sched.exit.unregister(onSchedExit, this);

    kernel.tracepoint.sync();

    while (this.task_sleep_pool.inUse()) kernel.time.sleep.us(100);

    this.clocks.ref.increment();
    const drift_len = this.clocks.pairs.len;
    this.clocks.ref.decrement();
    this.clocks.deinit(if (drift_len == clocks_starting_len) allocator else atomic_allocator);

    allocator.destroy(this.task_sleep_pool);
}

pub fn profilePid(this: *InferenceEngine, pid: Pid) !void {
    const task = kernel.Task.fromTid(pid);

    try this.clocks.put(.fromPtr(task), 0);
    this.profiled_pid.store(pid, .monotonic);

    for (&this.task_sleep_pool.entries) |*e| e.this = this;

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
    const this: *InferenceEngine = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldThisStop()) {
        this.setExperimentParameters();
        this.progress.store(0, .monotonic);

        this.sampler.?.enable();
        kernel.time.sleep.us(this.experiment_duration);
        while (this.progress.load(.monotonic) < 5 and !kernel.Thread.shouldThisStop()) {
            @branchHint(.unlikely);
            kernel.time.sleep.us(this.experiment_duration);
            this.experiment_duration *= 2;
        }
        this.sampler.?.disable();

        this.clocks.forEach(signalSleep, .{this});
    }

    return 0;
}

fn signalSleep(master: ClockTicks, key: *thread_safe.ThreadClocks.Key, value: *thread_safe.ThreadClocks.Value, this: *InferenceEngine) void {
    // We force collision bit since kernel pointer live in 0xffff8...
    const task: *kernel.Task = @ptrFromInt(key.withCollisionBit().data);
    if (!task.isRunning()) return;

    const lag = master - value.data.ticks;
    value.data.ticks = master;

    this.registerForSleep(task, lag);
}

fn setExperimentParameters(this: *InferenceEngine) void {
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

fn registerForSleep(this: *InferenceEngine, task: *kernel.Task, lag: ClockTicks) void {
    const delay: usize = lag * this.delay_per_tick.load(.monotonic);
    if (delay == 0) return;

    const slot = this.task_sleep_pool.getEntry() orelse {
        this.fatalErr("TODO");
        return;
    };

    slot.delay.store(delay, .monotonic);
    task.addWork(&slot.work, .@"resume") catch this.fatalErr("Could not register sleep work");
}

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *InferenceEngine = @ptrCast(@alignCast(event.context().?));
    const selected_line = this.selected_ip.load(.monotonic);

    const current_task = kernel.Task.current();

    if (selected_line == regs.ip) {
        this.clocks.tick(.fromPtr(current_task)) catch return;
    } else if (selected_line == 0) {
        @branchHint(.unlikely);

        if (this.selected_ip.cmpxchgStrong(0, regs.ip, .monotonic, .monotonic) == null)
            this.clocks.tick(.fromPtr(current_task)) catch return;
    }
}

fn fatalErr(this: *InferenceEngine, s: []const u8) void {
    @branchHint(.cold);
    std.log.err("{s}", .{s});
    this.error_has_occurred.store(true, .monotonic);
    this.deinit();
}

fn onSchedFork(data: ?*anyopaque, parent: *kernel.Task, child: *kernel.Task) callconv(.c) void {
    const this: *InferenceEngine = @ptrCast(@alignCast(data.?));
    if (parent.pid() != this.profiled_pid.load(.monotonic)) return;

    child.incrementReferences();

    const lag = this.clocks.fork(.fromPtr(parent), .fromPtr(child)) catch return; // TODO: allocate atomically

    this.registerForSleep(parent, lag);
    this.registerForSleep(child, lag);
}

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *InferenceEngine = @ptrCast(@alignCast(data.?));

    if (prev.pid() != this.profiled_pid.load(.monotonic) or prev.isDead()) return;

    if (!prev.isRunning()) this.clocks.prepareForSleep(.fromPtr(prev));
}

fn onSchedWaking(data: ?*anyopaque, woke: *kernel.Task) callconv(.c) void {
    const this: *InferenceEngine = @ptrCast(@alignCast(data.?));
    const instrumented_pid = this.profiled_pid.load(.monotonic);

    const current = kernel.Task.current();

    if (current.pid() != instrumented_pid or woke.pid() != instrumented_pid) return;

    const waker_lag, const woke_lag = this.clocks.wake(.fromPtr(current), .fromPtr(woke));

    this.registerForSleep(current, waker_lag);
    this.registerForSleep(woke, woke_lag);
}

fn onSchedExit(data: ?*anyopaque, task: *kernel.Task) callconv(.c) void {
    const this: *InferenceEngine = @ptrCast(@alignCast(data.?));
    if (task.pid() != this.profiled_pid.load(.monotonic)) return;

    const lag = this.clocks.remove(.fromPtr(task));
    this.registerForSleep(task, lag);
    task.decrementReferences();
}

fn doSleep(work: *kernel.Task.Work) callconv(.c) void {
    const sleep_work: *SleepTaskWork = @fieldParentPtr("work", work);

    const delay = sleep_work.delay.load(.monotonic);
    const this: *InferenceEngine = @ptrCast(@alignCast(sleep_work.this));
    this.task_sleep_pool.freeEntry(sleep_work);

    kernel.time.sleep.us(delay);
}
