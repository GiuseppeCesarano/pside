// For this file if a time variable has no postfix indicating otherwise the default unit is us.

const CausalEngine = @This();
const std = @import("std");
const kernel = @import("kernel");
const thread_safe = @import("thread_safe.zig");

const Pid = std.os.linux.pid_t;
const Tid = Pid;

const atomic_allocator = kernel.heap.atomic_allocator;
const allocator = kernel.heap.allocator;
const clocks_starting_len = 1024;

const DelayWork = struct {
    work: kernel.Task.Work,
    delay: std.atomic.Value(usize),
    this: *anyopaque,
};

const DelayWorkPool = thread_safe.Pool(DelayWork);
const ProfiledTasksPool = thread_safe.Pool(std.atomic.Value(?*kernel.Task));
const ClockTicks = thread_safe.ThreadClocks.Ticks;

const sampler_frequency = 997; //Hz, ~1ms; not round to avoid harmonics with the scheduler

profiled_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
experiment_duration: usize,

profiler_thread: ?*kernel.Thread,
sampler: ?*kernel.PerfEvent,

delay_per_tick: std.atomic.Value(u16),
target_ip: std.atomic.Value(usize) align(std.atomic.cache_line),

progress: *std.atomic.Value(usize),
virtual_clocks: thread_safe.ThreadClocks,
delay_pool: *DelayWorkPool,

error_has_occurred: std.atomic.Value(bool),

pub fn init(progress_ptr: *std.atomic.Value(usize)) !CausalEngine {
    try kernel.Task.findAddWork();
    kernel.tracepoint.init();

    const sleep_pool = try allocator.create(DelayWorkPool);
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
        .target_ip = .init(0),

        .progress = progress_ptr,
        .virtual_clocks = try .init(allocator, clocks_starting_len),
        .delay_pool = sleep_pool,
        .error_has_occurred = .init(false),

        .profiler_thread = null,
        .sampler = null,
    };
}

pub fn deinit(this: *CausalEngine) void {
    const pid = this.profiled_pid.load(.monotonic);
    const deinit_sentinel = std.math.maxInt(Pid);
    if (pid == deinit_sentinel or this.profiled_pid.cmpxchgStrong(pid, deinit_sentinel, .monotonic, .monotonic) != null) return;

    this.profiled_pid.store(0, .monotonic);
    this.error_has_occurred.store(true, .monotonic);

    if (this.profiler_thread) |t| t.stop();
    if (this.sampler) |s| s.deinit();

    kernel.tracepoint.sched.fork.unregister(onSchedFork, this);
    kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);
    kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
    kernel.tracepoint.sched.exit.unregister(onSchedExit, this);

    kernel.tracepoint.sync();

    while (this.delay_pool.inUse()) kernel.time.sleep.us(100);

    this.virtual_clocks.ref.increment();
    const drift_len = this.virtual_clocks.pairs.len;
    this.virtual_clocks.ref.decrement();
    this.virtual_clocks.deinit(if (drift_len == clocks_starting_len) allocator else atomic_allocator);

    allocator.destroy(this.delay_pool);
}

pub fn profilePid(this: *CausalEngine, pid: Pid) !void {
    const task = kernel.Task.fromTid(pid);

    try this.virtual_clocks.put(.fromPtr(task), 0);
    this.profiled_pid.store(pid, .monotonic);

    for (&this.delay_pool.entries) |*e| e.this = this;

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
    const this: *CausalEngine = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldThisStop()) {
        this.setExperimentParameters();

        const delay_per_tick = this.delay_per_tick.load(.monotonic);
        const baseline_vclock = this.virtual_clocks.master.load(.acquire);
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

        if (kernel.Thread.shouldThisStop() or this.error_has_occurred.swap(false, .monotonic)) {
            @branchHint(.unlikely);
            continue;
        }

        kernel.preempt.disable();
        this.virtual_clocks.forEach(applyVirtualDelay, .{this});
        kernel.preempt.enable();

        while (this.delay_pool.inUse()) {
            @branchHint(.cold);
            kernel.time.sleep.us(100);
        }

        const end_wall = kernel.time.now.us();
        const wall = end_wall - start_wall;
        const selected_ip = this.target_ip.load(.monotonic);
        const v_ticks = this.virtual_clocks.master.load(.acquire) - baseline_vclock;
        const total_delay = v_ticks * delay_per_tick;
        const adjusted = wall -| total_delay;
        const throughput = @as(u64, prog_delta) * 1_000_000 / @as(u64, adjusted);

        std.log.info("0x{x}: [{}, {}]", .{
            selected_ip & 0xFFF,
            delay_per_tick,
            throughput,
        });
    }

    return 0;
}

fn setExperimentParameters(this: *CausalEngine) void {
    const random = struct {
        var context: ?std.Random.DefaultPrng = null;
        var generator: std.Random = undefined;
    };

    if (random.context == null) {
        @branchHint(.cold);
        random.context = std.Random.DefaultPrng.init(@intCast(this.profiled_pid.load(.monotonic)));
        random.generator = random.context.?.random();
    }

    this.target_ip.store(0, .monotonic);

    // Like coz, ~25% bias twards 0% speedup, then linear distribution on 5% increments.
    const roll = random.generator.uintLessThan(usize, 27);
    const speedup_percent = (roll -| 6) * 5;
    const sampler_period = 1_000_000 / sampler_frequency;
    const delay = (speedup_percent * sampler_period) / 100;

    this.delay_per_tick.store(@truncate(delay), .monotonic);
}

fn applyVirtualDelay(master: ClockTicks, key: *thread_safe.ThreadClocks.Key, value: *thread_safe.ThreadClocks.Value, this: *CausalEngine) void {
    // We force collision bit since kernel pointer live in 0xffff8...
    const task: *kernel.Task = @ptrFromInt(key.withCollisionBit().data);
    if (!task.isRunning()) return;

    const lag = master - value.ticks;
    value.ticks = master;

    this.registerForSleep(task, lag);
}

fn abort(this: *CausalEngine, s: []const u8) void {
    @branchHint(.cold);
    std.log.err("{s}", .{s});
    this.error_has_occurred.store(true, .monotonic);
    this.deinit();
}

fn registerForSleep(this: *CausalEngine, task: *kernel.Task, lag: ClockTicks) void {
    const delay: usize = lag * this.delay_per_tick.load(.monotonic);
    if (delay == 0) return;

    const slot = this.delay_pool.getEntry() orelse {
        this.abort("TODO");
        return;
    };

    slot.delay.store(delay, .monotonic);
    task.addWork(&slot.work, .@"resume") catch this.abort("Could not register sleep work");
}

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(event.context().?));
    const selected_line = this.target_ip.load(.monotonic);

    const current_task = kernel.Task.current();

    if (selected_line == regs.ip) {
        this.virtual_clocks.tick(.fromPtr(current_task)) catch return;
    } else if (selected_line == 0) {
        @branchHint(.unlikely);

        if (this.target_ip.cmpxchgStrong(0, regs.ip, .monotonic, .monotonic) == null)
            this.virtual_clocks.tick(.fromPtr(current_task)) catch return;
    }
}

fn onSchedFork(data: ?*anyopaque, parent: *kernel.Task, child: *kernel.Task) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(data.?));
    if (parent.pid() != this.profiled_pid.load(.monotonic)) return;

    child.incrementReferences();

    const lag = this.virtual_clocks.fork(.fromPtr(parent), .fromPtr(child)) catch return; // TODO: allocate atomically

    this.registerForSleep(parent, lag);
    this.registerForSleep(child, lag);
}

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);
    if (prev.pid() != profiled_pid or prev.isRunning() or prev.isDead()) return;

    this.virtual_clocks.prepareForSleep(.fromPtr(prev));
}

fn onSchedWaking(data: ?*anyopaque, woke: *kernel.Task) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(data.?));
    const instrumented_pid = this.profiled_pid.load(.monotonic);

    if (woke.pid() != instrumented_pid or woke.isRunning()) return;

    const current = kernel.Task.current();
    if (current.pid() == instrumented_pid) {
        const waker_lag, const woke_lag = this.virtual_clocks.wake(.fromPtr(current), .fromPtr(woke));
        this.registerForSleep(current, waker_lag);
        this.registerForSleep(woke, woke_lag);
    }
}

fn onSchedExit(data: ?*anyopaque, task: *kernel.Task) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(data.?));
    if (task.pid() != this.profiled_pid.load(.monotonic)) return;

    const lag = this.virtual_clocks.remove(.fromPtr(task));
    this.registerForSleep(task, lag);
    task.decrementReferences();
}

fn doSleep(work: *kernel.Task.Work) callconv(.c) void {
    const sleep_work: *DelayWork = @fieldParentPtr("work", work);

    const delay = sleep_work.delay.load(.monotonic);
    const this: *CausalEngine = @ptrCast(@alignCast(sleep_work.this));

    kernel.time.sleep.us(delay);
    this.delay_pool.freeEntry(sleep_work);
}
