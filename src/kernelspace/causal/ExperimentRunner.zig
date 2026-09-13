const std = @import("std");
const assert = std.debug.assert;

const kernel = @import("kernel");
const atomic_allocator = kernel.heap.atomic_allocator;

const DelayPool = @import("../concurrent/DelayPool.zig");
const VmaRanges = @import("../process/VmaRanges.zig");
const ThreadClocks = @import("time/ThreadClocks.zig");
const Key = ThreadClocks.Key;
const Ticks = ThreadClocks.Ticks;

const ExperimentRunner = @This();

pub const sampler_frequency = 997; // Hz, ~1ms; not round to avoid harmonics with the scheduler

const clocks_reserve = 1024;

const max_exit_payment_us = 50 * std.time.us_per_ms;

profiled_pid: std.atomic.Value(std.os.linux.pid_t) align(std.atomic.cache_line),
sampler: ?*kernel.PerfEvent,
clocks: ThreadClocks,
delay_pool: DelayPool,
vma_ranges: VmaRanges,
vma_base: std.atomic.Value(usize),
has_errored: std.atomic.Value(bool),

// Current experiment state, armed/disarmed by begin/endExperiment.
target_ip: std.atomic.Value(usize),
delay_per_tick: std.atomic.Value(u16),

pub fn init() !ExperimentRunner {
    return .{
        .profiled_pid = .init(0),
        .sampler = null,
        .clocks = try .init(atomic_allocator, clocks_reserve),
        .delay_pool = .empty,
        .vma_ranges = .empty,
        .vma_base = .init(0),
        .has_errored = .init(false),
        .target_ip = .init(0),
        .delay_per_tick = .init(0),
    };
}

fn keyFromTask(task: *const kernel.Task) Key {
    // task pointers are always aligned, so bit 0 is free for the map's collision flag.
    assert(@intFromPtr(task) % 2 == 0);
    return .{ .data = @intFromPtr(task) };
}

fn taskFromKey(key: Key) *kernel.Task {
    return @ptrFromInt(key.withoutCollisionBit().data);
}

pub fn deinit(this: *ExperimentRunner) void {
    kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);
    kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
    kernel.tracepoint.sched.process_exit.unregister(onSchedProcessExit, this);
    kernel.tracepoint.task.newtask.unregister(onNewTask, this);
    kernel.tracepoint.sync();

    if (this.sampler) |s| s.deinit();

    this.delay_pool.deinit();
    this.vma_ranges.deinit();

    var it = this.clocks.iterate();
    while (it.next()) |pair|
        taskFromKey(pair.key.raw).decrementReferences();

    this.clocks.deinit(atomic_allocator);
}

pub fn profilePid(
    this: *ExperimentRunner,
    pid: std.os.linux.pid_t,
    vma_name: [:0]const u8,
    attribute_kernel_samples: bool,
) !void {
    try this.delay_pool.init();

    this.profiled_pid.store(pid, .monotonic);
    const task: *kernel.Task = kernel.Task.fromTid(pid) orelse return error.TaskNotFound;

    // Only this task is seeded; the rest join via onNewTask, so tracking can
    // be correct only if the target starts single-threaded.
    if (task.threadCount() != 1) {
        task.decrementReferences();
        std.log.err("Refusing to profile pid {d}: target already has multiple threads", .{pid});
        return error.MultiThreadedTarget;
    }

    // Only the first key, the reserve always has room for it.
    this.clocks.put(keyFromTask(task), 0) catch unreachable;

    this.vma_ranges = try .snapshot(task, vma_name);

    try kernel.tracepoint.sched.@"switch".register(onSchedSwitch, this);
    errdefer kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);

    try kernel.tracepoint.sched.waking.register(onSchedWaking, this);
    errdefer kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);

    try kernel.tracepoint.task.newtask.register(onNewTask, this);
    errdefer kernel.tracepoint.task.newtask.unregister(onNewTask, this);

    try kernel.tracepoint.sched.process_exit.register(onSchedProcessExit, this);
    errdefer kernel.tracepoint.sched.process_exit.unregister(onSchedProcessExit, this);

    var sampler_attr = std.os.linux.perf_event_attr{
        .type = .SOFTWARE,
        .config = @backingInt(std.os.linux.PERF.COUNT.SW.TASK_CLOCK),
        .sample_period_or_freq = sampler_frequency,
        .flags = .{
            .freq = true,
            .disabled = true,
            .inherit = true,
            .inherit_thread = true,
            .exclude_guest = true,
            .exclude_hv = true,
            .exclude_idle = true,
            .exclude_kernel = !attribute_kernel_samples,
        },
    };
    this.sampler = try kernel.PerfEvent.init(&sampler_attr, -1, pid, onSamplerTick, this);
}

pub fn beginExperiment(this: *ExperimentRunner, delay_per_tick: u16) void {
    this.delay_per_tick.store(delay_per_tick, .monotonic);
    this.target_ip.store(0, .seq_cst);
    this.vma_base.store(0, .seq_cst);
    this.sampler.?.enable();
}

pub fn endExperiment(this: *ExperimentRunner) void {
    this.delay_per_tick.store(0, .seq_cst); // zero first so any in-flight tick is a no-op
    this.sampler.?.disable();
}

pub fn getMasterClock(this: *const ExperimentRunner) Ticks {
    return this.clocks.master.load(.monotonic);
}

pub fn capturedRelativeIp(this: *const ExperimentRunner) ?usize {
    const target = this.target_ip.load(.acquire);
    if (target == 0) return null;
    return target - this.vma_base.load(.monotonic);
}

pub fn hasErrored(this: *const ExperimentRunner) bool {
    return this.has_errored.load(.monotonic);
}

pub fn delayEveryoneLagging(this: *ExperimentRunner) void {
    {
        // The map walk and per-thread delay application must not be preempted,
        // since we hold the gate closed, if a tracepoint callback gets scheduled
        // will try an increment and spinwait until we don't open the gate, but
        // if we get preempted and every core starts spinwaiting we will never get
        // the cpu and open the gate resulting in a deadlock
        kernel.preempt.disable();
        defer kernel.preempt.enable();

        var it = this.clocks.iterate();

        // Read after the gate closed, a tick still in flight would push a clock
        // past it and underflow the lag
        const master = this.clocks.master.load(.monotonic);

        while (it.next()) |pair| {
            const lag = master - pair.value.raw.ticks;
            pair.value.raw = .atValue(master);

            this.settleDelay(pair.key.raw, lag);
        }
    }

    // Signalling from inside the gate deadlocks against a spinwaiting tracepoint
    this.delay_pool.flushPending() catch this.abort("Could not flush delays");
}

fn applyDelay(this: *ExperimentRunner, key: Key, lag: Ticks) void {
    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    if (delay_per_tick == 0 or lag == 0) return;

    const task = taskFromKey(key);
    if (task.isDead()) return;

    this.delay_pool.delay(task, @as(usize, lag) * delay_per_tick) catch |err| switch (err) {
        // Past exit_task_work the work can never run; the task is off any critical path.
        error.TooLateShuttingDown => {},
        else => this.abort("Could not apply delay"),
    };
}

fn settleDelay(this: *ExperimentRunner, key: Key, lag: Ticks) void {
    const task = taskFromKey(key);
    if (task.isRunning()) return this.applyDelay(key, lag);

    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    if (delay_per_tick == 0 or lag == 0 or task.isDead()) return;

    this.delay_pool.pendDelay(task, @as(usize, lag) * delay_per_tick) catch this.abort("Could not pend delay");
}

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *ExperimentRunner = @ptrCast(@alignCast(event.context() orelse return));

    const ip = kernel.execution.currentUserSpaceIp(regs);
    const target = this.target_ip.load(.monotonic);
    const is_target = (ip == target) or (target == 0 and this.captureProfilingTarget(ip));

    if (is_target and this.delay_per_tick.load(.monotonic) != 0)
        this.clocks.tick(keyFromTask(kernel.Task.current())) catch {};
    // .tick() errors on a locked map; we discard the error (and the tick itself)
    // since the causal attribution algorithm is robust against missed samples.
}

fn captureProfilingTarget(this: *ExperimentRunner, ip: usize) bool {
    const vma_base = this.vma_ranges.findBase(ip) orelse return false;

    const we_claimed_first = this.vma_base.cmpxchgStrong(0, vma_base, .monotonic, .monotonic) == null;

    if (we_claimed_first) {
        @branchHint(.likely);
        this.target_ip.store(ip, .release);
    }

    return we_claimed_first;
}

fn onNewTask(data: ?*anyopaque, child: *kernel.Task, clone_flags: c_ulong) callconv(.c) void {
    const this: *ExperimentRunner = @ptrCast(@alignCast(data.?));
    const parent = kernel.Task.current();

    const profiled_pid = this.profiled_pid.load(.monotonic);
    if (parent.pid() != profiled_pid) return;
    if (clone_flags & std.os.linux.CLONE.THREAD == 0) return;

    assert(child.pid() == profiled_pid);

    const parent_key = keyFromTask(parent);
    const child_key = keyFromTask(child);

    child.incrementReferences();
    const lag = this.fork(parent_key, child_key) catch
        return this.abort("Error while forking");

    this.applyDelay(parent_key, lag);
    this.applyDelay(child_key, lag);
}

fn fork(this: *ExperimentRunner, parent: Key, child: Key) !Ticks {
    return this.clocks.fork(parent, child) catch blk: {
        try this.clocks.grow(atomic_allocator);
        break :blk try this.clocks.fork(parent, child);
    };
}

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *ExperimentRunner = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);

    if (prev.pid() == profiled_pid and !prev.isRunning() and !prev.isDead())
        this.clocks.prepareForSleep(keyFromTask(prev));
}

fn onSchedWaking(data: ?*anyopaque, wakee: *kernel.Task) callconv(.c) void {
    const this: *ExperimentRunner = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);

    if (wakee.pid() != profiled_pid or wakee.isRunning() or wakee.isDead()) return;

    const wakee_key = keyFromTask(wakee);

    if (kernel.execution.inTask()) {
        const waker = kernel.Task.current();
        if (waker.pid() == profiled_pid) {
            const waker_key = keyFromTask(waker);
            const waker_lag, const wakee_lag = this.clocks.wake(waker_key, wakee_key) orelse return;

            this.applyDelay(waker_key, waker_lag);
            return this.applyDelay(wakee_key, wakee_lag);
        }
    }

    this.applyDelay(wakee_key, this.clocks.catchUp(wakee_key) orelse return);
}

fn onSchedProcessExit(data: ?*anyopaque, task: *kernel.Task, _: bool) callconv(.c) void {
    const this: *ExperimentRunner = @ptrCast(@alignCast(data.?));

    if (task.pid() != this.profiled_pid.load(.monotonic)) return;

    assert(task.isDead());

    const key = keyFromTask(task);
    const payment = this.exitPayment(key);

    const removed = this.clocks.remove(key);
    assert(removed);

    task.decrementReferences();

    if (payment != 0) kernel.time.sleep.us(payment);
}

fn exitPayment(this: *ExperimentRunner, key: Key) usize {
    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    if (delay_per_tick == 0 or !kernel.execution.canSleep()) return 0;

    const lag = this.clocks.catchUp(key) orelse return 0;

    return @min(@as(usize, lag) * delay_per_tick, max_exit_payment_us);
}

fn abort(this: *ExperimentRunner, s: []const u8) void {
    @branchHint(.cold);
    std.log.err("{s}", .{s});
    this.has_errored.store(true, .monotonic);
}
