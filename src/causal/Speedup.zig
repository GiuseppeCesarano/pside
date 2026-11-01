const std = @import("std");
const assert = std.debug.assert;

const kernel = @import("kernel");
const safety = @import("safety");

const DelayPool = @import("DelayPool");
const VmaRanges = @import("VmaRanges.zig");
const ThreadClocks = @import("ThreadClocks.zig");
const Key = ThreadClocks.Key;
const Ticks = ThreadClocks.Ticks;

const Speedup = @This();

profiled_pid: std.atomic.Value(std.os.linux.pid_t) align(std.atomic.cache_line),
sampler: ?*kernel.PerfEvent,
clocks: ThreadClocks,
delay_pool: DelayPool,
vma_ranges: VmaRanges,
io: std.Io,
allocator: std.mem.Allocator,
atomic_allocator: std.mem.Allocator,
vma_base: std.atomic.Value(usize),
failure: std.atomic.Value(ErrorInt),

// Current experiment state, armed/disarmed by begin/endExperiment.
target_ip: std.atomic.Value(usize),
delay_per_tick: std.atomic.Value(u16),
experiment_start: Ticks,

task_references: TaskReferences,
state: safety.State(Lifecycle),
loop_task: BoundToTask,
address: safety.Pinned,

const Lifecycle = enum { idle, attached, running };
const BoundToTask = safety.BoundTo(currentTask);
const TaskReferences = safety.ConfigurableObligations(.{ .thread_safe = true }, .{});
const ErrorInt = @Int(.unsigned, @bitSizeOf(anyerror));

pub const Outcome = struct {
    relative_ip: usize,
    injected_us: u32,
};

pub const Error = DelayPool.Error || error{NoSpace};
pub const AttachError = error{ TaskNotFound, MultiThreadedTarget } ||
    std.mem.Allocator.Error ||
    VmaRanges.SnapshotError ||
    kernel.RegisterTraceError ||
    kernel.PerfEvent.CreateKernelCounterError;

pub const sampler_frequency = 997; // Hz, ~1ms; not round to avoid harmonics with the scheduler

const clocks_reserve = 1024;
const max_exit_payment_us = 50 * std.time.us_per_ms;

fn currentTask(_: *const anyopaque) *kernel.Task {
    return kernel.Task.current();
}

pub fn init(allocator: std.mem.Allocator, atomic_allocator: std.mem.Allocator) !Speedup {
    return .{
        .profiled_pid = .init(0),
        .sampler = null,
        .clocks = try .init(allocator, clocks_reserve),
        .delay_pool = .empty,
        .vma_ranges = .empty,
        .io = undefined,
        .allocator = allocator,
        .atomic_allocator = atomic_allocator,
        .vma_base = .init(0),
        .failure = .init(0),
        .target_ip = .init(0),
        .delay_per_tick = .init(0),
        .experiment_start = 0,

        .task_references = .none,
        .state = .init(.idle),
        .loop_task = .unbound,
        .address = .unbound,
    };
}

fn retainTask(this: *Speedup, task: *kernel.Task) void {
    task.get();
    this.task_references.incur();
}

fn releaseTask(this: *Speedup, task: *kernel.Task) void {
    task.put();
    this.task_references.discharge();
}

fn keyFromTask(task: *const kernel.Task) Key {
    // task pointers are always aligned, so bit 0 is free for the map's collision flag.
    assert(@intFromPtr(task) % 2 == 0);
    return .{ .data = @intFromPtr(task) };
}

fn taskFromKey(key: Key) *kernel.Task {
    return @ptrFromInt(key.withoutCollisionBit().data);
}

pub fn deinit(this: *Speedup) void {
    this.state.assertEqlAnyOf(&.{ .idle, .attached });
    this.address.assertCurrentIfBound();

    if (this.sampler) |s| {
        kernel.unregisterTraceSchedSwitch(onSchedSwitch, this);
        kernel.unregisterTraceSchedWaking(onSchedWaking, this);
        kernel.unregisterTraceSchedProcessExit(onSchedProcessExit, this);
        kernel.unregisterTraceTaskNewtask(onNewTask, this);
        kernel.tracepoint.synchronizeUnregister();

        _ = s.releaseKernel();
    }

    this.delay_pool.deinit(this.allocator, this.atomic_allocator);
    this.vma_ranges.deinit(this.allocator);

    var it = this.clocks.iterate();
    defer it.finish();

    while (it.next()) |pair|
        this.releaseTask(taskFromKey(pair.key.raw));

    this.task_references.assertCount(.eq, 0);

    this.clocks.deinit(this.allocator, this.atomic_allocator);

    this.* = undefined;
}

pub fn profilePid(
    this: *Speedup,
    io: std.Io,
    pid: std.os.linux.pid_t,
    vma_name: [:0]const u8,
    attribute_kernel_samples: bool,
) AttachError!void {
    this.state.assertEql(.idle);
    this.state.transition(.attached);
    errdefer this.state.transition(.idle);
    this.address.bind();

    this.io = io;
    try this.delay_pool.init(io, this.allocator);

    this.profiled_pid.store(pid, .monotonic);
    const task: *kernel.Task = kernel.Task.fromTid(pid) orelse return AttachError.TaskNotFound;
    this.task_references.incur();

    // Only this task is seeded; the rest join via onNewTask, so tracking can
    // be correct only if the target starts single-threaded.
    if (task.nrThreads() != 1) {
        this.releaseTask(task);
        return AttachError.MultiThreadedTarget;
    }

    // Only the first key, the reserve always has room for it.
    this.clocks.put(keyFromTask(task), 0) catch unreachable;

    this.vma_ranges = try .snapshot(this.allocator, task, vma_name);

    try kernel.registerTraceSchedSwitch(onSchedSwitch, this);
    errdefer kernel.unregisterTraceSchedSwitch(onSchedSwitch, this);

    try kernel.registerTraceSchedWaking(onSchedWaking, this);
    errdefer kernel.unregisterTraceSchedWaking(onSchedWaking, this);

    try kernel.registerTraceTaskNewtask(onNewTask, this);
    errdefer kernel.unregisterTraceTaskNewtask(onNewTask, this);

    try kernel.registerTraceSchedProcessExit(onSchedProcessExit, this);
    errdefer kernel.unregisterTraceSchedProcessExit(onSchedProcessExit, this);

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
    this.sampler = try kernel.PerfEvent.createKernelCounter(&sampler_attr, -1, task, onSamplerTick, this);
}

pub fn beginExperiment(this: *Speedup, speedup_percent: u8) void {
    this.state.assertEql(.attached);
    this.state.transition(.running);
    this.loop_task.bindOrAssert();

    // The speedup is delivered as a delay charged to everyone else.
    const sampler_period = std.time.us_per_s / sampler_frequency;
    const delay_per_tick: u16 = @intCast((@as(u32, speedup_percent) * sampler_period) / 100);

    this.experiment_start = this.clocks.master.load(.monotonic);
    this.delay_per_tick.store(delay_per_tick, .monotonic);
    this.target_ip.store(0, .seq_cst);
    this.vma_base.store(0, .seq_cst);
    this.sampler.?.enable();
}

pub fn endExperiment(this: *Speedup) Error!?Outcome {
    this.state.assertEql(.running);
    this.state.transition(.attached);
    this.loop_task.assertCurrent();

    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    this.sampler.?.disable();
    this.delayEveryoneLagging();
    this.delay_per_tick.store(0, .monotonic);

    const failure = this.failure.load(.monotonic);
    if (failure != 0) return @errorCast(@errorFromInt(failure));

    const target = this.target_ip.load(.acquire);
    if (target == 0) return null;

    const ticks = this.clocks.master.load(.monotonic) - this.experiment_start;
    return .{
        .relative_ip = target - this.vma_base.load(.monotonic),
        .injected_us = ticks * delay_per_tick,
    };
}

fn delayEveryoneLagging(this: *Speedup) void {
    {
        // The map walk and per-thread delay application must not be preempted,
        // since we hold the gate closed, if a tracepoint callback gets scheduled
        // will try an increment and spinwait until we don't open the gate, but
        // if we get preempted and every core starts spinwaiting we will never get
        // the cpu and open the gate resulting in a deadlock
        kernel.preempt.disable();
        defer kernel.preempt.enable();

        var it = this.clocks.iterate();
        defer it.finish();

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
    this.delay_pool.flushPending() catch |err| this.fail(err);
}

fn applyDelay(this: *Speedup, key: Key, lag: Ticks) void {
    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    if (delay_per_tick == 0 or lag == 0) return;

    const task = taskFromKey(key);
    if (task.isDead()) return;

    this.delay_pool.delay(this.allocator, this.atomic_allocator, task, @as(usize, lag) * delay_per_tick) catch |err| switch (err) {
        // Past exit_task_work the work can never run; the task is off any critical path.
        error.TooLateShuttingDown => {},
        else => |e| this.fail(e),
    };
}

fn settleDelay(this: *Speedup, key: Key, lag: Ticks) void {
    const task = taskFromKey(key);
    if (task.isRunning()) return this.applyDelay(key, lag);

    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    if (delay_per_tick == 0 or lag == 0 or task.isDead()) return;

    this.delay_pool.pendDelay(this.allocator, this.atomic_allocator, task, @as(usize, lag) * delay_per_tick) catch |err| this.fail(err);
}

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *Speedup = @ptrCast(@alignCast(event.overflowHandlerContext() orelse return));

    const ip = kernel.currentUserSpaceIp(regs);
    const target = this.target_ip.load(.monotonic);
    const is_target = (ip == target) or (target == 0 and this.captureProfilingTarget(ip));

    if (is_target and this.delay_per_tick.load(.monotonic) != 0)
        this.clocks.tick(keyFromTask(kernel.Task.current())) catch {};
    // .tick() errors on a locked map; we discard the error (and the tick itself)
    // since the causal attribution algorithm is robust against missed samples.
}

fn captureProfilingTarget(this: *Speedup, ip: usize) bool {
    const vma_base = this.vma_ranges.findBase(ip) orelse return false;

    const we_claimed_first = this.vma_base.cmpxchgStrong(0, vma_base, .monotonic, .monotonic) == null;

    if (we_claimed_first) {
        @branchHint(.likely);
        this.target_ip.store(ip, .release);
    }

    return we_claimed_first;
}

fn onNewTask(data: ?*anyopaque, child: *kernel.Task, clone_flags: c_ulong) callconv(.c) void {
    const this: *Speedup = @ptrCast(@alignCast(data.?));
    const parent = kernel.Task.current();

    const profiled_pid = this.profiled_pid.load(.monotonic);
    if (parent.tgidNr() != profiled_pid) return;
    if (clone_flags & std.os.linux.CLONE.THREAD == 0) return;

    assert(child.tgidNr() == profiled_pid);

    const parent_key = keyFromTask(parent);
    const child_key = keyFromTask(child);

    this.retainTask(child);
    const lag = this.fork(parent_key, child_key) catch |err| {
        this.releaseTask(child);
        return this.fail(err);
    };

    this.applyDelay(parent_key, lag);
    this.applyDelay(child_key, lag);
}

fn fork(this: *Speedup, parent: Key, child: Key) !Ticks {
    kernel.preempt.disable();
    defer kernel.preempt.enable();

    return this.clocks.fork(parent, child) catch blk: {
        try this.clocks.grow(this.allocator, this.atomic_allocator);
        break :blk try this.clocks.fork(parent, child);
    };
}

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *Speedup = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);

    if (prev.tgidNr() == profiled_pid and !prev.isRunning() and !prev.isDead())
        this.clocks.prepareForSleep(keyFromTask(prev));
}

fn onSchedWaking(data: ?*anyopaque, wakee: *kernel.Task) callconv(.c) void {
    const this: *Speedup = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);

    if (wakee.tgidNr() != profiled_pid or wakee.isRunning() or wakee.isDead()) return;

    const wakee_key = keyFromTask(wakee);

    if (kernel.inTask()) {
        const waker = kernel.Task.current();
        if (waker.tgidNr() == profiled_pid) {
            const waker_key = keyFromTask(waker);
            const waker_lag, const wakee_lag = this.clocks.wake(waker_key, wakee_key) orelse return;

            this.applyDelay(waker_key, waker_lag);
            return this.applyDelay(wakee_key, wakee_lag);
        }
    }

    this.applyDelay(wakee_key, this.clocks.catchUp(wakee_key) orelse return);
}

fn onSchedProcessExit(data: ?*anyopaque, task: *kernel.Task, _: bool) callconv(.c) void {
    const this: *Speedup = @ptrCast(@alignCast(data.?));

    if (task.tgidNr() != this.profiled_pid.load(.monotonic)) return;

    assert(task.isDead());

    const key = keyFromTask(task);
    const payment = this.exitPayment(key);

    {
        kernel.preempt.disable();
        defer kernel.preempt.enable();

        const removed = this.clocks.remove(key);
        assert(removed);
    }

    this.releaseTask(task);

    if (payment != 0) this.io.sleep(.fromMicroseconds(@intCast(payment)), .awake) catch unreachable;
}

fn exitPayment(this: *Speedup, key: Key) usize {
    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    if (delay_per_tick == 0 or !kernel.preemptible()) return 0;

    const lag = lag: {
        kernel.preempt.disable();
        defer kernel.preempt.enable();

        break :lag this.clocks.catchUp(key) orelse return 0;
    };

    return @min(@as(usize, lag) * delay_per_tick, max_exit_payment_us);
}

fn fail(this: *Speedup, err: Error) void {
    @branchHint(.cold);
    _ = this.failure.cmpxchgStrong(0, @intFromError(err), .monotonic, .monotonic);
}
