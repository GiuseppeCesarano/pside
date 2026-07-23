const std = @import("std");
const assert = std.debug.assert;

const kernel = @import("kernel");
const atomic_allocator = kernel.heap.atomic_allocator;

const DelayPool = @import("thread_safe/DelayPool.zig");
const VirtualTimeKeeper = @import("VirtualTimeKeeper.zig");
const KeyAndLag = VirtualTimeKeeper.KeyAndLag;
const VmaRanges = @import("VmaRanges.zig");

const ExperimentRunner = @This();
const TimeKeeper = VirtualTimeKeeper.GenericVirtualTimeKeeper(isReaped, releaseKey);

pub const sampler_frequency = 997; // Hz, ~1ms; not round to avoid harmonics with the scheduler

profiled_pid: std.atomic.Value(std.os.linux.pid_t) align(std.atomic.cache_line),
sampler: ?*kernel.PerfEvent,
time_keeper: TimeKeeper,
delay_pool: DelayPool,
vma_ranges: VmaRanges,
vma_base: std.atomic.Value(usize),
an_error_has_occurred: std.atomic.Value(bool),

// Current experiment state, armed/disarmed by begin/endExperiment.
target_ip: std.atomic.Value(usize),
delay_per_tick: std.atomic.Value(u16),

pub fn init() !ExperimentRunner {
    return .{
        .profiled_pid = .init(0),
        .sampler = null,
        .time_keeper = try VirtualTimeKeeper.init(atomic_allocator, isReaped, releaseKey),
        .delay_pool = .empty,
        .vma_ranges = .empty,
        .vma_base = .init(0),
        .an_error_has_occurred = .init(false),
        .target_ip = .init(0),
        .delay_per_tick = .init(0),
    };
}

fn keyFromTask(task: *kernel.Task) VirtualTimeKeeper.Key {
    // task pointers are always aligned, so bit 0 is free for the map's collision flag.
    assert(@intFromPtr(task) % 2 == 0);
    return .{ .data = @intFromPtr(task) };
}

fn taskFromKey(key: VirtualTimeKeeper.Key) *kernel.Task {
    return @ptrFromInt(key.withoutCollisionBit().data);
}

fn isReaped(key: *VirtualTimeKeeper.Key) bool {
    return taskFromKey(key.*).isReaped();
}

pub fn deinit(this: *ExperimentRunner) void {
    kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);
    kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
    kernel.tracepoint.task.newtask.unregister(onNewTask, this);
    kernel.tracepoint.sync();

    if (this.sampler) |s| s.deinit();

    this.delay_pool.deinit();
    this.vma_ranges.deinit();
    this.time_keeper.deinit(atomic_allocator);
}

fn releaseKey(key: *VirtualTimeKeeper.Key) void {
    taskFromKey(key.*).decrementReferences();
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

    this.time_keeper.addFirst(keyFromTask(task));

    this.vma_ranges = try .snapshot(task, vma_name);

    try kernel.tracepoint.sched.@"switch".register(onSchedSwitch, this);
    errdefer kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);

    try kernel.tracepoint.sched.waking.register(onSchedWaking, this);
    errdefer kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);

    try kernel.tracepoint.task.newtask.register(onNewTask, this);
    errdefer kernel.tracepoint.task.newtask.unregister(onNewTask, this);

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
            .exclude_kernel = !attribute_kernel_samples,
        },
    };
    this.sampler = try kernel.PerfEvent.init(&sampler_attr, -1, pid, onSamplerTick, this);
}

pub fn beginExperiment(this: *ExperimentRunner, delay_per_tick: u16) void {
    this.delay_per_tick.store(delay_per_tick, .monotonic);
    this.target_ip.store(0, .seq_cst);
    this.sampler.?.enable();
}

pub fn endExperiment(this: *ExperimentRunner) void {
    this.delay_per_tick.store(0, .seq_cst); // zero first so any in-flight tick is a no-op
    this.sampler.?.disable();
}

pub fn getMasterClock(this: *ExperimentRunner) VirtualTimeKeeper.Ticks {
    return this.time_keeper.getMasterClock();
}

pub fn capturedRelativeIp(this: *ExperimentRunner) ?usize {
    const target = this.target_ip.load(.monotonic);
    if (target == 0) return null;
    return target - this.vma_base.load(.monotonic);
}

pub fn anErrorHasOccurred(this: *ExperimentRunner) bool {
    return this.an_error_has_occurred.load(.monotonic);
}

pub fn delayEveryoneLagging(this: *ExperimentRunner) void {
    // TODO: we should find a way to force sleeping tasks to run the delay,
    // .signal is currently making it hang

    // The map walk and per-thread delay application must not be preempted,
    // since we hold the gate closed, if a tracepoint callabck gets scheduled
    // will try an increment and spinwait untill we don't open the gate, but
    // if we get preempted and every core starts spinwaiting we will never get
    // the cpu and open the gate resulting in a deadlock
    kernel.preempt.disable();
    defer kernel.preempt.enable();

    this.time_keeper.delayEveryoneLagging(applyDelays, .{this});
}

fn applyDelays(this: *ExperimentRunner, keys_and_lags: []const KeyAndLag) void {
    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    if (delay_per_tick == 0) return;

    for (keys_and_lags) |kl| {
        const task = taskFromKey(kl.key);
        if (kl.lag == 0 or task.isDead()) continue;
        this.delay_pool.delay(task, kl.lag * delay_per_tick, .@"resume") catch |err| switch (err) {
            // Past exit_task_work the work can never run; the task is off any critical path.
            error.TooLateShuttingDown => {},
            else => this.abort("Could not apply delay"),
        };
    }
}

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *ExperimentRunner = @ptrCast(@alignCast(event.context() orelse return));

    const ip = kernel.execution.currentUserSpaceIp(regs);
    const target = this.target_ip.load(.monotonic);
    const is_target = (ip == target) or (target == 0 and this.captureProfilingTarget(ip));

    if (is_target and this.delay_per_tick.load(.monotonic) != 0)
        this.time_keeper.onTick(keyFromTask(kernel.Task.current()));
}

fn captureProfilingTarget(this: *ExperimentRunner, ip: usize) bool {
    const vma_base = this.vma_ranges.findBase(ip) orelse return false;

    const we_exchanged_first = this.target_ip.cmpxchgStrong(0, ip, .release, .monotonic) == null;

    if (we_exchanged_first) {
        @branchHint(.likely);
        this.vma_base.store(vma_base, .release);
    }

    return we_exchanged_first;
}

fn onNewTask(data: ?*anyopaque, child: *kernel.Task, _: c_ulong) callconv(.c) void {
    const this: *ExperimentRunner = @ptrCast(@alignCast(data.?));
    const parent = kernel.Task.current();

    if (parent.pid() != this.profiled_pid.load(.monotonic)) return;

    child.incrementReferences();
    const delays = this.time_keeper.onFork(atomic_allocator, keyFromTask(parent), keyFromTask(child)) catch
        return this.abort("Error while forking");
    this.applyDelays(&delays);
}

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *ExperimentRunner = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);

    if (prev.pid() == profiled_pid and !prev.isRunning() and !prev.isDead())
        this.time_keeper.onSleep(keyFromTask(prev));
}

fn onSchedWaking(data: ?*anyopaque, wakee: *kernel.Task) callconv(.c) void {
    const this: *ExperimentRunner = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);

    if (wakee.pid() != profiled_pid or wakee.isRunning() or wakee.isDead()) return;

    const waker = kernel.Task.current();
    if (kernel.execution.inTask() and waker.pid() == profiled_pid)
        this.applyDelays(&this.time_keeper.onWake(keyFromTask(waker), keyFromTask(wakee)))
    else
        this.applyDelays(&this.time_keeper.onExternalWake(keyFromTask(wakee)));
}

fn abort(this: *ExperimentRunner, s: []const u8) void {
    @branchHint(.cold);
    std.log.err("{s}", .{s});
    this.an_error_has_occurred.store(true, .monotonic);
}
