const std = @import("std");
const assert = std.debug.assert;

const LineMap = @import("LineMap");
const platform = @import("platform");
const Delays = platform.Delays;
const Task = platform.Task;
const Clocks = platform.Clocks;
const Ticks = Clocks.Ticks;
const safety = @import("safety");

const VmaRanges = @import("VmaRanges.zig");

const Speedup = @This();

probes: Probes,
clocks: Clocks,
delays: Delays,
vma_ranges: VmaRanges,
line_map: *const LineMap,
allocator: std.mem.Allocator,
atomic_allocator: std.mem.Allocator,
failure: std.atomic.Value(ErrorInt),

// Current experiment state, armed/disarmed by begin/endExperiment.
experiment_running: std.atomic.Value(bool),
target_site: std.atomic.Value(LineMap.Site),
vma_base: std.atomic.Value(usize),
delay_per_tick: std.atomic.Value(u16),

state: safety.State(Lifecycle),
loop_task: BoundToTask,
address: safety.Pinned,

const Lifecycle = enum { idle, attached, running };
const Probes = platform.Probes(Speedup, .{
    .sleep = onSleep,
    .wake = onWake,
    .fork = onFork,
    .exit = onExit,
    .sample = onSample,
});
const BoundToTask = safety.BoundTo(currentTask);
const ErrorInt = @Int(.unsigned, @bitSizeOf(anyerror));

pub const Outcome = struct {
    site: LineMap.Site,
    injected_us: u32,
};

pub const Error = Delays.Error || Clocks.Error;
pub const AttachError = error{ TaskNotFound, MultiThreadedTarget } ||
    std.mem.Allocator.Error ||
    VmaRanges.SnapshotError ||
    platform.AttachError;

pub const sampler_frequency = 997; // Hz, ~1ms; not round to avoid harmonics with the scheduler

const call_site_scan_words = 64;
const co_runner_window = 8;
const co_runner_max_lag = 8;

fn currentTask(_: *const anyopaque) *Task {
    return Task.current();
}

pub fn init(allocator: std.mem.Allocator, atomic_allocator: std.mem.Allocator) std.mem.Allocator.Error!Speedup {
    return .{
        .probes = .detached,
        .clocks = try .init(allocator, atomic_allocator),
        .delays = .empty,
        .vma_ranges = .empty,
        .line_map = undefined,
        .allocator = allocator,
        .atomic_allocator = atomic_allocator,
        .failure = .init(0),
        .experiment_running = .init(false),
        .target_site = .init(.none),
        .vma_base = .init(0),
        .delay_per_tick = .init(0),

        .state = .init(.idle),
        .loop_task = .unbound,
        .address = .unbound,
    };
}

pub fn deinit(this: *Speedup) void {
    this.state.assertOneOf(&.{ .idle, .attached });
    this.address.assertUnchangedOrUnbound();

    this.probes.detach();

    this.delays.deinit();
    this.vma_ranges.deinit(this.allocator);
    this.clocks.deinit();

    this.* = undefined;
}

pub fn profilePid(
    this: *Speedup,
    io: std.Io,
    pid: std.os.linux.pid_t,
    vma_name: [:0]const u8,
    line_map: *const LineMap,
) AttachError!void {
    this.state.assertEql(.idle);
    this.state.transition(.attached);
    errdefer this.state.transition(.idle);

    this.line_map = line_map;
    try this.delays.init(io, this.allocator, this.atomic_allocator);

    const task = Task.fromTid(pid) orelse return AttachError.TaskNotFound;

    // Only this task is seeded; the rest join via onFork, so tracking can
    // be correct only if the target starts single-threaded.
    if (task.nrThreads() != 1) {
        task.put();
        return AttachError.MultiThreadedTarget;
    }

    this.clocks.track(task);

    this.vma_ranges = try .snapshot(this.allocator, task, vma_name);

    this.address.bind();
    errdefer this.address.unbind();

    try this.probes.attach(this, task, sampler_frequency);
}

pub fn beginExperiment(this: *Speedup, speedup_percent: u8) void {
    this.state.assertEql(.attached);
    this.loop_task.bindOrAssertUnchanged();
    this.state.transition(.running);

    // The speedup is delivered as a delay charged to everyone else.
    const sampler_period = std.time.us_per_s / sampler_frequency;
    const delay_per_tick: u16 = @intCast((@as(u32, speedup_percent) * sampler_period) / 100);

    this.clocks.beginEpoch();
    this.delay_per_tick.store(delay_per_tick, .monotonic);
    this.target_site.store(.none, .monotonic);
    this.vma_base.store(0, .monotonic);
    this.experiment_running.store(true, .release);
}

pub fn endExperiment(this: *Speedup) Error!?Outcome {
    this.state.assertEql(.running);
    this.loop_task.assertUnchanged();
    this.state.transition(.attached);

    this.experiment_running.store(false, .monotonic);

    const failure = this.failure.load(.monotonic);
    if (failure != 0) return @errorCast(@errorFromInt(failure));

    const target = this.target_site.load(.monotonic);
    if (target == LineMap.Site.none) return null;

    const settled_at = try this.settleAll();
    const delay_per_tick = this.delay_per_tick.load(.monotonic);

    return .{
        .site = target,
        .injected_us = @as(u32, settled_at.ticks) * delay_per_tick,
    };
}

fn isExperimentRunning(this: *const Speedup) bool {
    return this.experiment_running.load(.acquire) and !this.hasFailed();
}

fn hasFailed(this: *const Speedup) bool {
    return this.failure.load(.monotonic) != 0;
}

fn applyDelay(this: *Speedup, task: *Task, lag: Ticks) void {
    if (!this.isExperimentRunning()) return;

    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    const time_out: usize = lag * delay_per_tick;
    this.delays.delay(task, time_out) catch |err| this.fail(err);
}

fn onSample(this: *Speedup, sample: platform.Sample) void {
    if (!this.isExperimentRunning()) return;

    const hit = if (this.attributedIp(sample)) |ip| this.isTarget(ip) else false;

    if (this.delay_per_tick.load(.monotonic) == 0) return;

    const task = Task.current();

    const lag = lag: {
        // A locked map drops the sample, since the causal attribution
        // algorithm is robust against missed samples.
        const guard = this.clocks.tryTakeGuard() orelse return;
        defer guard.release();

        const slot = guard.slot(task) orelse return;

        if (hit) {
            const epoch = guard.master().epoch;
            if (slot.tick(epoch)) |ticks| guard.advanceMaster(epoch, ticks);
        }

        const tolerance: Ticks = if (slot.countSinceHit(hit) <= co_runner_window) co_runner_max_lag else 0;
        break :lag slot.catchUp(guard.master(), tolerance) orelse return;
    };

    this.applyDelay(task, lag);
}

fn attributedIp(this: *Speedup, sample: platform.Sample) ?usize {
    const ip = sample.userIp();
    if (this.vma_ranges.findBase(ip) != null) return ip;

    return this.callSiteOnStack(sample);
}

fn callSiteOnStack(this: *Speedup, sample: platform.Sample) ?usize {
    var words: [call_site_scan_words]usize = undefined;
    sample.readUserStack(&words) catch return null;

    return for (words) |word| {
        if (this.vma_ranges.findBase(word) != null and platform.followsCall(word))
            break word - 1;
    } else null;
}

fn isTarget(this: *Speedup, ip: usize) bool {
    const target = this.target_site.load(.acquire);
    if (target == LineMap.Site.none) return this.captureProfilingTarget(ip);

    const vma_base = this.vma_base.load(.monotonic);
    if (ip < vma_base) return false;

    return this.line_map.getSite(ip - vma_base) == target;
}

fn captureProfilingTarget(this: *Speedup, ip: usize) bool {
    const vma_base = this.vma_ranges.findBase(ip) orelse return false;
    const site = this.line_map.getSite(ip - vma_base) orelse return false;
    if (site == LineMap.Site.none) return false;

    const we_claimed_first = this.vma_base.cmpxchgStrong(0, vma_base, .monotonic, .monotonic) == null;
    if (we_claimed_first) {
        @branchHint(.likely);
        this.target_site.store(site, .release);
    }
    return we_claimed_first;
}

fn onFork(this: *Speedup, parent: *Task, child: *Task) void {
    if (this.hasFailed()) return;

    this.clocks.insert(child) catch |err| return this.fail(err);

    const lag = lag: {
        const guard = this.clocks.takeGuard();
        defer guard.release();

        break :lag guard.slot(parent).?.catchUp(guard.master(), 0) orelse 0;
    };

    this.applyDelay(parent, lag);
    this.applyDelay(child, lag);
}

fn onSleep(this: *Speedup, task: *Task) void {
    if (!this.isExperimentRunning()) return;

    const guard = this.clocks.takeGuard();
    defer guard.release();

    guard.slot(task).?.sleep(guard.master());
}

fn onWake(this: *Speedup, wakee: *Task, waker: ?*Task) void {
    if (!this.isExperimentRunning()) return;

    const known_waker = waker orelse return this.applyDelay(wakee, this.catchUp(wakee) orelse return);

    const waker_lag, const wakee_lag = lags: {
        const guard = this.clocks.tryTakeGuard() orelse return;
        defer guard.release();

        const master = guard.master();
        const waker_slot = guard.slot(known_waker);
        const waker_lag = if (waker_slot) |slot| slot.lag(master) orelse return else 0;
        const wakee_lag = guard.slot(wakee).?.wake(master, waker_lag) orelse return;

        if (waker_slot) |slot| _ = slot.catchUp(master, 0);

        break :lags .{ waker_lag, wakee_lag };
    };

    this.applyDelay(known_waker, waker_lag);
    this.applyDelay(wakee, wakee_lag);
}

fn onExit(this: *Speedup, task: *Task) void {
    assert(task.isDead());
    if (this.hasFailed()) return;

    const lag = this.catchUp(task);
    this.clocks.remove(task);
    if (!this.isExperimentRunning()) return;

    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    this.delays.delayExiting(task, @as(usize, lag orelse 0) * delay_per_tick);
}

fn catchUp(this: *Speedup, task: *Task) ?Ticks {
    const guard = this.clocks.tryTakeGuard() orelse return null;
    defer guard.release();

    const slot = guard.slot(task) orelse return null;
    return slot.catchUp(guard.master(), 0);
}

fn settleAll(this: *Speedup) Delays.Error!Clocks.Master {
    const settled_at = try this.clocks.forEachExclusive(this, Delays.Error, settle);
    try this.delays.flush();
    return settled_at;
}

fn settle(this: *Speedup, task: *Task, slot: *Clocks.Slot, master: Clocks.Master) Delays.Error!void {
    const lag = if (Clocks.iteration_freezes) slot.settle(master) else slot.catchUp(master, 0) orelse return;

    const delay_per_tick = this.delay_per_tick.load(.monotonic);
    try this.delays.pend(task, @as(usize, lag) * delay_per_tick);
}

fn fail(this: *Speedup, err: Error) void {
    @branchHint(.cold);
    _ = this.failure.cmpxchgStrong(0, @intFromError(err), .monotonic, .monotonic);
}
