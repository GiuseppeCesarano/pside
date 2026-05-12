// Time unit convention: All time variables use microseconds (us) unless otherwise marked.

const std = @import("std");
const Pid = std.os.linux.pid_t;
const Tid = Pid;

const kernel = @import("kernel");
const atomic_allocator = kernel.heap.atomic_allocator;
const allocator = kernel.heap.allocator;
const serialization = @import("serialization");

const DelayPool = @import("DelayPool.zig");
const DiskWriter = @import("DiskWriter.zig");
const thread_safe = @import("thread_safe.zig");
const ClockTicks = thread_safe.ThreadClocks.Ticks;
const VmaRanges = @import("VmaRanges.zig");

const CausalEngine = @This();

const sampler_frequency = 997; // Hz, ~1ms; not round to avoid harmonics with the scheduler
const initial_experiment_duration_us = 45 * std.time.us_per_ms;
const min_progress_delta = 5;
const flush_retry_count = 3;
const flush_retry_delay_us = 50;

const ExperimentParameters = struct {
    speedup_percent: u16,
    delay_per_tick: u16,
};

const Snapshot = struct {
    progress: usize,
    master: ClockTicks,
    time: u64,
};

// Profiling target
profiled_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
target_ip: std.atomic.Value(usize) align(std.atomic.cache_line),

// Sampling & virtual clock state
sampler_tick_delay_us: std.atomic.Value(u16),
vma_base: std.atomic.Value(usize),
vma_ranges: VmaRanges,

// Experiment tracking & progress
experiment_duration_us: usize,
progress: *std.atomic.Value(usize),
virtual_clocks: thread_safe.ThreadClocks,

// Delay application & output
delay_pool: DelayPool,
disk_writer: DiskWriter,

// System integration
profiler_thread: ?*kernel.Thread,
sampler: ?*kernel.PerfEvent,

// Lifecycle management
deinit_guard: std.atomic.Value(bool),
error_has_occurred: std.atomic.Value(bool),

pub fn init(progress_ptr: *std.atomic.Value(usize)) !CausalEngine {
    try kernel.Task.findAddWork();
    kernel.tracepoint.init();

    return .{
        .profiled_pid = .init(0),
        .target_ip = .init(0),

        .sampler_tick_delay_us = .init(0),
        .vma_base = .init(0),
        .vma_ranges = .empty,

        .experiment_duration_us = 0,
        .progress = progress_ptr,
        .virtual_clocks = try .init(atomic_allocator, 1024),

        .delay_pool = .empty,
        .disk_writer = .empty,

        .profiler_thread = null,
        .sampler = null,

        .deinit_guard = .init(false),
        .error_has_occurred = .init(false),
    };
}

pub fn deinit(this: *CausalEngine) void {
    if (this.deinit_guard.swap(true, .seq_cst)) return;

    if (this.profiler_thread) |t| t.stop();

    kernel.tracepoint.sched.fork.unregister(onSchedFork, this);
    kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);
    kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
    kernel.tracepoint.sched.exit.unregister(onSchedExit, this);
    kernel.tracepoint.sync();

    if (this.sampler) |s| s.deinit();
    this.vma_ranges.deinit();

    this.disk_writer.deinit();
    this.delay_pool.deinit();

    this.virtual_clocks.deinit(atomic_allocator);
}

pub fn profilePid(this: *CausalEngine, pid: Pid, fd: std.os.linux.fd_t, vma_name: [:0]const u8) !void {
    try this.delay_pool.init();

    const task = kernel.Task.fromTid(pid);

    this.experiment_duration_us = initial_experiment_duration_us;
    this.vma_ranges = try .snapshot(task, vma_name);

    try this.disk_writer.start(fd);

    try this.disk_writer.push(.{
        serialization.SectionHeader{ .kind = .throughput },
        vma_name[0 .. vma_name.len + 1],
    });

    try this.virtual_clocks.put(.fromPtr(task), 0);
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

    this.profiler_thread = .run(profilingLoop, this, "pside_loop");
}

fn profilingLoop(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *CausalEngine = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldThisStop() and !this.error_has_occurred.load(.monotonic)) {
        const params = this.generateRandomExperimentParameters();
        const snap = this.takeSnapshot();

        this.doExperiment(params, snap.progress);

        const target_ip = this.target_ip.load(.monotonic);
        const should_stop = kernel.Thread.shouldThisStop() or this.error_has_occurred.load(.monotonic);

        if (should_stop or (target_ip == 0 and params.speedup_percent != 0)) continue;

        this.applyAllDelays(params.speedup_percent);
        this.recordThroughput(params, snap, target_ip);
    }

    this.flushRecords();
    return 0;
}

fn generateRandomExperimentParameters(this: *CausalEngine) ExperimentParameters {
    const random = struct {
        var context: ?std.Random.DefaultPrng = null;
        var generator: std.Random = undefined;
    };

    if (random.context == null) {
        @branchHint(.cold);
        random.context = std.Random.DefaultPrng.init(@intCast(this.profiled_pid.load(.monotonic)));
        random.generator = random.context.?.random();
    }

    // Like coz, ~25% bias towards 0% speedup, then linear distribution on 5% increments.
    const roll = random.generator.uintLessThan(u16, 27);
    const speedup_percent = (roll -| 6) * 5;
    const sampler_period = 1_000_000 / sampler_frequency;
    const delay: u16 = @intCast(((@as(u32, speedup_percent) * sampler_period) / 100));

    return .{ .speedup_percent = speedup_percent, .delay_per_tick = delay };
}

fn takeSnapshot(this: *CausalEngine) Snapshot {
    return .{
        .progress = this.progress.load(.monotonic),
        .master = this.virtual_clocks.master.load(.acquire),
        .time = kernel.time.now.us(),
    };
}

fn doExperiment(this: *CausalEngine, params: ExperimentParameters, baseline_prog: usize) void {
    this.sampler_tick_delay_us.store(params.delay_per_tick, .monotonic);
    this.vma_base.store(0, .monotonic);
    this.target_ip.store(0, .monotonic);

    if (params.speedup_percent != 0) this.sampler.?.enable();
    kernel.time.sleep.us(this.experiment_duration_us);

    var prog_delta = this.progress.load(.monotonic) -% baseline_prog;
    while (prog_delta < min_progress_delta and
        !kernel.Thread.shouldThisStop()) : (prog_delta = this.progress.load(.monotonic) -% baseline_prog)
    {
        this.experiment_duration_us *|= 2;
        kernel.time.sleep.us(this.experiment_duration_us / 2);
    }

    this.sampler_tick_delay_us.store(0, .monotonic); // stop in flight ticks
    if (params.speedup_percent != 0) this.sampler.?.disable();
}

fn applyAllDelays(this: *CausalEngine, delay_per_tick: u16) void {
    if (delay_per_tick == 0) return;

    kernel.preempt.disable();
    this.virtual_clocks.forEach(applyDelayToThread, .{ this, delay_per_tick });
    kernel.preempt.enable();

    this.delay_pool.waitAllDelays();
}

fn applyDelayToThread(master: ClockTicks, key: *thread_safe.ThreadClocks.Key, value: *thread_safe.ThreadClocks.Value, this: *CausalEngine, delay_per_tick: u16) void {
    const task: *kernel.Task = @ptrFromInt(key.withoutCollisionBit().data);

    const lag = master - value.ticks;
    value.ticks = master;
    value.master_at_sleep = master;

    // If the thread is still not running we can simply credit it with the master clock
    // since it will make no difference to the current experiment, and the next experiment
    // shall not receive the delay generated in the current one.
    if (task.isRunning()) this.applyDelay(task, lag, delay_per_tick);
}

fn applyDelay(this: *CausalEngine, task: *kernel.Task, lag: ClockTicks, delay_per_tick: u16) void {
    if (lag == 0) return;

    const time = lag * delay_per_tick;
    this.delay_pool.delay(task, time) catch this.abort("Could not apply delay");
}

fn recordThroughput(this: *CausalEngine, params: ExperimentParameters, snap: Snapshot, target_ip: usize) void {
    const wall = kernel.time.now.us() - snap.time;
    const vclock_delta = this.virtual_clocks.master.load(.acquire) - snap.master;
    const injected_delay = vclock_delta * params.delay_per_tick;

    const progress_delta: f32 = @floatFromInt(this.progress.load(.monotonic) -% snap.progress);
    const virtual_time: f32 = @floatFromInt(wall - injected_delay);

    this.disk_writer.push(serialization.record.Throughput{
        .relative_ip = target_ip - this.vma_base.load(.monotonic),
        .throughput = progress_delta / virtual_time,
        .speedup_percent = @truncate(params.speedup_percent),
    }) catch std.log.warn("Writer buffer full, dropping sample", .{});
}

fn flushRecords(this: *CausalEngine) void {
    this.disk_writer.push(serialization.record.Throughput.empty) catch {
        for (0..flush_retry_count) |_| {
            kernel.time.sleep.us(flush_retry_delay_us);
            this.disk_writer.push(serialization.record.Throughput.empty) catch continue;
            break;
        } else std.log.err("Could not emit last empty record, file corrupted", .{});
    };
}

fn tickVirtualClock(this: *CausalEngine) void {
    if (this.sampler_tick_delay_us.load(.monotonic) == 0) return;

    const current_task = kernel.Task.current();
    this.virtual_clocks.tick(.fromPtr(current_task)) catch {};
}

fn captureProfilingTarget(this: *CausalEngine, ip: usize) bool {
    const vma_base = this.vma_ranges.findBase(ip) orelse return false;

    if (this.target_ip.cmpxchgStrong(0, ip, .release, .monotonic)) |_| {
        @branchHint(.likely);
        return false;
    } else {
        this.vma_base.store(vma_base, .release);
        return true;
    }
}

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(event.context() orelse return));
    const ip = regs.ip;

    const target = this.target_ip.load(.monotonic);

    if (ip == target)
        this.tickVirtualClock()
    else if (target == 0)
        if (this.captureProfilingTarget(ip)) this.tickVirtualClock();
}

fn onSchedFork(data: ?*anyopaque, parent: *kernel.Task, child: *kernel.Task) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(data.?));
    if (parent.pid() != this.profiled_pid.load(.monotonic)) return;

    const lag = this.virtual_clocks.fork(.fromPtr(parent), .fromPtr(child)) catch blk: {
        const clocks, const bits = this.virtual_clocks.grow(atomic_allocator) catch {
            this.abort("Grow in fork failed");
            return;
        };

        const l = this.virtual_clocks.fork(.fromPtr(parent), .fromPtr(child)) catch {
            this.abort("Could not fork after grow");
            return;
        };

        atomic_allocator.free(clocks);
        atomic_allocator.free(bits);

        break :blk l;
    };

    const delay_per_tick = this.sampler_tick_delay_us.load(.monotonic);
    this.applyDelay(parent, lag, delay_per_tick);
    this.applyDelay(child, lag, delay_per_tick);
}

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);

    if (prev.pid() == profiled_pid and !prev.isRunning() and !prev.isDead())
        this.virtual_clocks.prepareForSleep(.fromPtr(prev));
}

fn onSchedWaking(data: ?*anyopaque, woke: *kernel.Task) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);

    const current = kernel.Task.current();

    if (current.pid() == profiled_pid and
        woke.pid() == profiled_pid and
        !woke.isRunning() and
        !woke.isDead())
    {
        const waker_lag, const woke_lag = this.virtual_clocks.wake(.fromPtr(current), .fromPtr(woke));

        const delay_per_tick = this.sampler_tick_delay_us.load(.monotonic);
        this.applyDelay(current, waker_lag, delay_per_tick);
        this.applyDelay(woke, woke_lag, delay_per_tick);
    }
}

fn onSchedExit(data: ?*anyopaque, task: *kernel.Task) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(data.?));

    if (task.pid() == this.profiled_pid.load(.monotonic))
        this.applyDelay(task, this.virtual_clocks.remove(.fromPtr(task)), this.sampler_tick_delay_us.load(.monotonic));
}

fn abort(this: *CausalEngine, s: []const u8) void {
    @branchHint(.cold);
    std.log.err("{s}", .{s});
    this.error_has_occurred.store(true, .monotonic);
}
