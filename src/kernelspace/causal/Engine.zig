// Time unit convention: All time variables use microseconds (us) unless otherwise marked.

const std = @import("std");
const Pid = std.os.linux.pid_t;

const kernel = @import("kernel");
const atomic_allocator = kernel.heap.atomic_allocator;
const allocator = kernel.heap.allocator;
const serialization = @import("serialization");

const DiskWriter = @import("DiskWriter.zig");
const ThreadClocks = @import("thread_safe/ThreadClocks.zig");
const Ticks = ThreadClocks.Ticks;
const DelayPool = @import("thread_safe/DelayPool.zig");
const VmaRanges = @import("VmaRanges.zig");

const Engine = @This();

const sampler_frequency = 997; // Hz, ~1ms; not round to avoid harmonics with the scheduler
const initial_experiment_duration_us = 50 * std.time.us_per_ms;
const max_experiment_duration_us = 1 * std.time.us_per_s;
const min_progress_delta = 5;
const decay_progress_delta = min_progress_delta * 4;
const flush_retry_count = 3;
const flush_retry_delay_us = 50;

const ExperimentParameters = struct {
    speedup_percent: u16,
    delay_per_tick: u16,
};

const Snapshot = struct {
    progress: usize,
    master: Ticks,
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
virtual_clocks: ThreadClocks,

// Delay application & output
delay_pool: DelayPool,
disk_writer: DiskWriter,

// System integration
profiler_thread: ?*kernel.Thread,
sampler: ?*kernel.PerfEvent,

// Lifecycle management
deinit_guard: std.atomic.Value(bool),
error_has_occurred: std.atomic.Value(bool),

pub fn init(progress_ptr: *std.atomic.Value(usize)) !Engine {
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

pub fn deinit(this: *Engine) void {
    if (this.deinit_guard.swap(true, .seq_cst)) return;

    if (this.profiler_thread) |t| t.stop();

    kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);
    kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
    kernel.tracepoint.task.newtask.unregister(onNewTask, this);
    kernel.tracepoint.sync();

    if (this.sampler) |s| s.deinit();
    this.vma_ranges.deinit();

    this.disk_writer.deinit();
    this.delay_pool.deinit();

    this.virtual_clocks.removeIf(releaseThread, .{});
    this.virtual_clocks.deinit(atomic_allocator);
}

pub fn profilePid(this: *Engine, pid: Pid, fd: std.os.linux.fd_t, vma_name: [:0]const u8) !void {
    try this.delay_pool.init();

    const task = kernel.Task.fromTid(pid) orelse return error.TaskNotFound;

    // fromTid's task reference is kept as the map entry's, dropped at sweep.
    // Once in the map, any later failure is balanced by deinit's sweep.
    this.virtual_clocks.put(.fromPtr(task), 0) catch |err| {
        task.decrementReferences();
        return err;
    };

    this.experiment_duration_us = initial_experiment_duration_us;
    this.vma_ranges = try .snapshot(task, vma_name);

    try this.disk_writer.start(fd);

    try this.disk_writer.push(.{
        serialization.SectionHeader{ .kind = .throughput },
        vma_name[0 .. vma_name.len + 1],
    });

    this.profiled_pid.store(pid, .monotonic);

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
            .exclude_kernel = true,
        },
    };
    this.sampler = try kernel.PerfEvent.init(&sampler_attr, -1, pid, onSamplerTick, this);

    this.profiler_thread = kernel.Thread.run(profilingLoop, this, "pside_loop") orelse return error.ThreadSpawnFailed;
}

fn profilingLoop(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *Engine = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldThisStop() and !this.error_has_occurred.load(.monotonic)) {
        const params = this.generateRandomExperimentParameters();
        const snap = this.takeSnapshot();

        this.doExperiment(params, snap.progress);

        const target_ip = this.target_ip.load(.monotonic);
        const should_stop = kernel.Thread.shouldThisStop() or this.error_has_occurred.load(.monotonic);

        if (should_stop or (target_ip == 0 and params.speedup_percent != 0)) continue;

        this.applyAllDelays(params.delay_per_tick);
        this.recordThroughput(params, snap, target_ip);
    }

    this.flushRecords();
    return 0;
}

fn generateRandomExperimentParameters(this: *Engine) ExperimentParameters {
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

fn takeSnapshot(this: *Engine) Snapshot {
    return .{
        .progress = this.progress.load(.monotonic),
        .master = this.virtual_clocks.master.load(.acquire),
        .time = kernel.time.now.us(),
    };
}

fn doExperiment(this: *Engine, params: ExperimentParameters, baseline_prog: usize) void {
    this.sampler_tick_delay_us.store(params.delay_per_tick, .monotonic);
    this.vma_base.store(0, .monotonic);
    this.target_ip.store(0, .monotonic);

    if (params.speedup_percent != 0) this.sampler.?.enable();
    kernel.time.sleep.us(this.experiment_duration_us);

    var prog_delta = this.progress.load(.monotonic) -% baseline_prog;
    while (prog_delta < min_progress_delta and
        !kernel.Thread.shouldThisStop()) : (prog_delta = this.progress.load(.monotonic) -% baseline_prog)
    {
        this.experiment_duration_us = @min(max_experiment_duration_us, this.experiment_duration_us *| 2);
        kernel.time.sleep.us(this.experiment_duration_us / 2);
    }

    if (prog_delta > decay_progress_delta)
        this.experiment_duration_us = @max(initial_experiment_duration_us, this.experiment_duration_us / 2);

    this.sampler_tick_delay_us.store(0, .monotonic); // stop in flight ticks
    if (params.speedup_percent != 0) this.sampler.?.disable();
}

fn applyAllDelays(this: *Engine, delay_per_tick: u16) void {
    if (delay_per_tick == 0) return;

    kernel.preempt.disable();
    this.virtual_clocks.forEach(applyDelayToThread, .{ this, delay_per_tick });
    kernel.preempt.enable();

    this.delay_pool.waitAllDelays();
}

fn applyDelayToThread(master: Ticks, key: *ThreadClocks.Key, value: *ThreadClocks.Value, this: *Engine, delay_per_tick: u16) void {
    const task: *kernel.Task = @ptrFromInt(key.withoutCollisionBit().data);
    const lag = value.setToMaster(master);

    // If the thread is still not running we can simply credit it with the master clock
    // since it will make no difference to the current experiment, and the next experiment
    // shall not receive the delay generated in the current one.
    if (task.isRunning()) this.applyDelay(task, lag, delay_per_tick);
}

fn applyDelay(this: *Engine, task: *kernel.Task, lag: Ticks, delay_per_tick: u16) void {
    if (lag == 0 or delay_per_tick == 0) return;

    const time = lag * delay_per_tick;
    this.delay_pool.delay(task, time) catch |err| switch (err) {
        // Past exit_task_work the work can never run; the task is off any critical path.
        error.TooLateShuttingDown => {},
        else => this.abort("Could not apply delay"),
    };
}

fn recordThroughput(this: *Engine, params: ExperimentParameters, snap: Snapshot, target_ip: usize) void {
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

fn flushRecords(this: *Engine) void {
    this.disk_writer.push(serialization.record.Throughput.empty) catch {
        for (0..flush_retry_count) |_| {
            kernel.time.sleep.us(flush_retry_delay_us);
            this.disk_writer.push(serialization.record.Throughput.empty) catch continue;
            break;
        } else std.log.err("Could not emit last empty record, file corrupted", .{});
    };
}

fn captureProfilingTarget(this: *Engine, ip: usize) bool {
    const vma_base = this.vma_ranges.findBase(ip) orelse return false;

    if (this.target_ip.cmpxchgStrong(0, ip, .release, .monotonic)) |_| {
        @branchHint(.unlikely);
        return false;
    } else {
        this.vma_base.store(vma_base, .release);
        return true;
    }
}

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *Engine = @ptrCast(@alignCast(event.context() orelse return));
    const ip = regs.ip;

    const target = this.target_ip.load(.monotonic);
    const delay_per_tick = this.sampler_tick_delay_us.load(.monotonic);
    const current_task = kernel.Task.current();

    const is_target = (ip == target) or (target == 0 and this.captureProfilingTarget(ip));

    if (delay_per_tick != 0 and is_target)
        this.virtual_clocks.tick(.fromPtr(current_task)) catch {};
}

fn onNewTask(data: ?*anyopaque, child: *kernel.Task, _: c_ulong) callconv(.c) void {
    const this: *Engine = @ptrCast(@alignCast(data.?));
    const parent = kernel.Task.current();

    if (parent.pid() != this.profiled_pid.load(.monotonic)) return;

    const lag = this.virtual_clocks.fork(.fromPtr(parent), .fromPtr(child)) catch blk: {
        // Reclaim reaped threads before paying for a grow.
        this.virtual_clocks.removeIf(releaseThreadIfReaped, .{});

        break :blk this.virtual_clocks.fork(.fromPtr(parent), .fromPtr(child)) catch {
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
    };

    // The map entry owns a task reference until the reap sweep drops it.
    child.incrementReferences();

    const delay_per_tick = this.sampler_tick_delay_us.load(.monotonic);
    this.applyDelay(parent, lag, delay_per_tick);
    this.applyDelay(child, lag, delay_per_tick);
}

fn onSchedSwitch(data: ?*anyopaque, _: bool, prev: *kernel.Task, _: *kernel.Task) callconv(.c) void {
    const this: *Engine = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);

    if (prev.pid() == profiled_pid and !prev.isRunning() and !prev.isDead())
        this.virtual_clocks.prepareForSleep(.fromPtr(prev));
}

fn onSchedWaking(data: ?*anyopaque, woke: *kernel.Task) callconv(.c) void {
    const this: *Engine = @ptrCast(@alignCast(data.?));
    const profiled_pid = this.profiled_pid.load(.monotonic);

    if (woke.pid() != profiled_pid or woke.isRunning() or woke.isDead()) return;

    const current = kernel.Task.current();
    const delay_per_tick = this.sampler_tick_delay_us.load(.monotonic);

    // In interrupt context `current` is whoever got interrupted, never a waker.
    if (kernel.execution.inTask() and current.pid() == profiled_pid) {
        const waker_lag, const woke_lag = this.virtual_clocks.wake(.fromPtr(current), .fromPtr(woke));

        // A dying waker can't repay on the critical path; its lag is already in woke_lag.
        if (!current.isDead()) this.applyDelay(current, waker_lag, delay_per_tick);
        this.applyDelay(woke, woke_lag, delay_per_tick);
    } else {
        // External wake (timer, io): nobody paid on the wakee's behalf, it repays itself.
        this.applyDelay(woke, this.virtual_clocks.externalWake(.fromPtr(woke)), delay_per_tick);
    }
}

/// Only reaped tasks leave the map: their exit wake already handed the lag to
/// the joiner, and the held reference kept the pointer from being recycled.
fn releaseThreadIfReaped(key: *ThreadClocks.Key) bool {
    const task: *kernel.Task = @ptrFromInt(key.withoutCollisionBit().data);
    if (!task.isReaped()) return false;

    task.decrementReferences();
    return true;
}

fn releaseThread(key: *ThreadClocks.Key) bool {
    const task: *kernel.Task = @ptrFromInt(key.withoutCollisionBit().data);
    task.decrementReferences();
    return true;
}

fn abort(this: *Engine, s: []const u8) void {
    @branchHint(.cold);
    std.log.err("{s}", .{s});
    this.error_has_occurred.store(true, .monotonic);
}
