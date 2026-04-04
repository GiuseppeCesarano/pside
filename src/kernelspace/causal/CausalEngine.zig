// For this file if a time variable has no postfix indicating otherwise the default unit is us.

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
const sampler_frequency = 997; //Hz, ~1ms; not round to avoid harmonics with the scheduler
const clocks_starting_len = 1024;

deinit_guard: std.atomic.Value(bool),
profiled_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
error_has_occurred: std.atomic.Value(bool),

target_ip: std.atomic.Value(usize) align(std.atomic.cache_line),
vma_ranges: VmaRanges,
vma_base: std.atomic.Value(usize),
delay_per_tick: std.atomic.Value(u16),

experiment_duration: usize,
progress: *std.atomic.Value(usize),
virtual_clocks: thread_safe.ThreadClocks,
delay_pool: DelayPool,

profiler_thread: ?*kernel.Thread,
sampler: ?*kernel.PerfEvent,
disk_writer: DiskWriter,

pub fn init(progress_ptr: *std.atomic.Value(usize)) !CausalEngine {
    try kernel.Task.findAddWork();
    kernel.tracepoint.init();

    return .{
        .deinit_guard = .init(false),
        .profiled_pid = .init(0),
        .error_has_occurred = .init(false),

        .target_ip = .init(0),
        .vma_ranges = .empty,
        .vma_base = .init(0),
        .delay_per_tick = .init(0),

        .experiment_duration = 0,
        .progress = progress_ptr,
        .virtual_clocks = try .init(allocator, clocks_starting_len),
        .delay_pool = try .init(),

        .profiler_thread = null,
        .sampler = null,
        .disk_writer = .empty,
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

    const clocks_len = this.virtual_clocks.pairs.len;
    this.virtual_clocks.deinit(if (clocks_len == clocks_starting_len) allocator else atomic_allocator);
}

pub fn profilePid(this: *CausalEngine, pid: Pid, fd: std.os.linux.fd_t, vma_name: [:0]const u8) !void {
    const task = kernel.Task.fromTid(pid);

    this.experiment_duration = 45 * std.time.us_per_ms;
    this.vma_ranges = try .snapshot(task, vma_name);

    try this.disk_writer.start(fd);
    try this.disk_writer.push(serialization.SectionHeader{ .kind = .throughput });
    try this.disk_writer.pushBytes(vma_name);
    try this.disk_writer.push(@as(u8, 0));

    try this.virtual_clocks.put(.fromPtr(task), 0);
    this.profiled_pid.store(pid, .monotonic);

    this.delay_pool.initEntries(); //TODO: not happy about that

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

    while (!kernel.Thread.shouldThisStop() and !this.error_has_occurred.load(.monotonic)) {
        const speedup_percent = this.setExperimentParameters();

        const delay_per_tick = this.delay_per_tick.load(.monotonic);
        const baseline_prog = this.progress.load(.monotonic);
        const vclock_start = this.virtual_clocks.master.load(.acquire);
        const start_wall = kernel.time.now.us();

        if (speedup_percent != 0) this.sampler.?.enable();
        kernel.time.sleep.us(this.experiment_duration);

        var prog_delta = this.progress.load(.monotonic) -% baseline_prog;
        while (prog_delta < 5) : (prog_delta = this.progress.load(.monotonic) -% baseline_prog) {
            @branchHint(.cold);
            if (kernel.Thread.shouldThisStop()) break;
            this.experiment_duration *|= 2;
            kernel.time.sleep.us(this.experiment_duration / 2);
        }

        if (speedup_percent != 0) this.sampler.?.disable();

        const vma_base = this.vma_base.load(.monotonic);
        const target_ip = this.target_ip.load(.monotonic);

        if (kernel.Thread.shouldThisStop() or this.error_has_occurred.load(.monotonic) or target_ip == 0) {
            @branchHint(.unlikely);

            kernel.preempt.disable();
            this.virtual_clocks.forEach(clearThreadDelay, .{});
            kernel.preempt.enable();

            continue;
        }

        if (speedup_percent != 0) {
            kernel.preempt.disable();
            this.virtual_clocks.forEach(applyDelayToThread, .{this});
            kernel.preempt.enable();

            this.delay_pool.waitAllDelays();
        }

        const vclock_delta = this.virtual_clocks.master.load(.acquire) - vclock_start;
        const total_delay = vclock_delta * delay_per_tick;
        const wall = kernel.time.now.us() - start_wall;

        this.disk_writer.push(serialization.record.Throughput{
            .relative_ip = this.target_ip.load(.monotonic) - vma_base,
            .progress_delta = prog_delta,
            .wall = wall,
            .injected_delay = total_delay,
            .speedup_percent = speedup_percent,
        }) catch std.log.warn("Writer buffer full, dropping sample", .{}); //We just drop the sample
    }

    this.disk_writer.push(serialization.record.Throughput.empty) catch {
        for (0..3) |_| {
            kernel.time.sleep.us(50);
            this.disk_writer.push(serialization.record.Throughput.empty) catch continue;
            break;
        } else std.log.err("Could not emit last empty record, file corrupted", .{});
    };

    return 0;
}

fn setExperimentParameters(this: *CausalEngine) u8 {
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

    // Like coz, ~25% bias towards 0% speedup, then linear distribution on 5% increments.
    const roll = random.generator.uintLessThan(usize, 27);
    const speedup_percent = (roll -| 6) * 5;
    const sampler_period = 1_000_000 / sampler_frequency;
    const delay = (speedup_percent * sampler_period) / 100;

    this.delay_per_tick.store(@truncate(delay), .monotonic);

    return @truncate(speedup_percent);
}

fn clearThreadDelay(master: ClockTicks, _: *thread_safe.ThreadClocks.Key, value: *thread_safe.ThreadClocks.Value) void {
    value.ticks = master;
}

fn applyDelayToThread(master: ClockTicks, key: *thread_safe.ThreadClocks.Key, value: *thread_safe.ThreadClocks.Value, this: *CausalEngine) void {
    const task: *kernel.Task = @ptrFromInt(key.withoutCollisionBit().data);

    const lag = master - value.ticks;
    value.ticks = master;
    value.master_at_sleep = master;

    // If the thread is still not running we can simply credit it with
    // the master clock since it will make no difference to the current
    // experiment, and the next experiment shall not recive the delay
    // generated in current one.
    if (task.isRunning())
        this.applyDelay(task, lag);
}

fn applyDelay(this: *CausalEngine, task: *kernel.Task, lag: ClockTicks) void {
    if (lag == 0) return;

    const time = lag * this.delay_per_tick.load(.monotonic);
    this.delay_pool.delay(task, time) catch this.abort("Could not apply delay");
}

fn abort(this: *CausalEngine, s: []const u8) void {
    @branchHint(.cold);
    std.log.err("{s}", .{s});
    this.error_has_occurred.store(true, .monotonic);
}

fn onSamplerTick(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(event.context() orelse return));

    const ip = regs.ip;
    const target = this.target_ip.load(.monotonic);

    if (target == ip) {
        const current_task = kernel.Task.current();
        this.virtual_clocks.tick(.fromPtr(current_task)) catch {};
        return;
    }

    if (target == 0) {
        @branchHint(.unlikely);
        if (this.vma_ranges.findBase(ip)) |vma_base| {
            @branchHint(.unlikely);
            if (this.target_ip.cmpxchgStrong(0, ip, .release, .monotonic) == null) {
                @branchHint(.likely);
                this.vma_base.store(vma_base, .release);
                const current_task = kernel.Task.current();
                this.virtual_clocks.tick(.fromPtr(current_task)) catch {};
            }
        }
    }
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
            this.abort("Could not fork afther grow");
            return;
        };

        // Currently they both call kfree so this if block is useless for now.
        // This is there just for consistency (also free is always non blocking)
        if (clocks.len == clocks_starting_len) {
            allocator.free(clocks);
            allocator.free(bits);
        } else {
            atomic_allocator.free(clocks);
            atomic_allocator.free(bits);
        }

        break :blk l;
    };

    this.applyDelay(parent, lag);
    this.applyDelay(child, lag);
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

        this.applyDelay(current, waker_lag);
        this.applyDelay(woke, woke_lag);
    }
}

fn onSchedExit(data: ?*anyopaque, task: *kernel.Task) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(data.?));

    if (task.pid() == this.profiled_pid.load(.monotonic))
        this.applyDelay(task, this.virtual_clocks.remove(.fromPtr(task)));
}
