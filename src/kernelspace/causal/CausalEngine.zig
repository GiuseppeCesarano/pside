// For this file if a time variable has no postfix indicating otherwise the default unit is us.

const CausalEngine = @This();
const std = @import("std");
const kernel = @import("kernel");
const thread_safe = @import("thread_safe.zig");
const ThroughputRecord = @import("communications").ThroughputRecord;

const Pid = std.os.linux.pid_t;
const Tid = Pid;

const atomic_allocator = kernel.heap.atomic_allocator;
const allocator = kernel.heap.allocator;

const DelayPool = struct {
    const DelayWork = struct {
        work: kernel.Task.Work,
        delay_time: std.atomic.Value(usize),
        pool: *DelayPool,
    };
    const Pool = thread_safe.Pool(DelayWork);

    pools: *Pool,
    users_count: std.atomic.Value(u32),
    completion: kernel.Completion,

    pub fn init() !DelayPool {
        const pool = try allocator.create(Pool);
        pool.* = .empty;
        return .{ .pools = pool, .users_count = .init(0), .completion = undefined };
    }

    pub fn initEntries(this: *@This()) void {
        for (&this.pools.entries) |*e| e.* = .{ .work = .{ .func = executeDelay, .next = undefined }, .pool = this, .delay_time = undefined };
        this.completion.init();
    }

    pub fn deinit(this: *@This()) void {
        this.waitAllDelays();

        var pool: ?*Pool = this.pools.next.load(.monotonic);

        while (pool) |p| {
            pool = p.next.load(.monotonic);
            atomic_allocator.destroy(p);
        }

        allocator.destroy(this.pools);
    }

    pub fn delay(this: *DelayPool, task: *kernel.Task, delay_time: usize) !void {
        if (delay_time == 0) return;

        _ = this.users_count.fetchAdd(1, .monotonic);
        errdefer _ = this.users_count.fetchSub(1, .monotonic);

        const slot = this.pools.getEntry() orelse s: {
            const new_pool = try atomic_allocator.create(Pool);
            errdefer atomic_allocator.destroy(new_pool);
            new_pool.* = .empty;
            for (&new_pool.entries) |*e| e.* = .{ .work = .{ .func = executeDelay, .next = undefined }, .pool = this, .delay_time = undefined };

            const entry = new_pool.getEntry().?;
            this.pools.appendPool(new_pool);

            break :s entry;
        };

        slot.delay_time.store(delay_time, .release);
        try task.addWork(&slot.work, .@"resume");
    }

    pub fn waitAllDelays(this: *DelayPool) void {
        this.completion.reinit();
        if (this.users_count.load(.monotonic) != 0) this.completion.wait();
    }

    fn executeDelay(work: *kernel.Task.Work) callconv(.c) void {
        const sleep_work: *DelayWork = @fieldParentPtr("work", work);
        const delay_time = sleep_work.delay_time.load(.acquire);
        const this: *DelayPool = @ptrCast(@alignCast(sleep_work.pool));

        this.pools.freeEntry(sleep_work);

        kernel.time.sleep.us(delay_time);

        const prev = this.users_count.fetchSub(1, .monotonic);
        if (prev == 1) this.completion.signal();
    }
};

const DiskWriter = struct {
    thread: ?*kernel.Thread,

    file: ?*kernel.File,
    file_offset: i64,

    buffer: []u8,
    buffer_begin: std.atomic.Value(usize),
    buffer_end: std.atomic.Value(usize),

    completion: kernel.Completion,

    pub fn init() !DiskWriter {
        const buffer = try allocator.alloc(u8, std.heap.page_size_min * 6);
        errdefer allocator.free(buffer);

        return .{
            .buffer = buffer,
            .buffer_begin = .init(0),
            .buffer_end = .init(0),
            .file_offset = 0,
            .thread = null,
            .file = null,
            .completion = undefined,
        };
    }

    pub fn deinit(this: *DiskWriter) void {
        if (this.thread == null) return;
        this.completion.signal();
        this.thread.?.stop();
        this.file.?.put();
        allocator.free(this.buffer);
    }

    pub fn start(this: *DiskWriter, fd: std.os.linux.fd_t) void {
        this.completion.init(); // init before thread spawns
        this.file = .get(fd);
        this.file_offset = this.file.?.size();
        this.thread = .run(writerFn, this, "pside_disk_writer");
    }

    pub fn push(this: *DiskWriter, record: anytype) !void {
        const bytes = std.mem.asBytes(&record);
        const len = this.buffer.len;
        const end = this.buffer_end.load(.monotonic);
        const begin = this.buffer_begin.load(.acquire);

        const free = if (end >= begin)
            len - (end - begin) - 1
        else
            begin - end - 1;

        if (free < bytes.len) return error.Full;

        const tail_space = len - end;
        if (bytes.len <= tail_space) {
            @memcpy(this.buffer[end .. end + bytes.len], bytes);
        } else {
            @memcpy(this.buffer[end..], bytes[0..tail_space]);
            @memcpy(this.buffer[0 .. bytes.len - tail_space], bytes[tail_space..]);
        }

        this.buffer_end.store((end + bytes.len) % len, .release);

        if (free <= len / 2) this.completion.signal();
    }

    fn writerFn(ctx: ?*anyopaque) callconv(.c) c_int {
        const this: *DiskWriter = @ptrCast(@alignCast(ctx.?));

        while (!kernel.Thread.shouldThisStop()) {
            this.completion.wait();
            defer this.completion.reinit();

            this.flush();
        }

        return 0;
    }

    pub fn flush(this: *DiskWriter) void {
        const begin = this.buffer_begin.load(.monotonic);
        const end = this.buffer_end.load(.acquire);
        if (begin == end) return;

        const len = this.buffer.len;

        if (end > begin) {
            _ = this.file.?.write(this.buffer[begin..end], &this.file_offset);
        } else {
            const tail = this.buffer[begin..len];
            const head = this.buffer[0..end];

            _ = this.file.?.write(tail, &this.file_offset);
            _ = this.file.?.write(head, &this.file_offset);
        }

        this.buffer_begin.store(end, .monotonic);
    }
};

const ClockTicks = thread_safe.ThreadClocks.Ticks;

const sampler_frequency = 997; //Hz, ~1ms; not round to avoid harmonics with the scheduler
const clocks_starting_len = 1024;

profiled_pid: std.atomic.Value(Pid) align(std.atomic.cache_line),
experiment_duration: usize,

profiler_thread: ?*kernel.Thread,
sampler: ?*kernel.PerfEvent,
disk_writer: DiskWriter,

delay_per_tick: std.atomic.Value(u16),
target_ip: std.atomic.Value(usize) align(std.atomic.cache_line),

progress: *std.atomic.Value(usize),
virtual_clocks: thread_safe.ThreadClocks,
delay_pool: DelayPool,

error_has_occurred: std.atomic.Value(bool),
deinit_guard: std.atomic.Value(bool),

pub fn init(progress_ptr: *std.atomic.Value(usize)) !CausalEngine {
    try kernel.Task.findAddWork();
    kernel.tracepoint.init();

    return .{
        .profiled_pid = .init(0),
        .experiment_duration = 45 * std.time.us_per_ms,
        .delay_per_tick = .init(0),
        .target_ip = .init(0),
        .progress = progress_ptr,
        .virtual_clocks = try .init(allocator, clocks_starting_len),
        .delay_pool = try .init(),
        .error_has_occurred = .init(false),
        .deinit_guard = .init(false),
        .profiler_thread = null,
        .sampler = null,
        .disk_writer = try .init(),
    };
}

// TODO: check this sequence
pub fn deinit(this: *CausalEngine) void { 
    if (this.deinit_guard.swap(true, .acq_rel)) return;

    this.profiled_pid.store(0, .monotonic);
    this.error_has_occurred.store(true, .monotonic);

    if (this.profiler_thread) |t| t.stop();
    if (this.sampler) |s| s.deinit();

    kernel.tracepoint.sched.fork.unregister(onSchedFork, this);
    kernel.tracepoint.sched.@"switch".unregister(onSchedSwitch, this);
    kernel.tracepoint.sched.waking.unregister(onSchedWaking, this);
    kernel.tracepoint.sched.exit.unregister(onSchedExit, this);
    kernel.tracepoint.sync();

    this.delay_pool.deinit();
    this.disk_writer.deinit();

    this.virtual_clocks.ref.increment();
    const drift_len = this.virtual_clocks.pairs.len;
    this.virtual_clocks.ref.decrement();
    this.virtual_clocks.deinit(if (drift_len == clocks_starting_len) allocator else atomic_allocator);
}

pub fn profilePid(this: *CausalEngine, pid: Pid, fd: std.os.linux.fd_t) !void {
    const task = kernel.Task.fromTid(pid);

    this.disk_writer.start(fd);

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
        this.virtual_clocks.forEach(applyDelayForThread, .{this});
        kernel.preempt.enable();

        this.delay_pool.waitAllDelays();

        const v_ticks = this.virtual_clocks.master.load(.acquire) - baseline_vclock;
        const total_delay = v_ticks * delay_per_tick;
        const wall = kernel.time.now.us() - start_wall;

        this.disk_writer.push(ThroughputRecord{
            .ip = this.target_ip.load(.monotonic),
            .prog_delta = prog_delta,
            .wall = wall,
            .total_delay = total_delay,
            .delay_per_tick = delay_per_tick,
        }) catch {}; //We just drop the sample
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

fn applyDelayForThread(master: ClockTicks, key: *thread_safe.ThreadClocks.Key, value: *thread_safe.ThreadClocks.Value, this: *CausalEngine) void {
    // We force collision bit since kernel pointer live in 0xffff8...
    const task: *kernel.Task = @ptrFromInt(key.withCollisionBit().data);
    if (!task.isRunning()) return;

    const lag = master - value.ticks;
    value.ticks = master;

    this.applyDelay(task, lag);
}

fn applyDelay(this: *CausalEngine, task: *kernel.Task, lag: ClockTicks) void {
    const time = lag * this.delay_per_tick.load(.monotonic);
    this.delay_pool.delay(task, time) catch {
        this.abort("Could not apply delay");
        return;
    };
}

fn abort(this: *CausalEngine, s: []const u8) void {
    @branchHint(.cold);
    std.log.err("{s}", .{s});
    this.error_has_occurred.store(true, .monotonic);
    this.deinit();
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

    this.applyDelay(parent, lag);
    this.applyDelay(child, lag);
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
        this.applyDelay(current, waker_lag);
        this.applyDelay(woke, woke_lag);
    }
}

fn onSchedExit(data: ?*anyopaque, task: *kernel.Task) callconv(.c) void {
    const this: *CausalEngine = @ptrCast(@alignCast(data.?));
    if (task.pid() != this.profiled_pid.load(.monotonic)) return;

    const lag = this.virtual_clocks.remove(.fromPtr(task));
    this.applyDelay(task, lag);
    task.decrementReferences();
}
