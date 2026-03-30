const std = @import("std");

const kernel = @import("kernel");
const allocator = kernel.heap.allocator;
const atomic_allocator = kernel.heap.atomic_allocator;

const CausalEngine = @import("CausalEngine.zig");
const thread_safe = @import("thread_safe.zig");

const DelayPool = @This();

const Data = packed struct(usize) {
    u: packed union {
        time: usize,
        engine: usize,
    },
};

const DelayWork = struct {
    work: kernel.Task.Work,
    data: std.atomic.Value(Data),
    pool: *DelayPool,
};
const Pool = thread_safe.Pool(DelayWork);

pools: *Pool,
users_count: std.atomic.Value(u32),
completion: kernel.Completion,

pub fn init() !DelayPool {
    const pool = try allocator.create(Pool);
    pool.* = .empty;
    return .{
        .pools = pool,
        .users_count = .init(0),
        .completion = undefined,
    };
}

pub fn initEntries(this: *@This()) void {
    for (&this.pools.entries) |*e| e.* = .{
        .work = .{ .func = executeDelay, .next = undefined },
        .pool = this,
        .data = undefined,
    };

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

    const slot = this.pools.getEntry() orelse try this.reserveInNewAllocation();

    slot.data.store(.{ .u = .{ .time = delay_time } }, .release);
    try task.addWork(&slot.work, .@"resume");
}

fn reserveInNewAllocation(this: *DelayPool) !*DelayWork {
    const new_pool = try atomic_allocator.create(Pool);
    errdefer atomic_allocator.destroy(new_pool);
    new_pool.* = .empty;
    for (&new_pool.entries) |*e| e.* = .{
        .work = .{ .func = executeDelay, .next = undefined },
        .pool = this,
        .data = undefined,
    };

    const entry = new_pool.getEntry().?;
    this.pools.appendPool(new_pool);

    return entry;
}

pub fn waitAllDelays(this: *DelayPool) void {
    this.completion.reinit();
    if (this.users_count.load(.monotonic) != 0) this.completion.wait();
}

fn executeDelay(work: *kernel.Task.Work) callconv(.c) void {
    const slot: *DelayWork = @fieldParentPtr("work", work);
    const delay_time = slot.data.load(.acquire).u.time;
    const this: *DelayPool = @ptrCast(@alignCast(slot.pool));

    this.pools.freeEntry(slot);

    kernel.time.sleep.us(delay_time);

    const prev = this.users_count.fetchSub(1, .monotonic);
    if (prev == 1) this.completion.signal();
}
