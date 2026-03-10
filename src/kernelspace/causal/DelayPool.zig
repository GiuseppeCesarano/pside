const std = @import("std");
const thread_safe = @import("thread_safe.zig");
const kernel = @import("kernel");
const allocator = kernel.heap.allocator;
const atomic_allocator = kernel.heap.atomic_allocator;
const DelayPool = @This();

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
    for (&this.pools.entries) |*e| e.* = .{
        .work = .{ .func = executeDelay, .next = undefined },
        .pool = this,
        .delay_time = undefined,
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
