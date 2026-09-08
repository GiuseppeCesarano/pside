const std = @import("std");

const kernel = @import("kernel");
const allocator = kernel.heap.allocator;
const atomic_allocator = kernel.heap.atomic_allocator;

const GenericPool = @import("Pool.zig").GenericPool;
const DelayPool = @This();

const DelayWork = struct {
    work: kernel.Task.Work,
    time: std.atomic.Value(usize),
    pool: *DelayPool,
};

const Pool = GenericPool(DelayWork);

const uninitialized = std.math.maxInt(u32);

pools: *Pool,
users_count: std.atomic.Value(u32),
completion: kernel.Completion,

pub const empty: DelayPool = .{
    .pools = undefined,
    .users_count = .init(uninitialized),
    .completion = undefined,
};

pub fn init(this: *DelayPool) !void {
    if (this.users_count.load(.monotonic) != uninitialized) return;

    this.users_count = .init(0);

    this.pools = try allocator.create(Pool);
    this.initPool(this.pools);

    this.completion.init();
}

pub fn deinit(this: *DelayPool) void {
    if (this.users_count.load(.monotonic) == uninitialized) return;

    this.waitAllDelays();

    var pool: ?*Pool = this.pools.next.load(.monotonic);

    while (pool) |p| {
        pool = p.next.load(.monotonic);
        atomic_allocator.destroy(p);
    }

    allocator.destroy(this.pools);
}

pub fn delay(this: *DelayPool, task: *kernel.Task, delay_time: usize, mode: kernel.Task.NotifyMode) !void {
    std.debug.assert(delay_time != 0);

    _ = this.users_count.fetchAdd(1, .monotonic);
    errdefer _ = this.users_count.fetchSub(1, .monotonic);

    const slot = this.pools.getEntry() orelse try this.reserveInNewAllocation();
    errdefer this.pools.freeEntry(slot);

    slot.time.store(delay_time, .release);
    try task.addWork(&slot.work, mode);
}

fn initPool(this: *DelayPool, pool: *Pool) void {
    pool.* = .empty;
    for (&pool.entries) |*entry| entry.* = .{
        .work = .{ .func = executeDelay, .next = undefined },
        .pool = this,
        .time = undefined,
    };
}

fn reserveInNewAllocation(this: *DelayPool) !*DelayWork {
    const new_pool = try atomic_allocator.create(Pool);
    errdefer atomic_allocator.destroy(new_pool);

    this.initPool(new_pool);

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
    const delay_time = slot.time.load(.acquire);
    const this: *DelayPool = slot.pool;

    this.pools.freeEntry(slot);

    kernel.time.sleep.us(delay_time);

    const prev = this.users_count.fetchSub(1, .monotonic);
    if (prev == 1) this.completion.signal();
}
