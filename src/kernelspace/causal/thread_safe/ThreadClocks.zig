const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const RefGate = @import("RefGate.zig");

/// Concurrent map optimized for thread-local clock propagation.
const ThreadClocks = @This();

pub const Ticks = u32;

pub const Key = packed struct(usize) {
    data: usize,

    const bit_size = @bitSizeOf(Key);
    const Unsigned = @Int(.unsigned, bit_size);
    // Task pointers are always aligned so the first bit will always be 0
    // and we can use that as collide flag
    const collided_bit: Unsigned = 1;

    pub const empty: Key = .{ .data = 0 };
    pub const empty_collided: Key = @bitCast(collided_bit);

    pub const reserved: Key = @bitCast(std.math.maxInt(Unsigned) & ~collided_bit);

    pub fn isEql(this: Key, other: Key) bool {
        const this_bits: Unsigned = @bitCast(this);
        const other_bits: Unsigned = @bitCast(other);

        return (this_bits | collided_bit) == (other_bits | collided_bit);
    }

    pub fn hasCollided(this: Key) bool {
        const this_bits: Unsigned = @bitCast(this);
        return (this_bits & collided_bit) != 0;
    }

    pub fn fromPtr(ptr: *anyopaque) Key {
        const int = @intFromPtr(ptr);
        // kernel pointers shall always be aligned and we rely on that fact.
        assert(int % 2 == 0);

        return .{ .data = int };
    }

    pub fn hash(this: Key) usize {
        const unsigned: Unsigned = @bitCast(this.data);
        return std.hash.int(unsigned);
    }

    pub fn withCollisionBit(this: Key) Key {
        const bits: Unsigned = @bitCast(this);
        return @bitCast(bits | collided_bit);
    }

    pub fn withoutCollisionBit(this: Key) Key {
        const bits: Unsigned = @bitCast(this);
        return @bitCast(bits & ~collided_bit);
    }
};

pub const Value = packed struct(u64) {
    const ticks_lsb: u64 = @bitCast(Value{ .ticks = 1, .master_at_sleep = 0 });

    ticks: Ticks,
    master_at_sleep: Ticks,

    pub fn setToMaster(this: *Value, master: Ticks) Ticks {
        const lag = master - this.ticks;
        this.* = .{ .ticks = master, .master_at_sleep = master };

        return lag;
    }
};

const Pair = struct {
    key: std.atomic.Value(Key),
    value: std.atomic.Value(Value),

    const empty: Pair = .{ .key = .init(.empty), .value = undefined };
};

master: std.atomic.Value(Ticks) align(std.atomic.cache_line),
ref: RefGate,
pairs: []Pair,
bitmask: []std.atomic.Value(usize),

pub fn init(allocator: std.mem.Allocator, reserve: usize) !ThreadClocks {
    assert(@popCount(reserve) == 1);
    assert(reserve >= @bitSizeOf(usize));

    const pairs = try allocator.alloc(Pair, reserve);
    errdefer allocator.free(pairs);
    @memset(pairs, Pair.empty);

    const bitmask_len = @divExact(reserve, @bitSizeOf(usize));
    const used_bitmask = try allocator.alloc(std.atomic.Value(usize), bitmask_len);
    @memset(used_bitmask, .init(0));

    return .{
        .master = .init(0),
        .ref = .{},
        .pairs = pairs,
        .bitmask = used_bitmask,
    };
}

pub fn deinit(this: *ThreadClocks, allocator: std.mem.Allocator) void {
    this.ref.close();
    this.ref.drain();
    allocator.free(this.pairs);
    allocator.free(this.bitmask);
}

fn reserveSlotUnsafe(this: *ThreadClocks, key: Key, hash: usize) !*Pair {
    const len = this.pairs.len;

    assert(@popCount(len) == 1);
    const bitmask = len - 1;
    const max_retries = @max(16, len / 32);

    var i: usize = 0;
    while (i < max_retries) : (i += 1) {
        const index = (hash + i) & bitmask;
        const current_key = this.pairs[index].key.load(.monotonic);

        // Double insertion of the same key would mean broken logic
        assert(!current_key.isEql(key));

        const reserved = Key{ .data = Key.reserved.data | current_key.data };

        if (current_key.isEql(.empty) and
            this.pairs[index].key.cmpxchgStrong(current_key, reserved, .acquire, .monotonic) == null) // or will preserve the collided bit.
            return &this.pairs[index];

        if (!current_key.hasCollided())
            _ = this.pairs[index].key.fetchOr(Key.empty_collided, .monotonic);
    }

    return error.NoSpace;
}

fn publishReservedUnsafe(this: *ThreadClocks, key: Key, ptr: *Pair) void {
    assert(ptr.key.load(.unordered).isEql(.reserved));

    const index = this.getIndexUnsafe(ptr);

    const bit_bucket = &this.bitmask[@divFloor(index, @bitSizeOf(usize))];
    const operand = @as(usize, 1) << @intCast(index % @bitSizeOf(usize));
    _ = bit_bucket.fetchOr(operand, .monotonic);

    _ = ptr.key.fetchAnd(key.withCollisionBit(), .release);
}

/// Looks up the clock slot for a given key.
///
/// Note: A null return is only expected if the task was recently deleted (onSchedFree).
/// This typically happens during a race where one CPU cleans up the task while another
/// is mid-scheduler-event (like onSchedSwitch).
///
/// If this returns null, the caller should treat the task as having no local
/// accumulated delay and fallback to using the Master Clock for any attributions.
///
/// Conversely, the 'target' task (the one receiving the delay/tick) must always
/// exist in the map; if a target task lookup returns null, it indicates a
/// fundamental tracking failure and should be asserted with .?.
fn getSlotUnsafe(this: *ThreadClocks, key: Key, hash: usize) ?*Pair {
    const len = this.pairs.len;

    assert(@popCount(len) == 1);
    const bitmask = len - 1;
    const max_retries = @max(16, len / 32);

    var i: usize = 0;
    var current_key: Key = .empty_collided;
    return slot: while (current_key.hasCollided() and i < max_retries) : (i += 1) {
        const index = (hash + i) & bitmask;
        current_key = this.pairs[index].key.load(.acquire);
        if (current_key.isEql(key)) break :slot &this.pairs[index];
    } else null;
}

fn getIndexUnsafe(this: *ThreadClocks, elm: *Pair) usize {
    const elm_addr: usize = @intFromPtr(elm);
    const starting_addr: usize = @intFromPtr(this.pairs.ptr);
    return @divExact(elm_addr - starting_addr, @sizeOf(Pair));
}

pub fn put(this: *ThreadClocks, key: Key, ticks: Ticks) !void {
    const hash = key.hash();

    this.ref.increment();
    defer this.ref.decrement();

    const slot = try this.reserveSlotUnsafe(key, hash);

    slot.value.store(.{ .ticks = ticks, .master_at_sleep = undefined }, .monotonic);

    this.publishReservedUnsafe(key, slot);
}

pub fn get(this: *ThreadClocks, key: Key, field: enum { ticks, lag }) Ticks {
    const hash = key.hash();

    this.ref.increment();
    defer this.ref.decrement();

    const slot = this.getSlotUnsafe(key, hash).?;
    const value = slot.value.load(.monotonic);

    return if (field == .ticks) value.ticks else value.master_at_sleep - value.ticks;
}

pub fn tick(this: *ThreadClocks, key: Key) !void {
    const hash = key.hash();

    try this.ref.tryIncrement();
    defer this.ref.decrement();

    const slot = this.getSlotUnsafe(key, hash).?;
    const value_as_ticks: *std.atomic.Value(u64) = @ptrCast(&slot.value);

    const ticks: Value = @bitCast(value_as_ticks.fetchAdd(Value.ticks_lsb, .monotonic));

    _ = this.master.fetchMax(ticks.ticks + 1, .release);
}

pub fn prepareForSleep(this: *ThreadClocks, key: Key) void {
    this.ref.increment();
    defer this.ref.decrement();

    const slot = this.getSlotUnsafe(key, key.hash()).?;
    const master = this.master.load(.acquire);
    const ticks = slot.value.load(.monotonic).ticks;

    slot.value.store(.{ .ticks = ticks, .master_at_sleep = master }, .monotonic);
}

/// Wakes a sleeping thread, the sleeping thread must have calld prepareForSleep.
/// Returns the delay amounts those threads should sleep
pub fn wake(this: *ThreadClocks, waker: Key, wakee: Key) [2]Ticks {
    const waker_hash = waker.hash();
    const wakee_hash = wakee.hash();

    this.ref.increment();
    defer this.ref.decrement();

    const wakee_slot = this.getSlotUnsafe(wakee, wakee_hash).?;
    const wakee_value = wakee_slot.value.load(.monotonic);

    const master = this.master.load(.acquire);

    const waker_slot = this.getSlotUnsafe(waker, waker_hash);
    const waker_ticks = if (waker_slot) |slot| slot.value.load(.monotonic).ticks else master;

    const wakee_lag = wakee_value.master_at_sleep -| wakee_value.ticks;
    const wakee_credit = wakee_value.ticks -| wakee_value.master_at_sleep;

    wakee_slot.value.store(.{ .ticks = master, .master_at_sleep = undefined }, .monotonic);
    if (waker_slot) |slot| slot.value.store(.{ .ticks = master, .master_at_sleep = undefined }, .monotonic);

    const waker_lag = master - waker_ticks;
    return .{ waker_lag, waker_lag + wakee_lag -| wakee_credit };
}

/// Returns the full lag a thread woken by an external event must repay itself.
pub fn externalWake(this: *ThreadClocks, key: Key) Ticks {
    const hash = key.hash();

    this.ref.increment();
    defer this.ref.decrement();

    const slot = this.getSlotUnsafe(key, hash).?;

    const master = this.master.load(.acquire);
    const old = slot.value.swap(.{ .ticks = master, .master_at_sleep = undefined }, .monotonic);

    return master - old.ticks;
}

/// Removes a tracked task
pub fn remove(this: *ThreadClocks, task: Key) void {
    const task_hash = task.hash();

    this.ref.increment();
    defer this.ref.decrement();

    const slot = this.getSlotUnsafe(task, task_hash) orelse return;
    const index = this.getIndexUnsafe(slot);

    const bitmask_bucket = &this.bitmask[@divFloor(index, @bitSizeOf(usize))];
    const operand = ~(@as(usize, 1) << @intCast(index % @bitSizeOf(usize)));
    _ = bitmask_bucket.fetchAnd(operand, .monotonic);

    _ = slot.key.fetchAnd(Key.empty_collided, .monotonic);
}

/// Tracks a thread forking.
/// Returns the delay amount those threads should sleep
pub fn fork(this: *ThreadClocks, parent: Key, child: Key) !Ticks {
    const parent_hash = parent.hash();
    const child_hash = child.hash();

    this.ref.increment();
    defer this.ref.decrement();

    const parent_slot = this.getSlotUnsafe(parent, parent_hash).?;
    const child_slot = try this.reserveSlotUnsafe(child, child_hash);

    const master = this.master.load(.acquire);
    const parent_ticks = parent_slot.value.load(.monotonic).ticks;

    parent_slot.value.store(.{ .ticks = master, .master_at_sleep = undefined }, .monotonic);
    child_slot.value.store(.{ .ticks = master, .master_at_sleep = undefined }, .monotonic);

    this.publishReservedUnsafe(child, child_slot);

    return master - parent_ticks;
}

pub fn grow(this: *ThreadClocks, allocator: std.mem.Allocator) !struct { []Pair, []std.atomic.Value(usize) } {
    this.ref.increment();
    const new_len = this.pairs.len * 2;
    this.ref.decrement();

    assert(@popCount(new_len) == 1);
    const new_pairs = try allocator.alloc(Pair, new_len);
    @memset(new_pairs, Pair.empty);

    const new_bitmask_len = @divExact(new_len, @bitSizeOf(usize));
    const new_bitmask = try allocator.alloc(std.atomic.Value(usize), new_bitmask_len);
    @memset(new_bitmask, .init(0));

    this.ref.close();
    defer this.ref.open();

    const old_pairs = this.pairs;
    const old_bitmask = this.bitmask;

    this.ref.drain();
    this.pairs = new_pairs;
    this.bitmask = new_bitmask;

    const bitmask = new_len - 1;
    const max_retries = @max(16, new_len / 32);
    for (old_pairs) |pair| {
        const key = pair.key.load(.unordered).withoutCollisionBit();
        if (!key.isEql(.empty)) {
            const value = pair.value.load(.unordered);
            const hash = key.hash();

            var i: usize = 0;
            while (i < max_retries) : (i += 1) {
                const index = (hash + i) & bitmask;

                if (new_pairs[index].key.load(.unordered).isEql(.empty)) {
                    new_pairs[index] = .{ .key = .init(key), .value = .init(value) };
                    new_bitmask[@divFloor(index, @bitSizeOf(usize))].raw |= @as(usize, 1) << @intCast(index % @bitSizeOf(usize));
                    break;
                }

                new_pairs[index].key.raw.data |= @bitCast(Key.empty_collided);
            } else return error.NoSpace;
        }
    }

    return .{ old_pairs, old_bitmask };
}

/// Removes every entry the predicate marks, with exclusive map access.
pub fn removeIf(this: *ThreadClocks, comptime pred: anytype, args: anytype) void {
    this.ref.close();
    defer this.ref.open();

    this.ref.drain();

    for (this.bitmask, 0..) |*bit_bucket, i| {
        var bucket = bit_bucket.raw;
        while (bucket != 0) : (bucket &= bucket - 1) {
            const bit_pos = @ctz(bucket);
            const index = i * @bitSizeOf(usize) + bit_pos;

            const pair = &this.pairs[index];

            assert(!pair.key.raw.isEql(.empty) and !pair.key.raw.isEql(.reserved));

            if (@call(.always_inline, pred, .{&pair.key.raw} ++ args)) {
                bit_bucket.raw &= ~(@as(usize, 1) << @intCast(bit_pos));
                pair.key.raw = if (pair.key.raw.hasCollided()) .empty_collided else .empty;
            }
        }
    }
}

pub fn forEach(this: *ThreadClocks, comptime cb: anytype, args: anytype) void {
    this.ref.close();
    defer this.ref.open();

    this.ref.drain();

    const master = this.master.load(.unordered);

    for (this.bitmask, 0..) |*bit_bucket, i| {
        var bucket = bit_bucket.load(.unordered);
        while (bucket != 0) : (bucket &= bucket - 1) {
            const bit_pos = @ctz(bucket);
            const index = i * @bitSizeOf(usize) + bit_pos;

            const pair = &this.pairs[index];

            const key = &pair.key.raw;
            const value = &pair.value.raw;

            assert(!key.isEql(.empty) and !key.isEql(.reserved));

            @call(.always_inline, cb, .{ master, key, value } ++ args);
        }
    }
}

const min_cap = @bitSizeOf(usize);

test "ThreadClocks: basic lifecycle" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const key1: ThreadClocks.Key = .{ .data = 100 };
    const key2: ThreadClocks.Key = .{ .data = 200 };

    try clocks.put(key1, 10);
    try clocks.put(key2, 20);

    try testing.expectEqual(10, clocks.get(key1, .ticks));
    try testing.expectEqual(20, clocks.get(key2, .ticks));
}

test "ThreadClocks: tick and master propagation" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const key: ThreadClocks.Key = .{ .data = 2 };
    try clocks.put(key, 5);

    try clocks.tick(key);
    try testing.expectEqual(6, clocks.get(key, .ticks));
    try testing.expectEqual(6, clocks.master.load(.monotonic));

    try clocks.tick(key);
    try testing.expectEqual(7, clocks.get(key, .ticks));
    try testing.expectEqual(7, clocks.master.load(.monotonic));
}

test "ThreadClocks: sleep and wake logic" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const waker: ThreadClocks.Key = .{ .data = 2 };
    const wakee: ThreadClocks.Key = .{ .data = 4 };

    try clocks.put(waker, 10);
    try clocks.put(wakee, 5);

    clocks.master.store(20, .release);

    clocks.prepareForSleep(wakee);
    // lag = master (20) - ticks (5) = 15
    try testing.expectEqual(15, clocks.get(wakee, .lag));

    const delays = clocks.wake(waker, wakee);

    // waker_lag = master(20) - waker_ticks(10) = 10
    // wakee_lag = waker_lag(10) + wakee_lag(15) = 25
    try testing.expectEqual(10, delays[0]);
    try testing.expectEqual(25, delays[1]);

    try testing.expectEqual(20, clocks.get(waker, .ticks));
    try testing.expectEqual(20, clocks.get(wakee, .ticks));
}

test "ThreadClocks: fork" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const parent: ThreadClocks.Key = .{ .data = 2 };
    const child: ThreadClocks.Key = .{ .data = 4 };

    try clocks.put(parent, 50);
    clocks.master.store(100, .release);

    const delay = try clocks.fork(parent, child);

    try testing.expectEqual(50, delay);
    try testing.expectEqual(100, clocks.get(parent, .ticks));
    try testing.expectEqual(100, clocks.get(child, .ticks));
}

test "ThreadClocks: collision path" {
    const allocator = testing.allocator;

    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    // Use enough entries that collisions are plausible (half capacity).
    var keys: [min_cap / 2]ThreadClocks.Key = undefined;
    var expected: [min_cap / 2]ThreadClocks.Ticks = undefined;
    for (&keys, &expected, 0..) |*key, *expected_elm, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        expected_elm.* = @intCast((i + 1) * 10);
    }

    for (keys, expected) |key, ticks| try clocks.put(key, ticks);
    for (keys, expected) |key, ticks| try testing.expectEqual(ticks, clocks.get(key, .ticks));
}

test "ThreadClocks: Causal Mechanics" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const parent: ThreadClocks.Key = .{ .data = 2 };
    const child: ThreadClocks.Key = .{ .data = 4 };

    try clocks.put(parent, 10);
    clocks.master.store(50, .release);

    const fork_delay = try clocks.fork(parent, child);
    try testing.expectEqual(40, fork_delay);

    clocks.master.store(100, .release);
    clocks.prepareForSleep(child);

    const d = clocks.wake(parent, child);
    try testing.expectEqual(50, d[0]);
    try testing.expectEqual(100, d[1]);
}

test "ThreadClocks: concurrent stress" {
    const allocator = testing.allocator;

    var clocks = try ThreadClocks.init(allocator, 128);
    defer clocks.deinit(allocator);

    const thread_count = 8;
    const ops_per_thread = 10_000;

    const Context = struct {
        clocks: *ThreadClocks,
        id: usize,
        registered: *std.atomic.Value(u32),

        fn run(ctx: *@This()) void {
            var prng = std.Random.DefaultPrng.init(ctx.id * 0xDEAD_BEEF);
            const random = prng.random();

            const key: ThreadClocks.Key = .{ .data = @intCast((ctx.id + 1) * 2) };

            _ = ctx.registered.fetchAdd(1, .release);
            while (ctx.registered.load(.acquire) < thread_count) std.atomic.spinLoopHint();

            for (0..ops_per_thread) |i|
                switch (random.uintLessThan(u8, 3)) {
                    1 => ctx.clocks.tick(key) catch {},
                    2 => {
                        const child_virtual_key: ThreadClocks.Key = .{ .data = @intCast((ctx.id * ops_per_thread + i) * 2 + 100) };
                        if (ctx.clocks.fork(key, child_virtual_key)) |_| {
                            for (0..3) |_| ctx.clocks.tick(child_virtual_key) catch break;
                        } else |_| continue;
                    },
                    else => {},
                };
        }
    };

    const root: ThreadClocks.Key = .{ .data = 2 };
    try clocks.put(root, 0);
    for (1..thread_count) |i| {
        const child: ThreadClocks.Key = .{ .data = @intCast((i + 1) * 2) };
        _ = try clocks.fork(root, child);
    }

    var registered = std.atomic.Value(u32).init(0);
    var contexts: [thread_count]Context = undefined;
    var threads: [thread_count]std.Thread = undefined;

    for (&contexts, &threads, 0..) |*context, *thread, i| {
        context.* = .{ .clocks = &clocks, .id = i, .registered = &registered };
        thread.* = try .spawn(.{}, Context.run, .{context});
    }
    for (threads) |t| t.join();

    const master = clocks.master.load(.acquire);

    for (0..thread_count) |i| {
        const key: ThreadClocks.Key = .{ .data = @intCast((i + 1) * 2) };
        try testing.expect(master >= clocks.get(key, .ticks));
    }

    for (clocks.pairs) |pair| {
        const key = pair.key.load(.acquire);
        if (key.isEql(.empty) or key.isEql(.reserved)) continue;
        const ticks = pair.value.load(.monotonic).ticks;
        try testing.expect(master >= ticks);
    }
}

test "ThreadClocks: concurrent grow" {
    const allocator = testing.allocator;

    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const root: ThreadClocks.Key = .{ .data = 2 };
    try clocks.put(root, 0);

    const thread_count = 4;

    const Context = struct {
        clocks: *ThreadClocks,
        id: usize,

        fn run(ctx: *@This()) void {
            const key: ThreadClocks.Key = .{ .data = @intCast((ctx.id + 2) * 2) };
            const root_key: ThreadClocks.Key = .{ .data = 2 };
            _ = ctx.clocks.fork(root_key, key) catch return;

            for (0..5_000) |_| ctx.clocks.tick(key) catch break;
        }
    };

    const GrowContext = struct {
        clocks: *ThreadClocks,
        alloc: std.mem.Allocator,

        fn run(ctx: *@This()) void {
            std.atomic.spinLoopHint();

            const old = ctx.clocks.grow(ctx.alloc) catch return;
            ctx.alloc.free(old[0]);
            ctx.alloc.free(old[1]);
        }
    };

    var worker_contexts: [thread_count]Context = undefined;
    var threads: [thread_count + 1]std.Thread = undefined;
    var grow_ctx = GrowContext{ .clocks = &clocks, .alloc = allocator };

    threads[thread_count] = try .spawn(.{}, GrowContext.run, .{&grow_ctx});
    for (&worker_contexts, threads[0 .. threads.len - 1], 0..) |*context, *thread, i| {
        context.* = .{ .clocks = &clocks, .id = i };
        thread.* = try .spawn(.{}, Context.run, .{context});
    }
    for (threads) |t| t.join();

    try testing.expect(clocks.pairs.len >= min_cap);

    const master = clocks.master.load(.acquire);
    for (0..thread_count) |i| {
        const key: ThreadClocks.Key = .{ .data = @intCast((i + 2) * 2) };
        try testing.expect(master >= clocks.get(key, .ticks));
    }
}

/// Count the total number of set bits across all bitmask words.
fn countLiveBits(clocks: *ThreadClocks) usize {
    var total: usize = 0;
    for (clocks.bitmask) |word| total += @popCount(word.load(.monotonic));
    return total;
}

/// Return true if the bit for the slot occupied by `key` is set.
fn bitIsSet(clocks: *ThreadClocks, key: ThreadClocks.Key) bool {
    const hash = key.hash();
    const len = clocks.pairs.len;
    const mask = len - 1;
    const max_retries = @max(16, len / 32);

    return for (0..max_retries) |i| {
        const index = (hash + i) & mask;
        const current_key = clocks.pairs[index].key.load(.acquire);
        if (current_key.isEql(key)) {
            const bucket = index / @bitSizeOf(usize);
            const bit = @as(usize, 1) << @truncate(index % @bitSizeOf(usize));
            break clocks.bitmask[bucket].load(.monotonic) & bit != 0;
        }
    } else false;
}

test "ThreadClocks: removeIf removes only matching entries" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [8]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, 0);
    }

    const odd_data = struct {
        fn pred(key: *ThreadClocks.Key) bool {
            return (key.withoutCollisionBit().data / 2) % 2 == 1;
        }
    }.pred;

    clocks.removeIf(odd_data, .{});

    try testing.expectEqual(keys.len / 2, countLiveBits(&clocks));
    for (keys, 0..) |key, i| {
        const expect_alive = (i + 1) % 2 == 0;
        try testing.expectEqual(expect_alive, bitIsSet(&clocks, key));
    }
}

test "ThreadClocks: externalWake charges full lag including sleep ticks" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const sleeper: ThreadClocks.Key = .{ .data = 2 };

    try clocks.put(sleeper, 5);
    clocks.master.store(10, .release);
    clocks.prepareForSleep(sleeper);

    clocks.master.store(30, .release);

    // pre-sleep debt (10 - 5) + sleep-time ticks (30 - 10)
    try testing.expectEqual(25, clocks.externalWake(sleeper));
    try testing.expectEqual(30, clocks.get(sleeper, .ticks));
    try testing.expectEqual(0, clocks.externalWake(sleeper));
}

test "ThreadClocks: remove tolerates untracked keys" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const tracked: ThreadClocks.Key = .{ .data = 2 };
    const untracked: ThreadClocks.Key = .{ .data = 4 };

    try clocks.put(tracked, 10);

    clocks.remove(untracked);
    try testing.expectEqual(1, countLiveBits(&clocks));

    clocks.remove(tracked);
    try testing.expectEqual(0, countLiveBits(&clocks));
}

test "bitmask: put sets bit, remove clears it" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    try testing.expectEqual(0, countLiveBits(&clocks));

    const key: ThreadClocks.Key = .{ .data = 42 };
    try clocks.put(key, 0);

    try testing.expect(bitIsSet(&clocks, key));
    try testing.expectEqual(1, countLiveBits(&clocks));

    _ = clocks.remove(key);

    try testing.expect(!bitIsSet(&clocks, key));
    try testing.expectEqual(0, countLiveBits(&clocks));
}

test "bitmask: popcount tracks live entry count across multiple puts and removes" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [16]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, 0);
        try testing.expectEqual(i + 1, countLiveBits(&clocks));
    }

    var live = keys.len;
    for (&keys, 0..) |*key, i| {
        if (i % 2 == 1) continue;
        _ = clocks.remove(key.*);
        live -= 1;
        try testing.expectEqual(live, countLiveBits(&clocks));
    }
}

test "bitmask: fork sets child bit without clearing parent bit" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const parent: ThreadClocks.Key = .{ .data = 2 };
    const child: ThreadClocks.Key = .{ .data = 4 };

    try clocks.put(parent, 10);
    clocks.master.store(10, .release); // master must be >= ticks to avoid underflow in fork
    try testing.expectEqual(1, countLiveBits(&clocks));

    _ = try clocks.fork(parent, child);

    try testing.expect(bitIsSet(&clocks, parent));
    try testing.expect(bitIsSet(&clocks, child));
    try testing.expectEqual(2, countLiveBits(&clocks));
}

test "bitmask: grow migrates all live bits and clears none" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [8]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, @intCast(i * 10));
    }

    try testing.expectEqual(keys.len, countLiveBits(&clocks));

    const old = try clocks.grow(allocator);
    allocator.free(old[0]);
    allocator.free(old[1]);

    for (keys) |key| try testing.expect(bitIsSet(&clocks, key));

    try testing.expectEqual(keys.len, countLiveBits(&clocks));
}

test "bitmask: grow with partial removes — only live entries retain their bit" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [12]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, 0);
    }

    for (&keys, 0..) |key, i| _ = if (i % 2 == 0) clocks.remove(key);

    try testing.expectEqual(keys.len / 2, countLiveBits(&clocks));

    const old = try clocks.grow(allocator);
    allocator.free(old[0]);
    allocator.free(old[1]);

    try testing.expectEqual(keys.len / 2, countLiveBits(&clocks));

    for (&keys, 0..) |key, i|
        if (i % 2 == 0)
            try testing.expect(!bitIsSet(&clocks, key))
        else
            try testing.expect(bitIsSet(&clocks, key));
}

test "ThreadClocks: forEach visits all live entries exactly once" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [8]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, @intCast(i * 10));
    }

    clocks.master.store(30, .release);
    _ = clocks.remove(keys[3]);

    var count: usize = 0;
    var ticks_sum: u32 = 0;

    const cb = struct {
        fn cb(_: ThreadClocks.Ticks, _: *ThreadClocks.Key, value: *ThreadClocks.Value, c: *usize, sum: *u32) void {
            c.* += 1;
            sum.* += value.ticks;
        }
    }.cb;

    clocks.forEach(cb, .{ &count, &ticks_sum });

    try testing.expectEqual(keys.len - 1, count);
    try testing.expectEqual(250, ticks_sum);
}
