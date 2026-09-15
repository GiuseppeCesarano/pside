const std = @import("std");
const isPowerOfTwo = std.math.isPowerOfTwo;
const assert = std.debug.assert;
const testing = std.testing;

const BitSearch = @import("BitSearch");
const min_cap = BitSearch.bits_per_word;
const RefGate = @import("RefGate");
const safety = @import("safety");

/// Concurrent map optimized for thread-local clock propagation.
const ThreadClocks = @This();

pub const Ticks = u32;

pub const Key = packed struct(usize) {
    data: usize,

    // Task pointers are always aligned so the first bit will always be 0
    // and we can use that as collide flag
    const collided_bit: usize = 1;

    pub const empty: Key = .{ .data = 0 };
    pub const empty_collided: Key = .{ .data = collided_bit };

    pub const reserved: Key = .{ .data = std.math.maxInt(usize) & ~collided_bit };

    pub fn isEql(this: Key, other: Key) bool {
        return (this.data | collided_bit) == (other.data | collided_bit);
    }

    pub fn hasCollided(this: Key) bool {
        return (this.data & collided_bit) != 0;
    }

    pub fn hash(this: Key) usize {
        return std.hash.int(this.data);
    }

    pub fn withCollisionBit(this: Key) Key {
        return .{ .data = this.data | collided_bit };
    }

    pub fn withoutCollisionBit(this: Key) Key {
        return .{ .data = this.data & ~collided_bit };
    }
};

pub const Value = packed struct(u64) {
    ticks: Ticks,
    master_at_sleep: Ticks,

    const ticks_lsb: u64 = @bitCast(Value{ .ticks = 1, .master_at_sleep = 0 });

    pub fn atValue(ticks: Ticks) Value {
        return .{ .ticks = ticks, .master_at_sleep = ticks };
    }
};

pub const Pair = struct {
    key: std.atomic.Value(Key),
    value: std.atomic.Value(Value),

    const empty: Pair = .{ .key = .init(.empty), .value = undefined };
};

master: std.atomic.Value(Ticks) align(std.atomic.cache_line),
ref: RefGate,
pairs: []Pair,
used: BitSearch,
reservations: safety.AtomicCounter,

pub fn init(allocator: std.mem.Allocator, reserve: usize) !ThreadClocks {
    assert(isPowerOfTwo(reserve));
    assert(reserve >= min_cap);

    const pairs = try allocator.alloc(Pair, reserve);
    errdefer allocator.free(pairs);
    @memset(pairs, Pair.empty);

    return .{
        .master = .init(0),
        .ref = .{},
        .pairs = pairs,
        .used = try .init(allocator, reserve),
        .reservations = .zero,
    };
}

pub fn deinit(this: *ThreadClocks, allocator: std.mem.Allocator) void {
    this.ref.close();
    this.ref.drain();
    this.reservations.assertZero();

    allocator.free(this.pairs);
    this.used.deinit(allocator);

    this.* = undefined;
}

fn reserveSlotUnsafe(this: *ThreadClocks, key: Key, hash: usize) !*Pair {
    const len = this.pairs.len;

    // bit 0 is reserved for the collision flag; callers must pass it clear.
    assert(!key.hasCollided());
    assert(isPowerOfTwo(len));
    const index_mask = len - 1;
    const max_retries = @max(16, len / 32);

    var i: usize = 0;
    while (i < max_retries) : (i += 1) {
        const index = (hash + i) & index_mask;
        const current_key = this.pairs[index].key.load(.monotonic);

        // Double insertion of the same key would mean broken logic
        assert(!current_key.isEql(key));

        // or will preserve the collided bit.
        const reservation: Key = .{ .data = Key.reserved.data | current_key.data };

        if (current_key.isEql(.empty) and
            this.pairs[index].key.cmpxchgStrong(current_key, reservation, .acquire, .monotonic) == null)
        {
            this.reservations.increment();
            return &this.pairs[index];
        }

        if (!current_key.hasCollided())
            _ = this.pairs[index].key.fetchOr(Key.empty_collided, .monotonic);
    }

    return error.NoSpace;
}

fn publishReservedUnsafe(this: *ThreadClocks, key: Key, ptr: *Pair) void {
    assert(ptr.key.load(.unordered).isEql(.reserved));

    this.used.take(this.getIndexUnsafe(ptr));

    _ = ptr.key.fetchAnd(key.withCollisionBit(), .release);

    this.reservations.decrement();
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
fn getSlotUnsafe(this: *const ThreadClocks, key: Key, hash: usize) ?*Pair {
    const len = this.pairs.len;

    assert(isPowerOfTwo(len));
    const index_mask = len - 1;

    var i: usize = 0;
    var current_key: Key = .empty_collided;
    return slot: while (current_key.hasCollided() and i < len) : (i += 1) {
        const index = (hash + i) & index_mask;
        current_key = this.pairs[index].key.load(.acquire);
        if (current_key.isEql(key)) break :slot &this.pairs[index];
    } else null;
}

fn getIndexUnsafe(this: *const ThreadClocks, elm: *const Pair) usize {
    const elm_addr: usize = @intFromPtr(elm);
    const starting_addr: usize = @intFromPtr(this.pairs.ptr);
    return @divExact(elm_addr - starting_addr, @sizeOf(Pair));
}

pub fn put(this: *ThreadClocks, key: Key, ticks: Ticks) !void {
    this.ref.increment();
    defer this.ref.decrement();

    const slot = try this.reserveSlotUnsafe(key, key.hash());

    slot.value.store(.atValue(ticks), .monotonic);

    this.publishReservedUnsafe(key, slot);
}

fn valueOf(this: *ThreadClocks, key: Key) Value {
    this.ref.increment();
    defer this.ref.decrement();

    return this.getSlotUnsafe(key, key.hash()).?.value.load(.monotonic);
}

pub fn ticksOf(this: *ThreadClocks, key: Key) Ticks {
    return this.valueOf(key).ticks;
}

pub fn lagOf(this: *ThreadClocks, key: Key) Ticks {
    const value = this.valueOf(key);

    return value.master_at_sleep -| value.ticks;
}

pub fn tick(this: *ThreadClocks, key: Key) !void {
    try this.ref.tryIncrement();
    defer this.ref.decrement();

    const slot = this.getSlotUnsafe(key, key.hash()).?;
    const value_as_ticks: *std.atomic.Value(u64) = @ptrCast(&slot.value);

    const value: Value = @bitCast(value_as_ticks.fetchAdd(Value.ticks_lsb, .monotonic));
    const ticks = value.ticks + 1; // Account for the just done + 1

    if (this.master.load(.monotonic) < ticks)
        _ = this.master.fetchMax(ticks, .monotonic);
}

pub fn prepareForSleep(this: *ThreadClocks, key: Key) void {
    this.ref.increment();
    defer this.ref.decrement();

    const slot = this.getSlotUnsafe(key, key.hash()).?;
    const master = this.master.load(.monotonic);
    const ticks = slot.value.load(.monotonic).ticks;

    slot.value.store(.{ .ticks = ticks, .master_at_sleep = master }, .monotonic);
}

/// Wakes a sleeping thread, the sleeping thread must have calld prepareForSleep.
/// Returns the delay amounts those threads should sleep, null when the map is gated:
/// callers run in irq context and cannot spin on a gate this cpu may itself hold.
pub fn wake(this: *ThreadClocks, waker: Key, wakee: Key) ?[2]Ticks {
    this.ref.tryIncrement() catch return null;
    defer this.ref.decrement();

    const wakee_slot = this.getSlotUnsafe(wakee, wakee.hash()).?;
    const wakee_value = wakee_slot.value.load(.monotonic);

    const master = this.master.load(.monotonic);

    const waker_slot = this.getSlotUnsafe(waker, waker.hash());
    const waker_ticks = if (waker_slot) |slot| slot.value.load(.monotonic).ticks else master;

    const wakee_lag = wakee_value.master_at_sleep -| wakee_value.ticks;
    const wakee_credit = wakee_value.ticks -| wakee_value.master_at_sleep;

    wakee_slot.value.store(.atValue(master), .monotonic);
    if (waker_slot) |slot| slot.value.store(.atValue(master), .monotonic);

    const waker_lag = master -| waker_ticks;
    return .{ waker_lag, waker_lag + wakee_lag -| wakee_credit };
}

/// Settles a thread's clock against the master and returns the lag it must
/// repay itself. Null when the thread is not tracked or the map is gated.
pub fn catchUp(this: *ThreadClocks, key: Key) ?Ticks {
    this.ref.tryIncrement() catch return null;
    defer this.ref.decrement();

    const slot = this.getSlotUnsafe(key, key.hash()) orelse return null;

    const master = this.master.load(.monotonic);
    const old = slot.value.swap(.atValue(master), .monotonic);

    return master -| old.ticks;
}

pub fn removePairUnsafe(this: *ThreadClocks, slot: *Pair) void {
    this.used.release(this.getIndexUnsafe(slot));
    _ = slot.key.fetchAnd(Key.empty_collided, .release);
}

pub fn remove(this: *ThreadClocks, key: Key) bool {
    this.ref.increment();
    defer this.ref.decrement();

    const slot = this.getSlotUnsafe(key, key.hash()) orelse return false;
    this.removePairUnsafe(slot);

    return true;
}

/// Tracks a thread forking.
/// Returns the delay amount those threads should sleep
pub fn fork(this: *ThreadClocks, parent: Key, child: Key) !Ticks {
    this.ref.increment();
    defer this.ref.decrement();

    const parent_slot = this.getSlotUnsafe(parent, parent.hash()).?;
    const child_slot = try this.reserveSlotUnsafe(child, child.hash());

    const master = this.master.load(.monotonic);
    const parent_ticks = parent_slot.value.load(.monotonic).ticks;

    parent_slot.value.store(.atValue(master), .monotonic);
    child_slot.value.store(.atValue(master), .monotonic);

    this.publishReservedUnsafe(child, child_slot);

    return master -| parent_ticks;
}

pub const Iterator = struct {
    clocks: *ThreadClocks,
    closed: bool,
    used_it: BitSearch.Iterator,

    pub fn next(this: *Iterator) ?*Pair {
        if (this.used_it.next()) |index|
            return &this.clocks.pairs[index];

        this.finish();
        return null;
    }

    pub fn finish(this: *Iterator) void {
        if (this.closed) {
            this.clocks.ref.open();
            this.closed = false;
        }
    }
};

pub fn iterate(this: *ThreadClocks) Iterator {
    this.ref.close();
    this.ref.drain();

    return .{
        .clocks = this,
        .closed = true,
        .used_it = this.used.iterate(),
    };
}

pub fn grow(this: *ThreadClocks, allocator: std.mem.Allocator) !void {
    this.ref.increment();
    const old_len = this.pairs.len;
    this.ref.decrement();

    const new_len = old_len * 2;
    assert(isPowerOfTwo(new_len));
    const new_pairs = try allocator.alloc(Pair, new_len);
    errdefer allocator.free(new_pairs);
    @memset(new_pairs, Pair.empty);

    var new_used: BitSearch = try .init(allocator, new_len);

    this.ref.close();
    this.ref.drain();
    this.reservations.assertZero();

    if (this.pairs.len != old_len) {
        this.ref.open();
        allocator.free(new_pairs);
        new_used.deinit(allocator);
        return;
    }

    const index_mask = new_len - 1;
    var it = this.used.iterate();
    while (it.next()) |slot| {
        const pair = &this.pairs[slot];
        const key = pair.key.raw.withoutCollisionBit();
        const value = pair.value.raw;
        const hash = key.hash();

        for (0..new_len) |i| {
            const index = (hash + i) & index_mask;

            if (new_pairs[index].key.raw.isEql(.empty)) {
                new_pairs[index] = .{ .key = .init(key), .value = .init(value) };
                new_used.takeUnordered(index);
                break;
            }

            new_pairs[index].key.raw.data |= Key.collided_bit;
        } else unreachable;
    }

    const old_pairs = this.pairs;
    const old_used = this.used;

    this.pairs = new_pairs;
    this.used = new_used;

    this.ref.open();

    allocator.free(old_pairs);
    old_used.deinit(allocator);
}

fn isTaken(this: *const ThreadClocks, key: Key) bool {
    const slot = this.getSlotUnsafe(key, key.hash()) orelse return false;

    return this.used.isTaken(this.getIndexUnsafe(slot));
}

test "ThreadClocks: basic lifecycle" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const key1: ThreadClocks.Key = .{ .data = 100 };
    const key2: ThreadClocks.Key = .{ .data = 200 };

    try clocks.put(key1, 10);
    try clocks.put(key2, 20);

    try testing.expectEqual(10, clocks.ticksOf(key1));
    try testing.expectEqual(20, clocks.ticksOf(key2));
}

test "ThreadClocks: tick and master propagation" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const key: ThreadClocks.Key = .{ .data = 2 };
    try clocks.put(key, 5);

    try clocks.tick(key);
    try testing.expectEqual(6, clocks.ticksOf(key));
    try testing.expectEqual(6, clocks.master.load(.monotonic));

    try clocks.tick(key);
    try testing.expectEqual(7, clocks.ticksOf(key));
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
    try testing.expectEqual(15, clocks.lagOf(wakee));

    const delays = clocks.wake(waker, wakee).?;

    // waker_lag = master(20) - waker_ticks(10) = 10
    // wakee_lag = waker_lag(10) + wakee_lag(15) = 25
    try testing.expectEqual(10, delays[0]);
    try testing.expectEqual(25, delays[1]);

    try testing.expectEqual(20, clocks.ticksOf(waker));
    try testing.expectEqual(20, clocks.ticksOf(wakee));
}

test "ThreadClocks: wake without prepareForSleep yields zero wakee lag" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const waker: ThreadClocks.Key = .{ .data = 2 };
    const wakee: ThreadClocks.Key = .{ .data = 4 };

    try clocks.put(waker, 10);
    try clocks.put(wakee, 5);
    clocks.master.store(20, .release);

    const first = clocks.wake(waker, wakee).?;
    try testing.expectEqual(10, first[0]);
    try testing.expectEqual(10, first[1]);

    const second = clocks.wake(waker, wakee).?;
    try testing.expectEqual(0, second[0]);
    try testing.expectEqual(0, second[1]);

    try testing.expectEqual(0, clocks.catchUp(wakee));
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
    try testing.expectEqual(100, clocks.ticksOf(parent));
    try testing.expectEqual(100, clocks.ticksOf(child));
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
    for (keys, expected) |key, ticks| try testing.expectEqual(ticks, clocks.ticksOf(key));
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

    const d = clocks.wake(parent, child).?;
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
        try testing.expect(master >= clocks.ticksOf(key));
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

            ctx.clocks.grow(ctx.alloc) catch return;
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
        try testing.expect(master >= clocks.ticksOf(key));
    }
}

test "ThreadClocks: catchUp charges full lag including sleep ticks" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const sleeper: ThreadClocks.Key = .{ .data = 2 };

    try clocks.put(sleeper, 5);
    clocks.master.store(10, .release);
    clocks.prepareForSleep(sleeper);

    clocks.master.store(30, .release);

    // pre-sleep debt (10 - 5) + sleep-time ticks (30 - 10)
    try testing.expectEqual(25, clocks.catchUp(sleeper));
    try testing.expectEqual(30, clocks.ticksOf(sleeper));
    try testing.expectEqual(0, clocks.catchUp(sleeper));
}

test "ThreadClocks: a closed gate yields nothing owed instead of blocking" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const waker: ThreadClocks.Key = .{ .data = 2 };
    const wakee: ThreadClocks.Key = .{ .data = 4 };

    try clocks.put(waker, 10);
    try clocks.put(wakee, 5);
    clocks.master.store(20, .release);

    clocks.ref.close();
    clocks.ref.drain();

    try testing.expectEqual(null, clocks.wake(waker, wakee));
    try testing.expectEqual(null, clocks.catchUp(wakee));

    clocks.ref.open();

    try testing.expectEqual(10, clocks.catchUp(waker));
}

test "ThreadClocks: remove tolerates untracked keys" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const tracked: ThreadClocks.Key = .{ .data = 2 };
    const untracked: ThreadClocks.Key = .{ .data = 4 };

    try clocks.put(tracked, 10);

    try testing.expectEqual(false, clocks.remove(untracked));
    try testing.expectEqual(1, clocks.used.countTaken());

    try testing.expectEqual(true, clocks.remove(tracked));
    try testing.expectEqual(0, clocks.used.countTaken());
}

test "ThreadClocks: put takes the slot, remove releases it" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    try testing.expectEqual(0, clocks.used.countTaken());

    const key: ThreadClocks.Key = .{ .data = 42 };
    try clocks.put(key, 0);

    try testing.expect(clocks.isTaken(key));
    try testing.expectEqual(1, clocks.used.countTaken());

    _ = clocks.remove(key);

    try testing.expect(!clocks.isTaken(key));
    try testing.expectEqual(0, clocks.used.countTaken());
}

test "ThreadClocks: taken count tracks live entries across puts and removes" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [16]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, 0);
        try testing.expectEqual(i + 1, clocks.used.countTaken());
    }

    var live = keys.len;
    for (&keys, 0..) |*key, i| {
        if (i % 2 == 1) continue;
        _ = clocks.remove(key.*);
        live -= 1;
        try testing.expectEqual(live, clocks.used.countTaken());
    }
}

test "ThreadClocks: fork takes the child slot without releasing the parent" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const parent: ThreadClocks.Key = .{ .data = 2 };
    const child: ThreadClocks.Key = .{ .data = 4 };

    try clocks.put(parent, 10);
    clocks.master.store(10, .release); // master must be >= ticks to avoid underflow in fork
    try testing.expectEqual(1, clocks.used.countTaken());

    _ = try clocks.fork(parent, child);

    try testing.expect(clocks.isTaken(parent));
    try testing.expect(clocks.isTaken(child));
    try testing.expectEqual(2, clocks.used.countTaken());
}

test "ThreadClocks: grow migrates every taken slot and releases none" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [8]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, @intCast(i * 10));
    }

    try testing.expectEqual(keys.len, clocks.used.countTaken());

    try clocks.grow(allocator);

    for (keys) |key| try testing.expect(clocks.isTaken(key));

    try testing.expectEqual(keys.len, clocks.used.countTaken());
}

test "ThreadClocks: grow with partial removes, only live entries stay taken" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [12]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, 0);
    }

    for (&keys, 0..) |key, i| _ = if (i % 2 == 0) clocks.remove(key);

    try testing.expectEqual(keys.len / 2, clocks.used.countTaken());

    try clocks.grow(allocator);

    try testing.expectEqual(keys.len / 2, clocks.used.countTaken());

    for (&keys, 0..) |key, i|
        if (i % 2 == 0)
            try testing.expect(!clocks.isTaken(key))
        else
            try testing.expect(clocks.isTaken(key));
}

test "ThreadClocks: grow preserves ticks and pending lag" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [8]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, @intCast(i * 10));
    }

    clocks.master.store(100, .release);
    for (keys, 0..) |key, i| if (i % 2 == 0) clocks.prepareForSleep(key);

    try clocks.grow(allocator);

    for (keys, 0..) |key, i| {
        const expected_lag: ThreadClocks.Ticks = if (i % 2 == 0) @intCast(100 - i * 10) else 0;
        try testing.expectEqual(i * 10, clocks.ticksOf(key));
        try testing.expectEqual(expected_lag, clocks.lagOf(key));
    }
}

test "ThreadClocks: repeated grow keeps every entry reachable" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [min_cap / 2]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, @intCast(i));
    }

    for (0..2) |_| {
        try clocks.grow(allocator);
    }

    try testing.expectEqual(min_cap * 4, clocks.pairs.len);
    try testing.expectEqual(keys.len, clocks.used.countTaken());
    for (keys, 0..) |key, i| try testing.expectEqual(i, clocks.ticksOf(key));
}

test "ThreadClocks: slot reuse after remove" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const key: ThreadClocks.Key = .{ .data = 42 };

    try clocks.put(key, 7);
    _ = clocks.remove(key);
    try clocks.put(key, 9);

    try testing.expectEqual(9, clocks.ticksOf(key));
    try testing.expectEqual(1, clocks.used.countTaken());
}

test "ThreadClocks: racing growers keep every entry" {
    const allocator = testing.allocator;

    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [min_cap / 2]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, @intCast(i));
    }

    const grower_count = 4;

    const GrowContext = struct {
        clocks: *ThreadClocks,
        alloc: std.mem.Allocator,
        ready: *std.atomic.Value(u32),

        fn run(ctx: *@This()) void {
            _ = ctx.ready.fetchAdd(1, .release);
            while (ctx.ready.load(.acquire) < grower_count) std.atomic.spinLoopHint();

            ctx.clocks.grow(ctx.alloc) catch return;
        }
    };

    var ready: std.atomic.Value(u32) = .init(0);
    var contexts: [grower_count]GrowContext = undefined;
    var threads: [grower_count]std.Thread = undefined;

    for (&contexts, &threads) |*context, *thread| {
        context.* = .{ .clocks = &clocks, .alloc = allocator, .ready = &ready };
        thread.* = try .spawn(.{}, GrowContext.run, .{context});
    }
    for (threads) |t| t.join();

    try testing.expectEqual(keys.len, clocks.used.countTaken());
    for (keys, 0..) |key, i| try testing.expectEqual(i, clocks.ticksOf(key));
}

test "ThreadClocks: the taken bits of a grown map point at live entries" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    var keys: [20]ThreadClocks.Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try clocks.put(key.*, 0);
    }

    for (&keys, 0..) |key, i| _ = if (i % 2 == 0) clocks.remove(key);

    try clocks.grow(allocator);

    var live: usize = 0;
    var it = clocks.used.iterate();
    while (it.next()) |index| : (live += 1) {
        const key = clocks.pairs[index].key.raw.withoutCollisionBit();

        try testing.expect(!key.isEql(.empty));
        try testing.expect(!key.isEql(.reserved));
        try testing.expect(clocks.isTaken(key));
    }

    try testing.expectEqual(keys.len / 2, live);
}
