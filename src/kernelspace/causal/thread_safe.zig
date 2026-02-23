const std = @import("std");
const assert = std.debug.assert;

const RefGate = struct {
    const lock_bit = @as(usize, 1) << (@bitSizeOf(usize) - 1);
    const references_mask = ~lock_bit;

    reference: std.atomic.Value(usize) align(std.atomic.cache_line) = .init(0),

    pub inline fn increment(this: *@This()) void {
        var ref = this.reference.fetchAdd(1, .acquire);
        assert((ref & references_mask) != references_mask);

        while (ref & lock_bit != 0) {
            @branchHint(.cold);

            _ = this.reference.fetchSub(1, .monotonic);

            while (this.reference.load(.monotonic) & lock_bit != 0) std.atomic.spinLoopHint();

            ref = this.reference.fetchAdd(1, .acquire);
            assert((ref & references_mask) != references_mask);
        }
    }

    pub inline fn tryIncrement(this: *@This()) !void {
        const ref = this.reference.fetchAdd(1, .acquire);
        assert((ref & references_mask) != references_mask);
        if (ref & lock_bit != 0) {
            _ = this.reference.fetchSub(1, .monotonic);
            return error.WouldBlock;
        }
    }

    pub inline fn decrement(this: *@This()) void {
        assert(this.reference.fetchSub(1, .release) & references_mask != 0);
    }

    pub inline fn close(this: *@This()) void {
        while (this.reference.fetchOr(lock_bit, .acquire) & lock_bit != 0) {
            @branchHint(.cold);
            while (this.reference.load(.monotonic) & lock_bit != 0) std.atomic.spinLoopHint();
        }
    }

    pub inline fn drain(this: *@This()) void {
        while ((this.reference.load(.acquire) & references_mask) != 0)
            std.atomic.spinLoopHint();
    }

    pub inline fn open(this: *@This()) void {
        assert(this.reference.fetchAnd(references_mask, .release) & lock_bit != 0);
    }
};

/// Concurrent map optimized for thread-local clock propagation.
pub const ThreadClocks = struct {
    pub const Ticks = u32;

    pub const Key = packed struct(usize) {
        data: usize,

        const bit_size = @bitSizeOf(@This());
        const Unsigned = std.meta.Int(.unsigned, bit_size);
        const collided_bit: Unsigned = @bitCast(@as(Unsigned, 1 << bit_size - 1));

        pub const empty: @This() = .{ .data = 0 };
        pub const empty_collided: @This() = @bitCast(collided_bit);
        pub const reserved: @This() = @bitCast(std.math.maxInt(Unsigned) & ~collided_bit);

        pub fn isEql(this: Key, other: Key) bool {
            const this_bits: Unsigned = @bitCast(this);
            const other_bits: Unsigned = @bitCast(other);
            return (this_bits | collided_bit) == (other_bits | collided_bit);
        }

        pub fn hasCollided(this: Key) bool {
            const this_bits: Unsigned = @bitCast(this);
            return (this_bits & collided_bit) != 0;
        }

        pub fn fromPtr(ptr: *anyopaque) @This() {
            return .{ .data = @intFromPtr(ptr) };
        }

        pub fn hash(this: @This()) usize {
            const unsigned: Unsigned = @bitCast(this.data);
            return std.hash.int(unsigned);
        }

        pub fn withCollisionBit(this: @This()) @This() {
            const bits: Unsigned = @bitCast(this);
            return @bitCast(bits | collided_bit);
        }

        pub fn withoutCollisionBit(this: @This()) @This() {
            const bits: Unsigned = @bitCast(this);
            return @bitCast(bits & ~collided_bit);
        }
    };

    pub const Value = packed struct(Ticks) {
        data: packed union {
            ticks: Ticks,
            lag: Ticks,
        },
    };

    const Pair = struct {
        key: std.atomic.Value(Key),
        value: std.atomic.Value(Value),

        const empty: @This() = .{ .key = .init(.empty), .value = undefined };
    };

    master: std.atomic.Value(Ticks) align(std.atomic.cache_line),
    ref: RefGate,
    pairs: []Pair,
    bitmask: []std.atomic.Value(usize),

    pub fn init(allocator: std.mem.Allocator, reserve: usize) !@This() {
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

    pub fn deinit(this: *@This(), allocator: std.mem.Allocator) void {
        this.ref.close();
        this.ref.drain();
        allocator.free(this.pairs);
        allocator.free(this.bitmask);
    }

    fn reserveSlotUnsafe(this: *@This(), key: Key, hash: usize) !*Pair {
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

            if (current_key.isEql(.empty) and
                this.pairs[index].key.cmpxchgStrong(current_key, .reserved, .acquire, .monotonic) == null)
                return &this.pairs[index];

            if (!current_key.hasCollided())
                _ = this.pairs[index].key.fetchOr(Key.empty_collided, .monotonic);
        }

        return error.NoSpace;
    }

    fn getSlotUnsafe(this: *@This(), key: Key, hash: usize) *Pair {
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
        } else unreachable;
        // Somehow we required a key that has no entry.
        // This would be faulty logic in the algorithm implementation
        // so we use unreachable to catch that in the tests.
    }

    fn getIndexUnsafe(this: @This(), elm: *Pair) usize {
        const elm_addr: usize = @intFromPtr(elm);
        const starting_addr: usize = @intFromPtr(this.pairs.ptr);
        return @divExact(elm_addr - starting_addr, @sizeOf(Pair));
    }

    fn getPtrFromIndexUnsafe(this: @This(), index: usize) *Pair {
        const starting_addr: usize = @intFromPtr(this.pairs.ptr);
        return @ptrFromInt(starting_addr + index);
    }

    fn publishReservedUnsafe(this: *@This(), key: Key, ptr: *Pair) void {
        assert(ptr.key.load(.unordered).isEql(.reserved));

        const index = this.getIndexUnsafe(ptr);

        const bit_bucket = &this.bitmask[@divFloor(index, @bitSizeOf(usize))];
        const operand = @as(usize, 1) << @truncate(index % @bitSizeOf(usize));
        _ = bit_bucket.fetchOr(operand, .monotonic);

        _ = ptr.key.fetchAnd(key.withCollisionBit(), .release);
    }

    pub fn put(this: *@This(), key: Key, ticks: Ticks) !void {
        const hash = key.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const slot = try this.reserveSlotUnsafe(key, hash);

        slot.value.store(.{ .data = .{ .ticks = ticks } }, .monotonic);

        this.publishReservedUnsafe(key, slot);
    }

    pub fn get(this: *@This(), key: Key, field: enum { ticks, lag }) u32 {
        const hash = key.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const slot = this.getSlotUnsafe(key, hash);
        const value = slot.value.load(.monotonic);

        return if (field == .ticks) value.data.ticks else value.data.lag;
    }

    pub fn tick(this: *@This(), key: Key) !void {
        const hash = key.hash();

        try this.ref.tryIncrement();
        defer this.ref.decrement();

        const slot = this.getSlotUnsafe(key, hash);
        const value_as_ticks: *std.atomic.Value(Ticks) = @ptrCast(&slot.value);
        const ticks = value_as_ticks.fetchAdd(1, .monotonic) + 1;

        _ = this.master.fetchMax(ticks, .release);
    }

    pub fn prepareForSleep(this: *@This(), key: Key) void {
        this.ref.increment();
        defer this.ref.decrement();

        const slot = this.getSlotUnsafe(key, key.hash());
        const ticks = slot.value.load(.monotonic).data.ticks;
        const master = this.master.load(.acquire);

        slot.value.store(.{ .data = .{ .lag = master - ticks } }, .monotonic);
    }

    /// Wakes a sleeping thread, the sleeping thread must have calld prepareForSleep.
    /// Returns the delay amounts those threads should sleep
    pub fn wake(this: *@This(), waker: Key, wakee: Key) struct { waker: Ticks, wakee: Ticks } {
        const waker_hash = waker.hash();
        const wakee_hash = wakee.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const waker_slot = this.getSlotUnsafe(waker, waker_hash);
        const wakee_slot = this.getSlotUnsafe(wakee, wakee_hash);

        const waker_ticks = waker_slot.value.load(.monotonic).data.ticks;
        const wakee_lag = wakee_slot.value.load(.monotonic).data.lag;
        const master = this.master.load(.acquire);

        waker_slot.value.store(.{ .data = .{ .ticks = master } }, .monotonic);
        wakee_slot.value.store(.{ .data = .{ .ticks = master } }, .monotonic);

        const waker_lag = master - waker_ticks;

        return .{ .waker = waker_lag, .wakee = waker_lag + wakee_lag };
    }

    /// Tracks a thread forking.
    /// Returns the delay ammount those threads should sleep
    pub fn fork(this: *@This(), parent: Key, child: Key) !Ticks {
        const parent_hash = parent.hash();
        const child_hash = child.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const parent_slot = this.getSlotUnsafe(parent, parent_hash);
        const child_slot = try this.reserveSlotUnsafe(child, child_hash);

        const parent_ticks = parent_slot.value.load(.monotonic).data.ticks;
        const master = this.master.load(.acquire);

        parent_slot.value.store(.{ .data = .{ .ticks = master } }, .monotonic);
        child_slot.value.store(.{ .data = .{ .ticks = master } }, .monotonic);

        this.publishReservedUnsafe(child, child_slot);

        return master - parent_ticks;
    }

    /// Returns the delay ammount that the thread should sleep
    pub fn remove(this: *@This(), key: Key) Ticks {
        const key_hash = key.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const slot = this.getSlotUnsafe(key, key_hash);
        const ticks = slot.value.load(.monotonic).data.ticks;
        const master = this.master.load(.acquire);

        const index = this.getIndexUnsafe(slot);
        const bitmask_bucket = &this.bitmask[@divFloor(index, @bitSizeOf(usize))];
        const operand = ~(@as(usize, 1) << @truncate(index % @bitSizeOf(usize)));
        _ = bitmask_bucket.fetchAnd(operand, .monotonic);

        _ = slot.key.fetchAnd(Key.empty_collided, .monotonic);

        return master - ticks;
    }

    pub fn grow(this: *@This(), allocator: std.mem.Allocator) !struct { []Pair, []std.atomic.Value(usize) } {
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
                        new_bitmask[@divFloor(index, @bitSizeOf(usize))].raw |= @as(usize, 1) << @truncate(index % @bitSizeOf(usize));
                        break;
                    }
                    new_pairs[index].key.raw.data |= @bitCast(Key.empty_collided);
                } else return error.NoSpace;
            }
        }

        return .{ old_pairs, old_bitmask };
    }

    pub fn forEach(this: *@This(), comptime cb: anytype, args: anytype) void {
        this.ref.close();
        defer this.ref.open();
        this.ref.drain();

        const master = this.master.load(.unordered);

        for (this.bitmask, 0..) |*bit_bucket, i| {
            var bucket = bit_bucket.load(.unordered);
            while (bucket != 0) {
                const bit_pos = @ctz(bucket);
                const index = i * @bitSizeOf(usize) + bit_pos;

                const pair = &this.pairs[index];

                const key = &pair.key.raw;
                const value = &pair.value.raw;

                @call(.always_inline, cb, .{ master, key, value } ++ args);

                bucket &= bucket - 1;
            }
        }
    }
};

pub fn Pool(Type: type) type {
    return struct {
        const pool_len = @bitSizeOf(usize);
        const alignment = @sizeOf(Type) * pool_len;

        entries: [pool_len]Type align(alignment),
        used_bitmask: std.atomic.Value(usize) align(std.atomic.cache_line),

        pub const empty: @This() = .{ .entries = undefined, .used_bitmask = .init(0) };

        pub fn getPoolPtrFromEntryPtr(entry_ptr: *Type) *@This() {
            const aligned_addr = std.mem.alignBackward(usize, @intFromPtr(entry_ptr), alignment);
            const field_ptr: *[pool_len]Type align(alignment) = @ptrFromInt(aligned_addr);

            return @alignCast(@fieldParentPtr("entries", field_ptr));
        }

        pub fn getEntry(this: *@This()) ?*Type {
            var used = this.used_bitmask.load(.monotonic);
            var first_free = @ctz(~used);
            if (first_free == pool_len) return null;

            var locking_bit = @as(usize, 1) << @truncate(first_free);
            used = this.used_bitmask.fetchOr(locking_bit, .acquire);
            while (used & locking_bit != 0) {
                @branchHint(.unlikely);
                first_free = @ctz(~used);
                if (first_free == pool_len) return null;

                locking_bit = @as(usize, 1) << @truncate(first_free);
                used = this.used_bitmask.fetchOr(locking_bit, .acquire);
            }

            return &this.entries[first_free];
        }

        pub fn freeEntry(this: *@This(), entry_ptr: *anyopaque) void {
            const entry_address = @intFromPtr(entry_ptr);
            const position = @divExact(entry_address - std.mem.alignBackward(usize, @intFromPtr(entry_ptr), alignment), @sizeOf(Type));

            const freeing_bit = ~(@as(usize, 1) << @truncate(position));

            assert(this.used_bitmask.fetchAnd(freeing_bit, .release) & (~freeing_bit) != 0);
        }

        pub fn inUse(this: *@This()) bool {
            return @popCount(this.used_bitmask.load(.monotonic)) != 0;
        }
    };
}

const testing = std.testing;

test "RefGate: basic usage" {
    var gate = RefGate{};

    gate.increment();
    try testing.expectEqual(1, gate.reference.load(.monotonic));
    gate.decrement();

    try testing.expectEqual(0, gate.reference.load(.monotonic));
}

test "RefGate: cold path (waiting on closed gate)" {
    var gate = RefGate{};
    gate.close();

    const Context = struct {
        gate: *RefGate,
        entered: std.atomic.Value(bool) = .init(false),
        fn worker(ctx: *@This()) void {
            ctx.gate.increment();
            ctx.entered.store(true, .release);
            ctx.gate.decrement();
        }
    };

    var ctx = Context{ .gate = &gate };
    const thread = try std.Thread.spawn(.{}, Context.worker, .{&ctx});

    try testing.io.sleep(.fromMilliseconds(10), .real);
    try testing.expectEqual(false, ctx.entered.load(.acquire));

    gate.open();
    thread.join();

    try testing.expectEqual(true, ctx.entered.load(.acquire));
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

    const key: ThreadClocks.Key = .{ .data = 1 };
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

    const waker: ThreadClocks.Key = .{ .data = 1 };
    const wakee: ThreadClocks.Key = .{ .data = 2 };

    try clocks.put(waker, 10);
    try clocks.put(wakee, 5);

    clocks.master.store(20, .release);

    clocks.prepareForSleep(wakee);
    // lag = master (20) - ticks (5) = 15
    try testing.expectEqual(15, clocks.get(wakee, .lag));

    const delays = clocks.wake(waker, wakee);

    // waker_lag = master(20) - waker_ticks(10) = 10
    // wakee_lag = waker_lag(10) + wakee_lag(15) = 25
    try testing.expectEqual(10, delays.waker);
    try testing.expectEqual(25, delays.wakee);

    try testing.expectEqual(20, clocks.get(waker, .ticks));
    try testing.expectEqual(20, clocks.get(wakee, .ticks));
}

test "ThreadClocks: fork" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const parent: ThreadClocks.Key = .{ .data = 1 };
    const child: ThreadClocks.Key = .{ .data = 2 };

    try clocks.put(parent, 50);
    clocks.master.store(100, .release);

    const delay = try clocks.fork(parent, child);

    try testing.expectEqual(50, delay);
    try testing.expectEqual(100, clocks.get(parent, .ticks));
    try testing.expectEqual(100, clocks.get(child, .ticks));
}

test "ThreadClocks: collision path" {
    const allocator = testing.allocator;

    // With min_cap slots and many entries the collision bit may or may not
    // fire depending on hash distribution; we just verify all values survive.
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    // Use enough entries that collisions are plausible (half capacity).
    const n = min_cap / 2;
    var keys: [min_cap / 2]ThreadClocks.Key = undefined;
    var expected: [min_cap / 2]ThreadClocks.Ticks = undefined;
    for (0..n) |i| {
        keys[i] = ThreadClocks.Key{ .data = (@intCast(i + 1)) };
        expected[i] = @intCast((i + 1) * 10);
    }

    for (keys, expected) |key, ticks| {
        try clocks.put(key, ticks);
    }

    for (keys, expected) |key, ticks| {
        try testing.expectEqual(ticks, clocks.get(key, .ticks));
    }
}

test "ThreadClocks: Causal Mechanics" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const parent: ThreadClocks.Key = .{ .data = 1 };
    const child: ThreadClocks.Key = .{ .data = 2 };

    try clocks.put(parent, 10);
    clocks.master.store(50, .release);

    const fork_delay = try clocks.fork(parent, child);
    try testing.expectEqual(40, fork_delay);

    clocks.master.store(100, .release);
    clocks.prepareForSleep(child);

    const d = clocks.wake(parent, child);
    try testing.expectEqual(50, d.waker);
    try testing.expectEqual(100, d.wakee);
}

test "ThreadClocks: concurrent stress" {
    const allocator = testing.allocator;

    var clocks = try ThreadClocks.init(allocator, 128);
    defer clocks.deinit(allocator);

    const thread_count = 8;
    const ops_per_thread = 10_000;

    const Op = enum { tick, fork_and_tick };

    const Context = struct {
        clocks: *ThreadClocks,
        id: usize,
        registered: *std.atomic.Value(u32),

        fn run(ctx: *@This()) void {
            var prng = std.Random.DefaultPrng.init(ctx.id * 0xDEAD_BEEF);
            const random = prng.random();

            const key: ThreadClocks.Key = .{ .data = (@intCast(ctx.id + 1)) };

            _ = ctx.registered.fetchAdd(1, .release);
            while (ctx.registered.load(.acquire) < thread_count)
                std.atomic.spinLoopHint();

            var i: usize = 0;
            while (i < ops_per_thread) : (i += 1) {
                const op: Op = @enumFromInt(random.uintLessThan(u8, std.meta.fields(Op).len));

                switch (op) {
                    .tick => {
                        ctx.clocks.tick(key) catch {};
                    },

                    .fork_and_tick => {
                        const child_virtual_key: ThreadClocks.Key = .{ .data = @intCast((ctx.id + 1) * 10_000 + i + 1) };
                        if (ctx.clocks.fork(key, child_virtual_key)) |_| {
                            var t: usize = 0;
                            while (t < 3) : (t += 1) {
                                ctx.clocks.tick(child_virtual_key) catch break;
                            }
                        } else |_| {}
                    },
                }
            }
        }
    };

    const root: ThreadClocks.Key = .{ .data = 1 };
    try clocks.put(root, 0);
    for (1..thread_count) |i| {
        const child: ThreadClocks.Key = .{ .data = @intCast(i + 1) };
        _ = try clocks.fork(root, child);
    }

    var registered = std.atomic.Value(u32).init(0);

    var contexts: [thread_count]Context = undefined;
    for (0..thread_count) |i| {
        contexts[i] = .{ .clocks = &clocks, .id = i, .registered = &registered };
    }

    var threads: [thread_count]std.Thread = undefined;
    for (0..thread_count) |i| {
        threads[i] = try std.Thread.spawn(.{}, Context.run, .{&contexts[i]});
    }
    for (threads) |t| t.join();

    const master = clocks.master.load(.acquire);

    for (0..thread_count) |i| {
        const key: ThreadClocks.Key = .{ .data = @intCast(i + 1) };
        try testing.expect(master >= clocks.get(key, .ticks));
    }

    for (clocks.pairs) |pair| {
        const key = pair.key.load(.acquire);
        if (key.isEql(.empty) or key.isEql(.reserved)) continue;
        const ticks = pair.value.load(.monotonic).data.ticks;
        try testing.expect(master >= ticks);
    }
}

test "ThreadClocks: concurrent grow" {
    const allocator = testing.allocator;

    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const root: ThreadClocks.Key = .{ .data = 1 };
    try clocks.put(root, 0);

    const thread_count = 4;

    const Context = struct {
        clocks: *ThreadClocks,
        id: usize,

        fn run(ctx: *@This()) void {
            const key: ThreadClocks.Key = .{ .data = @intCast(ctx.id + 2) };
            const root_key: ThreadClocks.Key = .{ .data = 1 };
            _ = ctx.clocks.fork(root_key, key) catch return;

            var i: usize = 0;
            while (i < 5_000) : (i += 1) {
                ctx.clocks.tick(key) catch break;
            }
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
    for (0..thread_count) |i| {
        worker_contexts[i] = .{ .clocks = &clocks, .id = i };
    }

    var grow_ctx = GrowContext{ .clocks = &clocks, .alloc = allocator };

    var threads: [thread_count + 1]std.Thread = undefined;
    for (0..thread_count) |i| {
        threads[i] = try std.Thread.spawn(.{}, Context.run, .{&worker_contexts[i]});
    }
    threads[thread_count] = try std.Thread.spawn(.{}, GrowContext.run, .{&grow_ctx});

    for (threads) |t| t.join();

    try testing.expect(clocks.pairs.len >= min_cap);

    const master = clocks.master.load(.acquire);
    for (0..thread_count) |i| {
        const key: ThreadClocks.Key = .{ .data = @intCast(i + 2) };
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
    var i: usize = 0;
    while (i < max_retries) : (i += 1) {
        const index = (hash + i) & mask;
        const current_key = clocks.pairs[index].key.load(.acquire);
        if (current_key.isEql(key)) {
            const bucket = index / @bitSizeOf(usize);
            const bit = @as(usize, 1) << @truncate(index % @bitSizeOf(usize));
            return clocks.bitmask[bucket].load(.monotonic) & bit != 0;
        }
    }
    return false;
}

test "bitmask: put sets bit, remove clears it" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), countLiveBits(&clocks));

    const key: ThreadClocks.Key = .{ .data = 42 };
    try clocks.put(key, 0);

    try testing.expect(bitIsSet(&clocks, key));
    try testing.expectEqual(@as(usize, 1), countLiveBits(&clocks));

    _ = clocks.remove(key);

    try testing.expect(!bitIsSet(&clocks, key));
    try testing.expectEqual(@as(usize, 0), countLiveBits(&clocks));
}

test "bitmask: popcount tracks live entry count across multiple puts and removes" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const n = 16;
    var keys: [n]ThreadClocks.Key = undefined;
    for (0..n) |i| {
        keys[i] = ThreadClocks.Key{ .data = @intCast(i + 1) };
        try clocks.put(keys[i], 0);
        try testing.expectEqual(i + 1, countLiveBits(&clocks));
    }

    var live: usize = n;
    for (0..n) |i| {
        if (i % 2 == 0) {
            _ = clocks.remove(keys[i]);
            live -= 1;
            try testing.expectEqual(live, countLiveBits(&clocks));
        }
    }
}

test "bitmask: fork sets child bit without clearing parent bit" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const parent: ThreadClocks.Key = .{ .data = 1 };
    const child: ThreadClocks.Key = .{ .data = 2 };

    try clocks.put(parent, 10);
    clocks.master.store(10, .release); // master must be >= ticks to avoid underflow in fork
    try testing.expectEqual(@as(usize, 1), countLiveBits(&clocks));

    _ = try clocks.fork(parent, child);

    try testing.expect(bitIsSet(&clocks, parent));
    try testing.expect(bitIsSet(&clocks, child));
    try testing.expectEqual(@as(usize, 2), countLiveBits(&clocks));
}

test "bitmask: grow migrates all live bits and clears none" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const n = 8;
    var keys: [n]ThreadClocks.Key = undefined;
    for (0..n) |i| {
        keys[i] = ThreadClocks.Key{ .data = @intCast(i + 1) };
        try clocks.put(keys[i], @intCast(i * 10));
    }

    try testing.expectEqual(@as(usize, n), countLiveBits(&clocks));

    const old = try clocks.grow(allocator);
    allocator.free(old[0]);
    allocator.free(old[1]);

    for (keys) |key| {
        try testing.expect(bitIsSet(&clocks, key));
    }
    try testing.expectEqual(@as(usize, n), countLiveBits(&clocks));
}

test "bitmask: grow with partial removes — only live entries retain their bit" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const n = 12;
    var keys: [n]ThreadClocks.Key = undefined;
    for (0..n) |i| {
        keys[i] = ThreadClocks.Key{ .data = @intCast(i + 1) };
        try clocks.put(keys[i], 0);
    }

    for (0..n) |i| {
        if (i % 2 == 0) _ = clocks.remove(keys[i]);
    }
    try testing.expectEqual(@as(usize, n / 2), countLiveBits(&clocks));

    const old = try clocks.grow(allocator);
    allocator.free(old[0]);
    allocator.free(old[1]);

    try testing.expectEqual(@as(usize, n / 2), countLiveBits(&clocks));

    for (0..n) |i| {
        if (i % 2 == 0) {
            try testing.expect(!bitIsSet(&clocks, keys[i]));
        } else {
            try testing.expect(bitIsSet(&clocks, keys[i]));
        }
    }
}

test "ThreadClocks: forEach visits all live entries exactly once" {
    const allocator = testing.allocator;
    var clocks = try ThreadClocks.init(allocator, min_cap);
    defer clocks.deinit(allocator);

    const n = 8;
    var keys: [n]ThreadClocks.Key = undefined;
    for (0..n) |i| {
        keys[i] = ThreadClocks.Key{ .data = (@intCast(i + 1)) };
        try clocks.put(keys[i], @intCast(i * 10));
    }

    clocks.master.store(30, .release);
    _ = clocks.remove(keys[3]);

    var count: usize = 0;
    var ticks_sum: u32 = 0;

    const cb = struct {
        fn cb(_: ThreadClocks.Ticks, _: *ThreadClocks.Key, value: *ThreadClocks.Value, c: *usize, sum: *u32) void {
            c.* += 1;
            sum.* += value.data.ticks;
        }
    }.cb;

    clocks.forEach(cb, .{ &count, &ticks_sum });

    try testing.expectEqual(n - 1, count);
    try testing.expectEqual(@as(u32, 250), ticks_sum);
}

test "Pool: basic alloc/free and pointer math" {
    const P = Pool(u64);
    var pool: P = .empty;

    const ptr1 = pool.getEntry() orelse return error.TestUnexpectedFull;
    ptr1.* = 0xAAAA_BBBB;

    const parent = P.getPoolPtrFromEntryPtr(ptr1);
    try testing.expectEqual(&pool, parent);

    const ptr2 = pool.getEntry() orelse return error.TestUnexpectedFull;
    try testing.expect(ptr1 != ptr2);

    pool.freeEntry(ptr1);
}

test "Pool: exhaustion and capacity" {
    const P = Pool(u8);
    var pool: P = .empty;
    var ptrs: [@bitSizeOf(usize)]*u8 = undefined;

    for (0..@bitSizeOf(usize)) |i| {
        ptrs[i] = pool.getEntry() orelse return error.TestUnexpectedFull;
    }

    try testing.expectEqual(null, pool.getEntry());

    pool.freeEntry(ptrs[0]);

    const new_ptr = pool.getEntry();
    try testing.expectEqual(ptrs[0], new_ptr.?);
}

test "Pool: power of 2 struct alignment" {
    const Align16 = struct {
        data: [16]u8,
    };

    const P = Pool(Align16);
    var pool: P = .empty;

    const ptr = pool.getEntry() orelse return error.TestUnexpectedFull;
    const parent = P.getPoolPtrFromEntryPtr(ptr);
    try testing.expectEqual(&pool, parent);
}

test "Pool: concurrent churn" {
    const P = Pool(usize);

    const pool = try testing.allocator.create(P);
    pool.* = .empty;
    defer testing.allocator.destroy(pool);

    const thread_count = 4;
    const ops_per_thread = 20_000;

    const Context = struct {
        p: *P,
        id: usize,
        fn run(ctx: @This()) void {
            var prng = std.Random.DefaultPrng.init(ctx.id);
            const random = prng.random();

            var i: usize = 0;
            while (i < ops_per_thread) : (i += 1) {
                if (ctx.p.getEntry()) |ptr| {
                    ptr.* = ctx.id;
                    if (random.boolean()) std.atomic.spinLoopHint();
                    ctx.p.freeEntry(ptr);
                } else {
                    std.atomic.spinLoopHint();
                }
            }
        }
    };

    var threads: [thread_count]std.Thread = undefined;
    for (0..thread_count) |i| {
        threads[i] = try std.Thread.spawn(.{}, Context.run, .{Context{ .p = pool, .id = i }});
    }

    for (threads) |t| t.join();

    try testing.expectEqual(0, pool.used_bitmask.load(.monotonic));
}
