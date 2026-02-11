const std = @import("std");
const assert = std.debug.assert;

const RefGate = struct {
    const lock_bit = @as(usize, 1) << (@bitSizeOf(usize) - 1);
    const references_mask = ~lock_bit;

    reference: std.atomic.Value(usize) align(std.atomic.cache_line) = .init(0),

    pub inline fn increment(this: *@This()) void {
        const ref = this.reference.fetchAdd(1, .acquire);
        assert((ref & references_mask) != references_mask);
        if (ref & lock_bit != 0) {
            @branchHint(.cold);
            var reference = (this.reference.fetchSub(1, .monotonic) - 1) & references_mask;
            while (this.reference.cmpxchgWeak(reference, reference + 1, .acquire, .monotonic)) |new_ref| {
                assert(new_ref & lock_bit != lock_bit - 1);
                reference = new_ref & references_mask;
                std.atomic.spinLoopHint();
            }
        }
    }

    pub inline fn decrement(this: *@This()) void {
        assert(this.reference.fetchSub(1, .release) != 0);
    }

    pub inline fn close(this: *@This()) void {
        while (this.reference.fetchOr(lock_bit, .acquire) & lock_bit != 0) {
            @branchHint(.cold);
            while (this.reference.load(.monotonic) & lock_bit != 0) std.atomic.spinLoopHint();
        }
    }

    pub inline fn drain(this: *@This()) void {
        while ((this.reference.load(.acquire) & references_mask) != 0) {
            std.atomic.spinLoopHint();
        }
    }

    pub inline fn open(this: *@This()) void {
        assert(this.reference.fetchAnd(references_mask, .release) & lock_bit != 0);
    }
};

/// Concurrent map optimized for thread-local clock propagation.
///
/// It is undefined behavior for multiple threads to concurrently
/// try to reserve the same key .
pub const TidClocks = struct {
    pub const Tid = std.os.linux.pid_t;

    pub const Key = packed struct(u64) {
        from: Tid,
        to: Tid,

        const collided_bit: u64 = 1 << 63;

        pub const empty: @This() = @bitCast(@as(u64, 0));
        pub const empty_collided: @This() = @bitCast(collided_bit);
        pub const locked: @This() = @bitCast(@as(u64, std.math.maxInt(u64)));

        pub fn clock(tid: Tid) @This() {
            return .{ .from = tid, .to = 0 };
        }

        pub fn lag(from: Tid, to: Tid) @This() {
            return .{ .from = from, .to = to };
        }

        pub fn hasCollided(this: @This()) bool {
            return @as(u64, @bitCast(this)) & collided_bit != 0;
        }

        pub fn eql(this: @This(), other: @This()) bool {
            const collided_mask = ~@as(u64, @bitCast(collided_bit));
            return (@as(u64, @bitCast(this)) & collided_mask) == (@as(u64, @bitCast(other)) & collided_mask);
        }

        pub fn hash(this: @This()) u64 {
            const collided_mask = ~@as(u64, @bitCast(collided_bit));
            return std.hash.int(@as(u64, @bitCast(this)) & collided_mask);
        }
    };

    pub const Value = packed struct(u32) {
        epoque: u16,
        ticks: u16,
    };

    const Pair = struct {
        key: std.atomic.Value(Key),
        value: std.atomic.Value(Value),

        const empty: @This() = .{ .key = .init(Key.empty), .value = undefined };
    };

    ref: RefGate,
    epoque: std.atomic.Value(u16) align(std.atomic.cache_line),
    pairs: []Pair,

    pub fn init(allocator: std.mem.Allocator, reserve: usize) !@This() {
        assert(@popCount(reserve) == 1);

        const pairs = try allocator.alloc(Pair, reserve);
        @memset(pairs, Pair.empty);
        return .{ .ref = .{}, .pairs = pairs, .epoque = .init(0) };
    }

    pub fn deinit(this: *@This(), allocator: std.mem.Allocator) void {
        this.ref.close();
        this.ref.drain();
        allocator.free(this.pairs);
    }

    fn reserveSlotUnsafe(this: *@This(), key: Key, hash: u64) !*Pair {
        const len = this.pairs.len;

        assert(@popCount(len) == 1);
        const bitmask = len - 1;
        const max_retries = @max(16, len / 32);

        var i: usize = 0;
        while (i < max_retries) : (i += 1) {
            const index = (hash + i) & bitmask;
            const local_key = this.pairs[index].key.load(.monotonic);

            if (local_key.eql(key) or
                (local_key.eql(.empty) and this.pairs[index].key.cmpxchgStrong(.empty, .locked, .monotonic, .monotonic) == null))
                return &this.pairs[index];

            if (!local_key.hasCollided())
                _ = this.pairs[index].key.fetchOr(Key.empty_collided, .monotonic);
        }

        return error.NoSpace;
    }

    fn getSlotUnsafe(this: *@This(), key: Key, hash: u64) *Pair {
        const len = this.pairs.len;

        assert(@popCount(len) == 1);
        const bitmask = len - 1;
        const max_retries = @max(16, len / 32);

        var i: usize = 0;
        var current_key: Key = .empty_collided;

        return slot: while (current_key.hasCollided() and i < max_retries) : (i += 1) {
            const index = (hash + i) & bitmask;
            current_key = this.pairs[index].key.load(.monotonic);

            if (current_key.eql(key)) break :slot &this.pairs[index];
        } else unreachable; // Somehow we required a tid that has no entry.
        // This would be faulty logic in the algorithm implementaiton
        // so we use unreachable to catch that in the tests.
    }

    pub fn put(this: *@This(), clock: Key, ticks: u16) !void {
        assert(clock.to == 0);
        const hash = clock.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const slot = try this.reserveSlotUnsafe(clock, hash);
        const epoque = this.epoque.load(.monotonic);

        slot.value.store(.{
            .epoque = epoque,
            .ticks = ticks,
        }, .monotonic);

        slot.key.store(clock, .monotonic);
    }

    pub fn tick(this: *@This(), clock: Key) !void {
        assert(clock.to == 0);

        const hash = clock.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const slot = try this.reserveSlotUnsafe(clock, hash);

        const epoque = this.epoque.load(.monotonic);
        const value = slot.value.load(.monotonic);

        slot.value.store(.{
            .epoque = epoque,
            .ticks = if (epoque == value.epoque) value.ticks + 1 else 1,
        }, .monotonic);

        slot.key.store(clock, .monotonic);
    }

    // The key will contain the from clock and the to clock.
    // the from clock is the waking tid's clock while the to clock is woke tid's clock.
    //
    // At this point the to clock will not contain the ticks but the delay with the global
    // clock's tick when the tid went to sleep.
    //
    // The attribution logic is the following:
    //
    // to_ticks = from_ticks - to_lag + old_transfered_lag
    // old_transfered_lag = global_ticks - from_ticks
    //
    // Old transfered lag is simply the lag we already counted in other transfers from the same
    // tid to avoid recounting the same lag
    //
    /// Transfers clocks from one tid to another, both clocks must have an entry
    pub fn transfer(this: *@This(), lag: Key, global_ticks: u16) !void {
        // Tick shall be used only for transfering lag
        assert(lag.from != 0 and lag.to != 0);

        const lag_hash = lag.hash();

        const from_clock: Key = .clock(lag.from);
        const from_hash = from_clock.hash();

        const to_clock: Key = .clock(lag.to);
        const to_hash = from_clock.hash();

        this.ref.increment();
        defer this.ref.decrement();
        const epoque = this.epoque.load(.monotonic);

        // to_ticks = from_ticks - to_lag + old_transfered_lag
        // old_transfered_lag = global_ticks - from_ticks

        const from_slot = this.getSlotUnsafe(from_clock, from_hash);
        const to_slot = this.getSlotUnsafe(to_clock, to_hash);
        const old_transfered_lag_slot = try this.reserveSlotUnsafe(lag, lag_hash);

        const from_ticks = l: {
            const value = from_slot.value.load(.monotonic);
            break :l if (value.epoque == this.epoque) value.ticks else 0;
        };

        const to_lag = l: {
            const value = to_slot.value.load(.monotonic);
            break :l if (value.epoque == this.epoque) value.ticks else 0;
        };

        const old_transfered_lag = l: {
            const value = old_transfered_lag_slot.value.load(.monotonic);
            break :l if (value.epoque == epoque) value.ticks else 0;
        };

        to_slot.value.store(.{
            .epoque = epoque,
            .ticks = from_ticks - to_lag + old_transfered_lag,
        }, .monotonic);

        old_transfered_lag_slot.value.store(.{
            .epoque = epoque,
            .ticks = global_ticks - from_ticks,
        }, .monotonic);
        old_transfered_lag_slot.key.store(lag, .monotonic);
    }

    pub fn drainAndGetLag(this: *@This(), clock: Key, global_ticks: u16) u16 {
        assert(clock.to == 0);
        const hash = clock.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const epoque = this.epoque.load(.monotonic);

        const slot = this.getSlotUnsafe(clock, hash);
        const value = slot.value.load(.monotonic);
        slot.value.store(.{ .epoque = epoque, .ticks = 0 }, .monotonic);
        const ticks = if (value.epoque == this.epoque) value.ticks else 0;

        return global_ticks - ticks;
    }

    pub fn clear(this: *@This()) void {
        _ = this.epoque.fetchAdd(1, .monotonic);
        // This could wrap around and it means that we could actually resurrect data
        // that was in old epoques; The situation should basically never happen
        //
        // (It only happens if we don't access a specific fields for ~30m to ~1h,
        // based on experiment length 25ms or 50ms, and then we read the data
        // without inserting something new)
        //
        // and even if it does happen a bad datapoint is completly fine
    }

    pub fn grow(this: *@This(), allocator: std.mem.Allocator) ![]Pair {
        this.ref.increment();
        const new_size = this.pairs.len * 2;
        this.ref.decrement();

        assert(@popCount(new_size) == 1);
        const new_pairs = try allocator.alloc(Pair, new_size);
        @memset(new_pairs, Pair.empty);

        this.ref.close();
        defer this.ref.open();

        const old_pairs = this.pairs;

        this.ref.drain();
        this.pairs = new_pairs;

        const epoque = this.epoque.load(.monotonic);

        for (old_pairs) |pair| {
            const key = pair.key.load(.unordered);
            const value = pair.value.load(.unordered);
            const hash = key.hash();
            if (!key.eql(.empty) and value.epoque == epoque) {
                const slot = try this.reserveSlotUnsafe(key, hash); // We could drop to non atomic operations.
                slot.value.store(.{ .epoque = epoque, .ticks = value.ticks }, .unordered);
                slot.key.store(key, .unordered);
            }
        }

        return old_pairs;
    }
};

pub fn Pool(Type: type) type {
    return struct {
        const pool_len = @bitSizeOf(usize);
        const alignment = @sizeOf(Type) * pool_len;

        entries: [pool_len]Type align(alignment),
        used_bitmask: std.atomic.Value(usize) align(std.atomic.cache_line),
        context: ?*anyopaque,

        pub fn empty() @This() {
            return .{
                .entries = undefined,
                .used_bitmask = .init(0),
                .context = null,
            };
        }

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

        pub fn freeEntry(this: *@This(), entry_ptr: *Type) void {
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

test "TidClocks.Key: construction and bit manipulation" {
    const Key = TidClocks.Key;

    const k1 = Key.clock(100);
    try testing.expectEqual(100, k1.from);
    try testing.expectEqual(0, k1.to);
    try testing.expect(!k1.hasCollided());

    const k2 = Key.lag(100, 200);
    try testing.expectEqual(100, k2.from);
    try testing.expectEqual(200, k2.to);

    var k3 = k1;
    const raw_k3: *u64 = @ptrCast(&k3);
    raw_k3.* |= Key.collided_bit;

    try testing.expect(k3.hasCollided());
    try testing.expect(k1.eql(k3));
}

test "TidClocks: basic put and get" {
    const Key = TidClocks.Key;

    var clocks = try TidClocks.init(testing.allocator, 16);
    defer clocks.deinit(testing.allocator);

    const k1 = Key.clock(1);
    const v1 = 1234;

    try clocks.put(k1, v1);

    const retrieved = clocks.get(k1);
    try testing.expectEqual(v1, retrieved);

    const k2 = Key.clock(2);
    try testing.expectEqual(null, clocks.get(k2));
}

test "TidClocks: update existing key" {
    const Key = TidClocks.Key;

    var clocks = try TidClocks.init(testing.allocator, 16);
    defer clocks.deinit(testing.allocator);

    const k1 = Key.clock(1);
    try clocks.put(k1, 10);
    try testing.expectEqual(10, clocks.get(k1).?);

    try clocks.put(k1, 20);
    try testing.expectEqual(20, clocks.get(k1).?);
}

test "TidClocks: functioning with reasonable size" {
    const Key = TidClocks.Key;
    const size = 1024; // max_retries = 32
    var clocks = try TidClocks.init(testing.allocator, size);
    defer clocks.deinit(testing.allocator);

    var i: u16 = 0;
    while (i < 100) : (i += 1) {
        try clocks.put(Key.clock(i), i * 10);
    }

    i = 0;
    while (i < 100) : (i += 1) {
        const val = clocks.get(Key.clock(i));
        try testing.expectEqual(i * 10, val.?);
    }
}

test "ThreadLocalClock: grow data preservation and memory return" {
    const Key = TidClocks.Key;

    var clocks = try TidClocks.init(testing.allocator, 16);
    var i: u16 = 1;
    while (i < 9) : (i += 1) {
        try clocks.put(Key.clock(i), i * 10);
    }

    const old_pairs = try clocks.grow(testing.allocator);

    testing.allocator.free(old_pairs);

    i = 1;
    for (clocks.pairs) |pair| {
        if (!pair.key.load(.acquire).eql(.empty)) {}
    }
    while (i < 9) : (i += 1) {
        const val = clocks.get(Key.clock(i));
        try testing.expectEqual(i * 10, val.?);
    }

    try testing.expectEqual(32, clocks.pairs.len);

    clocks.deinit(testing.allocator);
}

test "ThreadLocalClock: grow blocks concurrent readers" {
    const Key = TidClocks.Key;
    var clocks = try TidClocks.init(testing.allocator, 16);

    const target_key = Key.clock(1234);
    try clocks.put(target_key, 55);

    const ReaderContext = struct {
        clocks: *TidClocks,
        key: Key,
        stop: std.atomic.Value(bool) = .init(false),
        success_count: std.atomic.Value(usize) = .init(0),

        fn run(ctx: *@This()) void {
            while (!ctx.stop.load(.monotonic)) {
                if (ctx.clocks.get(ctx.key)) |v| {
                    assert(v == 55);
                    _ = ctx.success_count.fetchAdd(1, .monotonic);
                }
            }
        }
    };

    var ctx = ReaderContext{ .clocks = &clocks, .key = target_key };
    const thread = try std.Thread.spawn(.{}, ReaderContext.run, .{&ctx});

    try testing.io.sleep(.fromMilliseconds(1), .real);

    const old_pairs = try clocks.grow(testing.allocator);
    testing.allocator.free(old_pairs);

    ctx.stop.store(true, .release);
    thread.join();

    try testing.expect(ctx.success_count.load(.monotonic) > 0);
    clocks.deinit(testing.allocator);
}

test "ThreadLocalClock: grow error on full table" {
    const Key = TidClocks.Key;

    var clocks = try TidClocks.init(testing.allocator, 2);
    defer clocks.deinit(testing.allocator);

    var i: u16 = 0;
    var failed = false;
    while (i < 5) : (i += 1) {
        clocks.put(Key.clock(i), i) catch {
            failed = true;
            break;
        };
    }

    try testing.expect(failed);

    const old_pairs = try clocks.grow(testing.allocator);
    testing.allocator.free(old_pairs);

    try clocks.put(Key.clock(100), 100);
    try testing.expectEqual(100, clocks.get(Key.clock(100)).?);
}

test "TidClocks: epoque clear invalidates entries" {
    const Key = TidClocks.Key;
    var clocks = try TidClocks.init(testing.allocator, 16);
    defer clocks.deinit(testing.allocator);

    const k1 = Key.clock(1);
    const k2 = Key.clock(2);

    try clocks.put(k1, 100);
    try clocks.put(k2, 200);

    try testing.expectEqual(100, clocks.get(k1).?);
    try testing.expectEqual(200, clocks.get(k2).?);

    clocks.clear();

    try testing.expectEqual(null, clocks.get(k1));
    try testing.expectEqual(null, clocks.get(k2));
}

test "TidClocks: epoque recycling" {
    const Key = TidClocks.Key;
    var clocks = try TidClocks.init(testing.allocator, 16);
    defer clocks.deinit(testing.allocator);

    const k1 = Key.clock(1);

    try clocks.put(k1, 10);
    try testing.expectEqual(10, clocks.get(k1).?);

    clocks.clear();
    try testing.expectEqual(null, clocks.get(k1));

    try clocks.put(k1, 20);

    try testing.expectEqual(20, clocks.get(k1).?);

    clocks.clear();
    try testing.expectEqual(null, clocks.get(k1));
}

test "TidClocks: grow preserves only current epoque values (indirectly)" {
    const Key = TidClocks.Key;
    var clocks = try TidClocks.init(testing.allocator, 4);
    defer clocks.deinit(testing.allocator);

    try clocks.put(Key.clock(1), 10);
    clocks.clear(); // Invalidates Key 1

    try clocks.put(Key.clock(2), 20); // Valid in new epoch

    const old_pairs = try clocks.grow(testing.allocator);
    testing.allocator.free(old_pairs);

    try testing.expectEqual(null, clocks.get(Key.clock(1)));
    try testing.expectEqual(20, clocks.get(Key.clock(2)).?);
}

test "TidClocks: concurrent put/get" {
    const Key = TidClocks.Key;

    var clocks = try TidClocks.init(testing.allocator, 4096);
    defer clocks.deinit(testing.allocator);

    const thread_count = 4;
    const items_per_thread = 500;

    const Context = struct {
        clocks: *TidClocks,
        id: usize,
        fn run(ctx: @This()) void {
            var i: usize = 0;
            const start = ctx.id * items_per_thread;

            while (i < items_per_thread) : (i += 1) {
                const key: i32 = @truncate(@as(i64, @bitCast(start + i)));
                const val: u16 = @truncate(start + i);
                ctx.clocks.put(Key.clock(key), val) catch unreachable;
            }

            i = 0;
            while (i < items_per_thread) : (i += 1) {
                const key_val: i32 = @truncate(@as(i64, @bitCast(start + i)));
                const val = ctx.clocks.get(Key.clock(key_val));
                assert(val != null and val.? == key_val);
            }
        }
    };

    var threads: [thread_count]std.Thread = undefined;
    for (0..thread_count) |i| {
        threads[i] = try std.Thread.spawn(.{}, Context.run, .{Context{ .clocks = &clocks, .id = i }});
    }

    for (threads) |t| t.join();
}

test "Pool: basic alloc/free and pointer math" {
    const P = Pool(u64);
    var pool = P.empty();

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
    var pool = P.empty();
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
    var pool = P.empty();

    const ptr = pool.getEntry() orelse return error.TestUnexpectedFull;
    const parent = P.getPoolPtrFromEntryPtr(ptr);
    try testing.expectEqual(&pool, parent);
}

test "Pool: concurrent churn" {
    const P = Pool(usize);

    const pool = try testing.allocator.create(P);
    pool.* = .empty();
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

    try testing.expectEqual(@as(usize, 0), pool.used_bitmask.load(.monotonic));
}
