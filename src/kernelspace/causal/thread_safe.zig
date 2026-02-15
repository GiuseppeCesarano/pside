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
///
/// It is undefined behavior for multiple threads to concurrently
/// try to reserve the same key .
pub const DriftRegistry = struct {
    pub const Tid = std.os.linux.pid_t;

    pub const Key = packed struct(u64) {
        upper_half: Tid,
        lower_half: Tid,

        const collided_bit: u64 = 1 << 63;

        pub const empty: @This() = @bitCast(@as(u64, 0));
        pub const empty_collided: @This() = @bitCast(collided_bit);
        pub const locked: @This() = @bitCast(@as(u64, std.math.maxInt(u64)) & ~collided_bit);

        pub fn clock(tid: Tid) @This() {
            return .{ .upper_half = tid, .lower_half = 0 };
        }

        pub fn lag(from: Tid, to: Tid) @This() {
            return .{ .upper_half = from, .lower_half = to };
        }

        pub fn hasCollided(this: @This()) bool {
            return @as(u64, @bitCast(this)) & collided_bit != 0;
        }

        pub fn withCollisionBitSet(this: @This()) @This() {
            return @bitCast(@as(u64, @bitCast(this)) | collided_bit);
        }

        pub fn eql(this: @This(), other: @This()) bool {
            const collided_mask = ~@as(u64, @bitCast(collided_bit));
            return (@as(u64, @bitCast(this)) & collided_mask) == (@as(u64, @bitCast(other)) & collided_mask);
        }

        pub fn upperHalfEql(this: @This(), other: @This()) bool {
            const rhs = this.withCollisionBitSet();
            const lhs = other.withCollisionBitSet();
            return rhs.upper_half == lhs.upper_half;
        }

        pub fn hash(this: @This()) u64 {
            const collided_mask = ~@as(u64, @bitCast(collided_bit));
            return std.hash.int(@as(u64, @bitCast(this)) & collided_mask);
        }
    };

    pub const Value = packed struct(u32) {
        epoch: u16,
        data: packed union { ticks: u16, lag: u16 },
    };

    const Pair = struct {
        key: std.atomic.Value(Key),
        value: std.atomic.Value(Value),

        const empty: @This() = .{ .key = .init(Key.empty), .value = undefined };
    };

    ref: RefGate,
    epoch: std.atomic.Value(u16) align(std.atomic.cache_line),
    pairs: []Pair,

    pub fn init(allocator: std.mem.Allocator, reserve: usize) !@This() {
        assert(@popCount(reserve) == 1);

        const pairs = try allocator.alloc(Pair, reserve);
        @memset(pairs, Pair.empty);
        return .{ .ref = .{}, .pairs = pairs, .epoch = .init(0) };
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
                (local_key.eql(.empty) and this.pairs[index].key.cmpxchgStrong(.empty, .locked, .acquire, .monotonic) == null))
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
            current_key = this.pairs[index].key.load(.acquire);

            if (current_key.eql(key)) break :slot &this.pairs[index];
        } else unreachable; // Somehow we required a tid that has no entry.
        // This would be faulty logic in the algorithm implementation
        // so we use unreachable to catch that in the tests.
    }

    pub fn put(this: *@This(), clock: Key, ticks: u16) !void {
        assert(!clock.eql(.empty));
        const hash = clock.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const slot = try this.reserveSlotUnsafe(clock, hash);
        const epoch = this.epoch.load(.monotonic);

        slot.value.store(.{
            .epoch = epoch,
            .data = .{ .ticks = ticks },
        }, .monotonic);

        _ = slot.key.fetchAnd(clock.withCollisionBitSet(), .release);
    }

    pub fn get(this: *@This(), clock: Key) u16 {
        assert(!clock.eql(.empty));
        const hash = clock.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const slot = this.getSlotUnsafe(clock, hash);
        const epoch = this.epoch.load(.monotonic);

        const value = slot.value.load(.monotonic);

        return if (value.epoch == epoch) value.data.ticks else 0;
    }

    pub fn tick(this: *@This(), clock: Key) !u16 {
        assert(clock.upper_half != 0 and clock.lower_half == 0);

        const hash = clock.hash();

        try this.ref.tryIncrement();
        defer this.ref.decrement();

        const slot = this.getSlotUnsafe(clock, hash);

        const epoch = this.epoch.load(.monotonic);
        const value = slot.value.load(.monotonic);

        const ticks = if (epoch == value.epoch) value.data.ticks + 1 else 1;

        slot.value.store(.{
            .epoch = epoch,
            .data = .{ .ticks = ticks },
        }, .monotonic);

        return ticks;
    }

    pub fn prepareForTransfer(this: *@This(), clock: Key, global_ticks: u16) void {
        assert(clock.lower_half == 0);
        const hash = clock.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const epoch = this.epoch.load(.monotonic);

        const slot = this.getSlotUnsafe(clock, hash);
        const value = slot.value.load(.monotonic);
        const ticks = if (value.epoch == epoch) value.data.ticks else 0;

        slot.value.store(.{
            .epoch = epoch,
            .data = .{ .lag = global_ticks - ticks },
        }, .monotonic);
    }

    // The key will contain the from clock and the to clock.
    // The from clock is the waking tid's ticks while the to clock is woke tid's lag from
    // the global clock ticks at the time of sleeping.
    //
    // The attribution logic is the following:
    //
    // to_ticks = from_ticks - to_lag + old_transferred_lag
    // old_transferred_lag = global_ticks - from_ticks
    //
    // Old transferred lag is simply the lag we already counted in other transfers from the same
    // tid to avoid recounting the same lag
    //
    /// Transfers clocks from one tid to another, both clocks must have an entry
    /// The lag.from key must match the callee tid
    /// The lag.to tid must be blocked or not try to read/increment its own clock
    /// prepareForTransfer(...) must be called on the lag.to tid before calling this function.
    pub fn transfer(this: *@This(), lag: Key, global_ticks: u16) !void {
        // Tick shall be used only for transferring lag
        assert(lag.upper_half != 0 and lag.lower_half != 0);

        const lag_hash = lag.hash();

        const from_clock: Key = .clock(lag.upper_half);
        const from_hash = from_clock.hash();

        const to_clock: Key = .clock(lag.lower_half);
        const to_hash = to_clock.hash();

        this.ref.increment();
        defer this.ref.decrement();
        const epoch = this.epoch.load(.monotonic);

        // to_ticks = from_ticks - to_lag + old_transferred_lag
        // old_transferred_lag = global_ticks - from_ticks

        const from_slot = this.getSlotUnsafe(from_clock, from_hash);
        const to_slot = this.getSlotUnsafe(to_clock, to_hash);
        const old_transferred_lag_slot = try this.reserveSlotUnsafe(lag, lag_hash);

        const from_ticks = l: {
            const value = from_slot.value.load(.unordered);
            break :l if (value.epoch == epoch) value.data.ticks else 0;
        };

        const to_lag = l: {
            const value = to_slot.value.load(.unordered);
            break :l if (value.epoch == epoch) value.data.lag else 0;
        };

        const old_transferred_lag = l: {
            const value = old_transferred_lag_slot.value.load(.unordered);
            break :l if (value.epoch == epoch) value.data.lag else 0;
        };

        to_slot.value.store(.{
            .epoch = epoch,
            .data = .{ .ticks = from_ticks - to_lag + old_transferred_lag },
        }, .monotonic);

        old_transferred_lag_slot.value.store(.{
            .epoch = epoch,
            .data = .{ .lag = global_ticks - from_ticks },
        }, .unordered);
        _ = old_transferred_lag_slot.key.fetchAnd(lag.withCollisionBitSet(), .release);
    }

    /// The from key must match the callee tid
    /// The to tid must be blocked or not try to read/increment its own clock
    pub fn copy(this: *@This(), from: Key, to: Key) !void {
        assert(!from.eql(to));
        assert(from != Key.empty and to != Key.empty);
        assert(from.lower_half == 0 and to.lower_half == 0);

        this.ref.increment();
        defer this.ref.decrement();

        const epoch = this.epoch.load(.monotonic);

        // We don't care about other threads updates, so we are not racing them with unordered
        // We only want the current tid values to be put in the new thread; then ref.decrement()
        // will handle the publishing
        for (this.pairs) |*pair| {
            const key = pair.key.load(.unordered);
            if (key.upperHalfEql(from)) {
                @branchHint(.unpredictable);
                _ = pair.key.load(.acquire);
                const value = pair.value.load(.unordered);
                if (value.epoch == epoch or key.lower_half == 0) { // We still want to reserve space for the clock itself
                    const new_key: Key = .{ .upper_half = to.upper_half, .lower_half = key.lower_half };
                    const slot = try this.reserveSlotUnsafe(new_key, new_key.hash());
                    slot.value.store(value, .unordered);
                    slot.key.store(new_key, .unordered);
                }
            }
        }
    }

    pub fn clear(this: *@This()) void {
        _ = this.epoch.fetchAdd(1, .monotonic);
        // This could wrap around and it means that we could actually resurrect data
        // that was in old epochs; this situation is rare:
        //
        // It only happens if we don't access a field for ~30m to ~1h,
        // based on experiment length 25ms or 50ms, and then we read the data
        // without inserting something new
        //
        // and even if it does happen a bad datapoint is completely fine
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

        const epoch = this.epoch.load(.monotonic);

        for (old_pairs) |pair| {
            const key = pair.key.load(.unordered);
            const value = pair.value.load(.unordered);
            const hash = key.hash();
            if (!key.eql(.empty) and value.epoch == epoch) {
                const slot = try this.reserveSlotUnsafe(key, hash); // We could drop to non atomic operations.
                slot.value.store(.{ .epoch = epoch, .data = value.data }, .unordered);
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

        const empty: @This() = .{ .entries = undefined, .used_bitmask = .init(0) };

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

test "DriftRegistry: epoch isolation" {
    const Key = DriftRegistry.Key;
    var registry: DriftRegistry = try .init(testing.allocator, 16);
    defer registry.deinit(testing.allocator);

    const k1 = Key.clock(1);

    try registry.put(k1, 100);
    try testing.expectEqual(100, registry.get(k1));

    registry.clear();

    try testing.expectEqual(0, registry.get(k1));

    _ = registry.tick(k1) catch unreachable;
    try testing.expectEqual(1, registry.get(k1));
}

test "DriftRegistry: hash collision and linear probing" {
    var registry: DriftRegistry = try .init(testing.allocator, 4);
    defer registry.deinit(testing.allocator);

    try registry.put(.clock(1), 10);
    try registry.put(.clock(2), 20);
    try registry.put(.clock(3), 30);

    try testing.expectEqual(10, registry.get(.clock(1)));
    try testing.expectEqual(20, registry.get(.clock(2)));
    try testing.expectEqual(30, registry.get(.clock(3)));
}

test "DriftRegistry: tick logic" {
    const Key = DriftRegistry.Key;
    var registry: DriftRegistry = try .init(testing.allocator, 16);
    defer registry.deinit(testing.allocator);

    const k: Key = .clock(1);
    try registry.put(k, 0);
    try testing.expectEqual(1, registry.tick(k) catch unreachable);
    try testing.expectEqual(2, registry.tick(k) catch unreachable);

    registry.clear();
    try testing.expectEqual(1, registry.tick(k) catch unreachable);
}

test "DriftRegistry: prepareForTransfer" {
    const Key = DriftRegistry.Key;
    var registry: DriftRegistry = try .init(testing.allocator, 16);
    defer registry.deinit(testing.allocator);

    const k: Key = .clock(1);
    try registry.put(k, 30);

    registry.prepareForTransfer(k, 100);
    try testing.expectEqual(70, registry.get(k));
}

test "DriftRegistry: complex transfer (propagation)" {
    var registry: DriftRegistry = try .init(testing.allocator, 16);
    defer registry.deinit(testing.allocator);

    const a: DriftRegistry.Tid = 1;
    const b: DriftRegistry.Tid = 2;

    var global_ticks: u16 = 100;
    try registry.put(.clock(a), 100);
    try registry.put(.clock(b), 90);
    registry.prepareForTransfer(.clock(b), global_ticks);

    // b_ticks = a_ticks(100) - b_lag(10) + old_lag(0) = 90
    // old_lag = global(150) - a_ticks(100) = 50
    global_ticks = 150;
    try registry.transfer(.lag(a, b), global_ticks);
    try testing.expectEqual(90, registry.get(.clock(b)));
    try testing.expectEqual(50, registry.get(.lag(a, b)));

    global_ticks = 200;
    try registry.put(.clock(a), 120); // a_ticks = 120
    registry.prepareForTransfer(.clock(b), global_ticks); // b_lag = global(200) - b_tiks(90) = 110
    try testing.expectEqual(110, registry.get(.clock(b)));

    // b_ticks = a_ticks(120) - b_lag(110) + old_lag(50) = 60
    // old_lag = global(200) - from(120) = 80
    try registry.transfer(.lag(a, b), global_ticks);
    try testing.expectEqual(60, registry.get(.clock(b)));
    try testing.expectEqual(80, registry.get(.lag(a, b)));
}

test "DriftRegistry: grow and safety" {
    var registry: DriftRegistry = try .init(testing.allocator, 2);
    defer registry.deinit(testing.allocator);

    try registry.put(.clock(1), 10);
    try registry.put(.clock(2), 20);

    const old_pairs = try registry.grow(testing.allocator);
    testing.allocator.free(old_pairs);

    try testing.expectEqual(10, registry.get(.clock(1)));
    try testing.expectEqual(20, registry.get(.clock(2)));
}

test "DriftRegistry: copy basic functionality" {
    var registry: DriftRegistry = try .init(testing.allocator, 32);
    defer registry.deinit(testing.allocator);

    const a: DriftRegistry.Tid = 1;
    const b: DriftRegistry.Tid = 2;
    const c: DriftRegistry.Tid = 3;

    try registry.put(.clock(a), 100);
    try registry.put(.lag(a, c), 42);

    try registry.copy(.clock(a), .clock(b));

    try testing.expectEqual(100, registry.get(.clock(b)));
    try testing.expectEqual(42, registry.get(.lag(b, c)));
    try testing.expectEqual(100, registry.get(.clock(a)));
}

test "DriftRegistry: copy epoch filtration" {
    var registry: DriftRegistry = try .init(testing.allocator, 16);
    defer registry.deinit(testing.allocator);

    const a: DriftRegistry.Tid = 1;
    const b: DriftRegistry.Tid = 2;

    try registry.put(.clock(a), 10);

    registry.clear();

    try registry.copy(.clock(a), .clock(b));

    try testing.expectEqual(0, registry.get(.clock(b)));
}

test "DriftRegistry: copy overwrites/updates destination" {
    var registry: DriftRegistry = try .init(testing.allocator, 16);
    defer registry.deinit(testing.allocator);

    const a: DriftRegistry.Tid = 1;
    const b: DriftRegistry.Tid = 2;

    try registry.put(.clock(a), 100);
    try registry.put(.clock(b), 50);

    try registry.copy(.clock(a), .clock(b));

    try testing.expectEqual(100, registry.get(.clock(b)));
}

test "DriftRegistry: mid-copy exhaustion and recovery" {
    var registry: DriftRegistry = try .init(testing.allocator, 4);
    defer registry.deinit(testing.allocator);

    const a: DriftRegistry.Tid = 1;
    const b: DriftRegistry.Tid = 2;
    const c: DriftRegistry.Tid = 3;
    const d: DriftRegistry.Tid = 4;

    try registry.put(.clock(a), 10);
    try registry.put(.lag(a, c), 20);
    try registry.put(.lag(a, d), 30);

    const copy_err = registry.copy(.clock(a), .clock(b));
    try testing.expectError(error.NoSpace, copy_err);

    const old_pairs = try registry.grow(testing.allocator);
    testing.allocator.free(old_pairs);

    try registry.copy(.clock(a), .clock(b));

    try testing.expectEqual(10, registry.get(.clock(b)));
    try testing.expectEqual(20, registry.get(.lag(b, c)));
    try testing.expectEqual(30, registry.get(.lag(b, d)));

    try testing.expectEqual(10, registry.get(.clock(a)));
}

test "DriftRegistry: concurrent stress with growth and copies" {
    const Key = DriftRegistry.Key;
    const thread_count = 4;
    const ops_per_thread = 5_000;

    var registry: DriftRegistry = try .init(testing.allocator, 8);
    defer registry.deinit(testing.allocator);

    const Context = struct {
        clocks: *DriftRegistry,

        fn worker(ctx: *@This(), id: u32) void {
            var prng = std.Random.DefaultPrng.init(id);
            const rand = prng.random();

            const tid: DriftRegistry.Tid = @intCast(id + 100);
            const my_key = Key.clock(tid);

            ctx.clocks.put(my_key, 0) catch unreachable;

            for (0..ops_per_thread) |_| {
                const op = rand.uintLessThan(u8, 100);
                if (op < 35) {
                    _ = ctx.clocks.get(my_key);
                } else if (op < 70) {
                    _ = ctx.clocks.tick(my_key) catch continue;
                } else if (op < 95) {
                    ctx.clocks.put(my_key, @truncate(rand.int(u16))) catch {};
                } else {
                    const shadow_tid: DriftRegistry.Tid = @intCast(id + 200);
                    ctx.clocks.copy(my_key, Key.clock(shadow_tid)) catch {};
                }
            }
        }

        fn resizer(ctx: *@This()) void {
            for (0..10) |_| {
                std.Thread.yield() catch {};
                const old = ctx.clocks.grow(testing.allocator) catch continue;
                testing.allocator.free(old);
            }
        }
    };

    var ctx = Context{ .clocks = &registry };
    var threads: [thread_count]std.Thread = undefined;

    for (0..thread_count) |i| {
        threads[i] = try std.Thread.spawn(.{}, Context.worker, .{ &ctx, @as(u32, @truncate(i)) });
    }

    const resizer_thread = try std.Thread.spawn(.{}, Context.resizer, .{&ctx});

    for (threads) |t| t.join();
    resizer_thread.join();
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
