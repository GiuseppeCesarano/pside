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
    pub const Tid = std.os.linux.pid_t;
    pub const Ticks = u32;

    pub const Key = packed struct {
        data: Tid,

        const bit_size = @bitSizeOf(@This());
        const Unsigned = std.meta.Int(.unsigned, bit_size);
        const collided_bit: Tid = @bitCast(@as(Unsigned, 1 << bit_size - 1));

        pub const empty: @This() = .{ .data = 0 };
        pub const empty_collided: @This() = @bitCast(collided_bit);
        pub const reserved: @This() = @bitCast(std.math.maxInt(Unsigned) & ~collided_bit);

        pub fn isEql(this: Key, other: Key) bool {
            return (this | collided_bit) == (other | collided_bit);
        }

        pub fn hasCollided(this: Key) bool {
            return (this & collided_bit) != 0;
        }

        pub fn fromTid(tid: Tid) @This() {
            return .{ .data = tid };
        }

        pub fn hash(this: @This()) usize {
            return @bitCast(std.hash.int(this.data));
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

    pub const Value = union(Ticks) {
        ticks: Ticks,
        lag: Ticks,
    };

    const Pair = struct {
        key: std.atomic.Value(Key),
        value: std.atomic.Value(Value),

        const empty: @This() = .{ .key = .init(.empty), .value = undefined };
    };

    master: std.atomic.Value(Ticks) align(std.atomic.cache_line),
    ref: RefGate,
    pairs: []Pair,

    pub fn init(allocator: std.mem.Allocator, reserve: usize) !@This() {
        assert(@popCount(reserve) == 1);

        const pairs = try allocator.alloc(Pair, reserve);
        @memset(pairs, Pair.empty);
        return .{ .ref = .{}, .pairs = pairs, .master = .init(0) };
    }

    pub fn deinit(this: *@This(), allocator: std.mem.Allocator) void {
        this.ref.close();
        this.ref.drain();
        allocator.free(this.pairs);
    }

    fn reserveSlotUnsafe(this: *@This(), hash: usize) !*Pair {
        const len = this.pairs.len;

        assert(@popCount(len) == 1);
        const bitmask = len - 1;
        const max_retries = @max(16, len / 32);

        var i: usize = 0;
        while (i < max_retries) : (i += 1) {
            const index = (hash + i) & bitmask;
            const key = this.pairs[index].key.load(.monotonic);

            if (key.isEql(.empty) and
                this.pairs[index].key.cmpxchgStrong(.empty, .reserved, .acquire, .monotonic) == null)
                return &this.pairs[index];

            if (!key.hasCollided())
                _ = this.pairs[index].key.fetchOr(Key.empty_collided, .monotonic);
        }

        return error.NoSpace;
    }

    fn getSlotUnsafe(this: *@This(), tid: Key, hash: usize) *Pair {
        const len = this.pairs.len;

        assert(@popCount(len) == 1);
        const bitmask = len - 1;
        const max_retries = @max(16, len / 32);

        var i: usize = 0;
        var current_key: Key = .empty_collided;
        return slot: while (current_key.hasCollided() and i < max_retries) : (i += 1) {
            const index = (hash + i) & bitmask;
            current_key = this.pairs[index].key.load(.acquire);
            if (current_key.isEql(tid)) break :slot &this.pairs[index];
        } else unreachable;
        // Somehow we required a tid that has no entry.
        // This would be faulty logic in the algorithm implementation
        // so we use unreachable to catch that in the tests.
    }

    pub fn put(this: *@This(), tid: Key, ticks: u32) !void {
        const hash = tid.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const slot = try this.reserveSlotUnsafe(hash);

        slot.value.store(.{ .ticks = ticks }, .monotonic);
        _ = slot.key.fetchAnd(tid.withCollisionBit(), .release);
    }

    pub fn get(this: *@This(), tid: Key, field: enum { ticks, lag }) u32 {
        const hash = tid.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const slot = this.getSlotUnsafe(tid, hash);
        const value = slot.value.load(.monotonic);

        return if (field == .ticks) value.ticks else value.lag;
    }

    pub fn tick(this: *@This(), tid: Key) !void {
        const hash = tid.hash();

        try this.ref.tryIncrement();
        defer this.ref.decrement();

        const slot = this.getSlotUnsafe(tid, hash);
        const value_as_ticks: *std.atomic.Value(Ticks) = &slot.value;
        const ticks = value_as_ticks.fetchAdd(1, .monotonic) + 1;

        _ = this.master.fetchMax(ticks, .release);
    }

    pub fn prepareForSleep(this: *@This(), tid: Key) void {
        this.ref.increment();
        defer this.ref.decrement();

        const slot = this.getSlotUnsafe(tid, tid.hash());
        const ticks = slot.value.load(.monotonic).ticks;
        const master = this.master.load(.acquire);

        slot.value.store(.{ .lag = master - ticks }, .monotonic);
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

        const waker_ticks = waker_slot.value.load(.monotonic).ticks;
        const wakee_lag = wakee_slot.value.load(.monotonic).lag;
        const master = this.master.load(.acquire);

        waker_slot.value.store(.{ .ticks = master }, .monotonic);
        wakee_slot.value.store(.{ .ticks = master }, .monotonic);

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
        const child_slot = try this.reserveSlotUnsafe(child_hash);

        const parent_ticks = parent_slot.value.load(.monotonic).ticks;
        const master = this.master.load(.acquire);

        parent_slot.value.store(.{ .ticks = master }, .monotonic);
        child_slot.value.store(.{ .ticks = master }, .monotonic);

        _ = child_slot.key.fetchAnd(child.withCollisionBit(), .release);

        return master - parent_ticks;
    }

    pub fn grow(this: *@This(), allocator: std.mem.Allocator) ![]Pair {
        this.ref.increment();
        const new_len = this.pairs.len * 2;
        this.ref.decrement();

        assert(@popCount(new_len) == 1);
        const new_pairs = try allocator.alloc(Pair, new_len);
        @memset(new_pairs, Pair.empty);

        this.ref.close();
        defer this.ref.open();

        const old_pairs = this.pairs;

        this.ref.drain();
        this.pairs = new_pairs;

        const bitmask = new_len - 1;
        const max_retries = @max(16, new_len / 32);
        for (old_pairs) |pair| {
            const key = pair.key.load(.unordered).withoutCollisionBit();
            if (key != .empty) {
                const value = pair.value.load(.unordered);
                const hash = key.hash();

                var i: usize = 0;
                while (i < max_retries) : (i += 1) {
                    const index = (hash + i) & bitmask;

                    if (new_pairs[index].key.load(.unordered).isEql(.empty)) {
                        new_pairs[index] = .{ .key = .init(key), .value = .init(value) };
                        break;
                    }
                    new_pairs[index].key.fetchOr(.empty_collided, .unordered);
                } else return error.NoSpace;
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
