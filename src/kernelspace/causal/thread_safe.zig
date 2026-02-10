const std = @import("std");
const assert = std.debug.assert;

const RefGate = struct {
    const lock_bit = @as(usize, 1) << (@bitSizeOf(usize) - 1);
    const references_mask = ~lock_bit;

    reference: std.atomic.Value(usize) align(std.atomic.cache_line) = .init(0),

    pub inline fn increment(this: *@This()) void {
        const ref = this.reference.fetchAdd(1, .acquire);
        assert(ref & lock_bit != lock_bit - 1);
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
/// - It is undefined behavior for multiple threads to concurrently insert
///   the same key when that key is not already present.
///
/// This is also a logical error: key claiming is only valid in two cases:
/// 1) Tid A created Tid B and transfers its clock to Tid B
///    (only one creator may exist).
/// 2) Tid A wakes Tid B and sets lag and a new clock
///    (only one thread may be responsible for the wake event).
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

    const Pair = struct {
        key: std.atomic.Value(Key),
        value: u32,

        const empty: @This() = .{ .key = .init(Key.empty), .value = undefined };
    };

    ref: RefGate,
    pairs: []Pair,

    pub fn init(allocator: std.mem.Allocator, reserve: usize) !@This() {
        assert(@popCount(reserve) == 1);

        const pairs = try allocator.alloc(Pair, reserve);
        @memset(pairs, Pair.empty);
        return .{ .ref = .{}, .pairs = pairs };
    }

    pub fn deinit(this: *@This(), allocator: std.mem.Allocator) void {
        this.ref.close();
        this.ref.drain();
        allocator.free(this.pairs);
    }

    pub fn put(this: *@This(), key: Key, value: u32) !void {
        const hash = key.hash();

        this.ref.increment();
        defer this.ref.decrement();

        try this.putUnsafe(key, hash, value);
    }

    fn putUnsafe(this: *@This(), key: Key, hash: u64, value: u32) !void {
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
            {
                this.pairs[index].value = value;
                this.pairs[index].key.store(key, .release);
                return;
            }

            _ = this.pairs[index].key.fetchOr(Key.empty_collided, .monotonic);
        }

        return error.NoSpace;
    }

    pub fn get(this: *@This(), key: Key) ?u32 {
        const hash = key.hash();

        this.ref.increment();
        defer this.ref.decrement();

        const len = this.pairs.len;

        assert(@popCount(len) == 1);
        const bitmask = len - 1;
        const max_retries = @max(16, len / 32);

        var local_key: Key = .empty_collided;
        var i: usize = 0;
        while (local_key.hasCollided() and i < max_retries) : (i += 1) {
            const index = (hash + i) & bitmask;
            local_key = this.pairs[index].key.load(.acquire);

            if (local_key.eql(key)) return this.pairs[index].value;
        }

        return null;
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

        for (old_pairs) |pair| {
            const key = pair.key.load(.unordered);
            const hash = key.hash();
            if (!key.eql(.empty)) {
                try this.putUnsafe(key, hash, pair.value);
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

    var i: i32 = 0;
    while (i < 100) : (i += 1) {
        try clocks.put(Key.clock(i), @intCast(i * 10));
    }

    i = 0;
    while (i < 100) : (i += 1) {
        const val = clocks.get(Key.clock(i));
        try testing.expectEqual(@as(u32, @intCast(i * 10)), val.?);
    }
}

test "ThreadLocalClock: grow data preservation and memory return" {
    const Key = TidClocks.Key;

    var clocks = try TidClocks.init(testing.allocator, 16);
    var i: u32 = 1;
    while (i < 9) : (i += 1) {
        try clocks.put(Key.clock(@intCast(i)), i * 10);
    }

    const old_pairs = try clocks.grow(testing.allocator);

    testing.allocator.free(old_pairs);

    i = 1;
    for (clocks.pairs) |pair| {
        if (!pair.key.load(.acquire).eql(.empty)) {}
    }
    while (i < 9) : (i += 1) {
        const val = clocks.get(Key.clock(@intCast(i)));
        try testing.expectEqual(i * 10, val.?);
    }

    try testing.expectEqual(@as(usize, 32), clocks.pairs.len);

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

    var i: u32 = 0;
    var failed = false;
    while (i < 5) : (i += 1) {
        clocks.put(Key.clock(@intCast(i)), i) catch {
            failed = true;
            break;
        };
    }

    try testing.expect(failed);

    const old_pairs = try clocks.grow(testing.allocator);
    testing.allocator.free(old_pairs);

    try clocks.put(Key.clock(100), 100);
    try testing.expectEqual(@as(u32, 100), clocks.get(Key.clock(100)).?);
}

test "TidClocks: concurrent put/get" {
    const Key = TidClocks.Key;

    var clocks = try TidClocks.init(testing.allocator, 4096);
    defer clocks.deinit(testing.allocator);

    const thread_count = 4;
    const items_per_thread = 500;

    const Context = struct {
        clocks: *TidClocks,
        id: i32,
        fn run(ctx: @This()) void {
            var i: i32 = 0;
            const start = ctx.id * items_per_thread;

            while (i < items_per_thread) : (i += 1) {
                const key_val = start + i;
                ctx.clocks.put(Key.clock(key_val), @intCast(key_val)) catch unreachable;
            }

            i = 0;
            while (i < items_per_thread) : (i += 1) {
                const key_val = start + i;
                const val = ctx.clocks.get(Key.clock(key_val));
                assert(val != null and val.? == @as(u32, @intCast(key_val)));
            }
        }
    };

    var threads: [thread_count]std.Thread = undefined;
    for (0..thread_count) |i| {
        threads[i] = try std.Thread.spawn(.{}, Context.run, .{Context{ .clocks = &clocks, .id = @intCast(i) }});
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
