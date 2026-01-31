const std = @import("std");

const RefGate = struct {
    const lock_bit = @as(usize, 1) << (@bitSizeOf(usize) - 1);
    const references_mask = ~lock_bit;

    reference: std.atomic.Value(usize) align(std.atomic.cache_line) = .init(0),

    pub inline fn increment(this: *@This()) void {
        const ref = this.reference.fetchAdd(1, .acquire);
        std.debug.assert(ref & lock_bit != lock_bit - 1);
        if (ref & lock_bit != 0) {
            @branchHint(.cold);
            var reference = (this.reference.fetchSub(1, .monotonic) - 1) & references_mask;
            while (this.reference.cmpxchgWeak(reference, reference + 1, .acquire, .monotonic)) |new_ref| {
                std.debug.assert(new_ref & lock_bit != lock_bit - 1);
                reference = new_ref & references_mask;
                std.atomic.spinLoopHint();
            }
        }
    }

    pub inline fn decrement(this: *@This()) void {
        std.debug.assert(this.reference.fetchSub(1, .release) != 0);
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
        std.debug.assert(this.reference.fetchAnd(references_mask, .release) & lock_bit != 0);
    }
};

pub const ThreadsClock = struct {
    pub const Clock = struct {
        pub const Tick = usize;
        pub const empty_tick = @as(Tick, 1) << (@bitSizeOf(Tick) - 1);

        pub const empty: @This() = .{ .ticks = .init(empty_tick), .lag = .init(empty_tick) };

        const Field = enum {
            ticks,
            lag,
        };

        ticks: std.atomic.Value(Tick),
        lag: std.atomic.Value(Tick),

        pub fn get(this: *@This(), comptime field: Field) ?Tick {
            const v = switch (field) {
                .ticks => this.ticks.load(.monotonic),
                .lag => this.lag.load(.monotonic),
            };

            return if (v & empty_tick == 0) v else null;
        }

        pub fn put(this: *@This(), comptime field: Field, value: Tick) void {
            switch (field) {
                .ticks => this.ticks.store(value, .monotonic),
                .lag => this.lag.store(value, .monotonic),
            }
        }

        pub fn fetchAdd(this: *@This(), comptime field: Field, value: Tick) ?Tick {
            const v = switch (field) {
                .ticks => &this.ticks,
                .lag => &this.lag,
            };

            const ret = v.fetchAdd(value, .monotonic);
            if (ret & empty_tick != 0) {
                _ = v.cmpxchgStrong(ret, empty_tick, .monotonic, .monotonic);
                return null;
            }

            return ret;
        }
    };

    const block_len = @divExact(std.heap.page_size_min, @sizeOf(Clock));
    const Block = [block_len]Clock;

    const Indexes = struct {
        block: usize,
        element: std.meta.Int(.unsigned, std.math.log2(block_len)),
    };

    // Those pointers need to be atomic since two threads could be
    // trying to create the same block and we would find ourself with
    // an ivalid layout.
    //
    // Meanwhile the slice itself can use acquire/release semantic on
    // the ref_gate
    blocks: []std.atomic.Value(?*Block),
    ref_gate: RefGate,

    pub const init = @This(){ .blocks = &.{}, .ref_gate = .{} };

    fn getBlockAndItemIndex(at: std.os.linux.pid_t) Indexes {
        std.debug.assert(at > 0);
        const i: usize = @intCast(at);
        return .{ .block = @divFloor(i, block_len), .element = @intCast(i % block_len) };
    }

    fn unsafeGetPtr(this: *@This(), index: Indexes) ?*Clock {
        if (index.block >= this.blocks.len) return null;

        const block = this.blocks[index.block].load(.acquire) orelse return null;
        return &block[index.element];
    }

    pub fn put(this: *@This(), allocator: std.mem.Allocator, comptime field: Clock.Field, at: std.os.linux.pid_t, value: Clock.Tick) !void {
        const index = getBlockAndItemIndex(at);

        this.ref_gate.increment();
        defer this.ref_gate.decrement();

        if (index.block >= this.blocks.len) {
            const new_size = @max(index.block + 1, this.blocks.len * 2);
            this.ref_gate.decrement();
            try this.grow(allocator, new_size);
            this.ref_gate.increment();
        }

        const block = this.blocks[index.block].load(.acquire) orelse try this.createBlockUnsafe(allocator, index.block);
        block[index.element].put(field, value);
    }

    pub fn get(this: *@This(), comptime field: Clock.Field, at: std.os.linux.pid_t) ?Clock.Tick {
        const indexes = getBlockAndItemIndex(at);

        this.ref_gate.increment();
        defer this.ref_gate.decrement();

        const nullable_ptr = this.unsafeGetPtr(indexes);
        return if (nullable_ptr) |ptr| ptr.get(field) else null;
    }

    pub fn add(this: *@This(), comptime field: Clock.Field, at: std.os.linux.pid_t, operand: Clock.Tick) ?Clock.Tick {
        const indexes = getBlockAndItemIndex(at);

        this.ref_gate.increment();
        defer this.ref_gate.decrement();

        const nullable_ptr = this.unsafeGetPtr(indexes);
        return if (nullable_ptr) |ptr| v: {
            const old = ptr.fetchAdd(field, operand) orelse break :v null;
            break :v old + operand;
        } else null;
    }

    fn grow(this: *@This(), allocator: std.mem.Allocator, new_len: usize) !void {
        @branchHint(.cold);

        const new_blocks = try allocator.alloc(std.meta.Child(@TypeOf(this.blocks)), new_len);
        @memset(new_blocks, .{ .raw = null });

        this.ref_gate.close();

        const old_blocks = this.blocks;

        // Somebody else may have grown the array already
        if (new_len <= old_blocks.len) {
            @branchHint(.unlikely);
            this.ref_gate.open();
            allocator.free(new_blocks);
            return;
        }

        this.ref_gate.drain();

        @memcpy(new_blocks[0..old_blocks.len], old_blocks);
        this.blocks = new_blocks;

        this.ref_gate.open();

        allocator.free(old_blocks);
    }

    fn createBlockUnsafe(this: *@This(), allocator: std.mem.Allocator, block_index: usize) !*Block {
        @branchHint(.unlikely);

        this.ref_gate.decrement();
        const new_block = try allocator.create(Block);
        @memset(new_block, .empty);
        this.ref_gate.increment();

        return if (this.blocks[block_index].cmpxchgStrong(null, new_block, .release, .acquire)) |actual| blk: {
            @branchHint(.unlikely);

            this.ref_gate.decrement();
            defer this.ref_gate.increment();

            allocator.destroy(new_block);

            break :blk actual.?;
        } else new_block;
    }

    pub fn deinit(this: *@This(), allocator: std.mem.Allocator) void {
        for (this.blocks) |*block| {
            if (block.load(.monotonic)) |ptr| {
                allocator.destroy(ptr);
            }
        }

        allocator.free(this.blocks);
    }
};

pub fn Pool(Type: type) type {
    return struct {
        const pool_len = @bitSizeOf(usize);
        const alignment = @sizeOf(Type) * pool_len;

        entries: [pool_len]Type align(alignment),
        used_bitmask: std.atomic.Value(usize),
        context: std.atomic.Value(?*anyopaque),

        pub fn empty() @This() {
            return .{
                .entries = undefined,
                .used_bitmask = .init(0),
                .context = .init(null),
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

            std.debug.assert(this.used_bitmask.fetchAnd(freeing_bit, .release) & (~freeing_bit) != 0);
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
    try std.testing.expectEqual(1, gate.reference.load(.monotonic));
    gate.decrement();

    try std.testing.expectEqual(0, gate.reference.load(.monotonic));
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

    try std.testing.io.sleep(.fromMilliseconds(10), .real);
    try std.testing.expectEqual(false, ctx.entered.load(.acquire));

    gate.open();
    thread.join();

    try std.testing.expectEqual(true, ctx.entered.load(.acquire));
}

test "ThreadsClock: single thread functional" {
    const allocator = testing.allocator;
    var clock_vec = ThreadsClock.init;
    defer clock_vec.deinit(allocator);

    try clock_vec.put(allocator, .ticks, 10, 123);
    try clock_vec.put(allocator, .lag, 10, 456);

    try testing.expectEqual(@as(?usize, 123), clock_vec.get(.ticks, 10));
    try testing.expectEqual(@as(?usize, 456), clock_vec.get(.lag, 10));

    try testing.expectEqual(@as(?usize, null), clock_vec.get(.ticks, 11));

    const old = clock_vec.add(.ticks, 10, 7);
    try testing.expectEqual(@as(?usize, 130), old);
    try testing.expectEqual(@as(?usize, 130), clock_vec.get(.ticks, 10));

    try clock_vec.put(allocator, .ticks, 10000, 999);
    try testing.expectEqual(@as(?usize, 999), clock_vec.get(.ticks, 10000));
    try testing.expectEqual(@as(?usize, 130), clock_vec.get(.ticks, 10));
}

test "ThreadsClock: concurrent growth and access" {
    var ts_alloc = std.heap.ThreadSafeAllocator{ .child_allocator = testing.allocator };
    const allocator = ts_alloc.allocator();

    var clock_vec = ThreadsClock.init;
    defer clock_vec.deinit(allocator);

    const thread_count = 4;
    const items_per_thread = 500;

    const Context = struct {
        vec: *ThreadsClock,
        id: usize,
        alloc: std.mem.Allocator,

        fn run(ctx: *@This()) void {
            var i: usize = 1;
            while (i <= items_per_thread) : (i += 1) {
                const pid: std.os.linux.pid_t = @intCast((i * thread_count) + ctx.id);
                ctx.vec.put(ctx.alloc, .ticks, pid, @intCast(pid * 2)) catch unreachable;
            }
        }
    };

    var threads: [thread_count]std.Thread = undefined;
    var contexts: [thread_count]Context = undefined;

    for (0..thread_count) |i| {
        contexts[i] = .{ .vec = &clock_vec, .id = i, .alloc = allocator };
        threads[i] = try std.Thread.spawn(.{}, Context.run, .{&contexts[i]});
    }

    for (threads) |t| t.join();

    for (0..thread_count) |t_id| {
        var i: usize = 1;
        while (i <= items_per_thread) : (i += 1) {
            const pid: std.os.linux.pid_t = @intCast((i * thread_count) + t_id);
            const val = clock_vec.get(.ticks, pid);
            try testing.expectEqual(@as(usize, @intCast(pid * 2)), val.?);
        }
    }
}

test "Pool: basic alloc/free and pointer math" {
    const P = Pool(u64);
    var pool = P.empty();

    const ptr1 = pool.getEntry() orelse return error.TestUnexpectedFull;
    ptr1.* = 0xAAAA_BBBB;

    const parent = P.getPoolPtrFromEntryPtr(ptr1);
    try std.testing.expectEqual(&pool, parent);

    const ptr2 = pool.getEntry() orelse return error.TestUnexpectedFull;
    try std.testing.expect(ptr1 != ptr2);

    pool.freeEntry(ptr1);
}

test "Pool: exhaustion and capacity" {
    const P = Pool(u8);
    var pool = P.empty();
    var ptrs: [@bitSizeOf(usize)]*u8 = undefined;

    for (0..@bitSizeOf(usize)) |i| {
        ptrs[i] = pool.getEntry() orelse return error.TestUnexpectedFull;
    }

    try std.testing.expectEqual(null, pool.getEntry());

    pool.freeEntry(ptrs[0]);

    const new_ptr = pool.getEntry();
    try std.testing.expect(new_ptr != null);
    try std.testing.expectEqual(ptrs[0], new_ptr.?);
}

test "Pool: power of 2 struct alignment" {
    const Align16 = struct {
        data: [16]u8,
    };

    const P = Pool(Align16);
    var pool = P.empty();

    const ptr = pool.getEntry() orelse return error.TestUnexpectedFull;
    const parent = P.getPoolPtrFromEntryPtr(ptr);
    try std.testing.expectEqual(&pool, parent);
}

test "Pool: concurrent churn" {
    const P = Pool(usize);

    const pool = try std.testing.allocator.create(P);
    pool.* = .empty();
    defer std.testing.allocator.destroy(pool);

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

    try std.testing.expectEqual(@as(usize, 0), pool.used_bitmask.load(.monotonic));
}
