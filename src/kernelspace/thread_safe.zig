const std = @import("std");

const RefGate = struct {
    const lock_bit = @as(usize, 1) << (@bitSizeOf(usize) - 1);
    const references_mask = ~lock_bit;

    reference: std.atomic.Value(usize) = .init(0),

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

    pub inline fn waitAllReferenceDecrement(this: *@This()) void {
        while ((this.reference.load(.acquire) & references_mask) != 0) {
            std.atomic.spinLoopHint();
        }
    }

    pub inline fn open(this: *@This()) void {
        std.debug.assert(this.reference.fetchAnd(references_mask, .release) & lock_bit != 0);
    }
};

pub fn SegmentedSparseVector(Value: type, empty_value: Value) type {
    return struct {
        const ValueAtomic = std.atomic.Value(Value);
        const block_len = @divExact(4096, @sizeOf(ValueAtomic));

        const Block = [block_len]ValueAtomic;

        // Those pointers need to be atomic since two threads could be
        // trying to create the same block and we would find ourself with
        // an ivalid layout.
        //
        // Meanwhile the slice itself can use acquire/release semantic on
        // the ref_gate
        blocks: []std.atomic.Value(?*Block),
        ref_gate: RefGate,

        pub const init = @This(){ .blocks = &.{}, .ref_gate = .{} };

        pub fn get(this: *@This(), at: usize) ?Value {
            const block_index = @divFloor(at, block_len);
            if (block_index >= this.blocks.len) return null;

            this.ref_gate.increment();
            defer this.ref_gate.decrement();

            const block = this.blocks[block_index].load(.acquire) orelse return null;
            const ret = block[at % block_len].load(.monotonic);

            return if (ret != empty_value) ret else null;
        }

        pub fn put(this: *@This(), allocator: std.mem.Allocator, at: usize, value: Value) !void {
            const block_index = @divFloor(at, block_len);

            this.ref_gate.increment();
            defer this.ref_gate.decrement();

            if (block_index >= this.blocks.len) {
                this.ref_gate.decrement();
                try this.grow(allocator, block_index + 1);
                this.ref_gate.increment();
            }

            const block = this.blocks[block_index].load(.acquire) orelse try this.createBlockUnsafe(allocator, block_index);
            block[at % block_len].store(value, .monotonic);
        }

        fn grow(this: *@This(), allocator: std.mem.Allocator, new_len: usize) !void {
            @branchHint(.unlikely);

            const new_blocks = try allocator.alloc(std.meta.Child(@TypeOf(this.blocks)), new_len);
            for (new_blocks) |*new_block| {
                new_block.store(null, .monotonic);
            }

            this.ref_gate.close();

            const blocks = this.blocks;

            // Somebody else may have grown the array already
            if (new_len <= blocks.len) {
                @branchHint(.unlikely);
                this.ref_gate.open();
                allocator.free(new_blocks);
                return;
            }

            this.ref_gate.waitAllReferenceDecrement();

            @memcpy(new_blocks[0..this.blocks.len], blocks);
            this.blocks = new_blocks;

            this.ref_gate.open();

            allocator.free(blocks);
        }

        fn createBlockUnsafe(this: *@This(), allocator: std.mem.Allocator, block_index: usize) !*Block {
            @branchHint(.unlikely);
            this.ref_gate.decrement();
            const new_block = try allocator.create(Block);
            for (new_block) |*value| value.store(empty_value, .unordered);
            this.ref_gate.increment();

            // Release the unrdered stores in the blocks.
            return if (this.blocks[block_index].cmpxchgStrong(null, new_block, .release, .acquire)) |actual| blk: {
                @branchHint(.unlikely);
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
}

/// This will thorow away top two bits of the key.
pub fn AddressMap(Value: type, empty_value: Value) type {
    return struct {
        const Key = usize;
        const KeyWithMetadata = packed struct {
            pub const empty_bit: @This() = .{ .full = 0, .collided = 0, .key = 0 };
            pub const collided_bit: @This() = .{ .full = 0, .collided = 1, .key = 0 };

            full: u1,
            collided: u1,
            key: std.meta.Int(.unsigned, @bitSizeOf(usize) - 2),
        };
        const KeyWithMetadataAtomic = std.atomic.Value(KeyWithMetadata);

        fn hash(in: Key) Key {
            return std.hash.int(in);
        }

        keys_with_metadata: []KeyWithMetadataAtomic,
        values: [*]std.atomic.Value(Value),
        capacity: std.atomic.Value(isize),

        ref_gate: RefGate,

        pub const init: @This() = .{ .keys_with_metadata = &.{}, .values = undefined, .capacity = .init(0), .ref_gate = .{} };

        pub fn deinit(this: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(this.values[0..this.keys_with_metadata.len]);
            allocator.free(this.keys_with_metadata);
        }

        pub fn getPtr(this: *@This(), key: Key) ?*std.atomic.Value(Value) {
            const hashed_key = hash(key);

            this.ref_gate.increment();
            defer this.ref_gate.decrement();

            var i: usize = 0;
            const len = this.keys_with_metadata.len;
            std.debug.assert(@popCount(len) <= 1);
            const offset = hashed_key & (len -| 1);
            const value_index = search: while (i < len) : (i += 1) {
                const index = (i + offset) & (len - 1);
                const entry = this.keys_with_metadata[index].load(.monotonic);
                if (entry.key == key) break :search if (entry.full == 1) index else null;
                if (entry.collided != 1) break :search null;
            } else null;

            return if (value_index) |index| &this.values[index] else null;
        }

        pub fn get(this: *@This(), key: Key) ?Value {
            const v = if (this.getPtr(key)) |ptr| ptr.load(.monotonic) else return null;
            return if (v != empty_value) v else null;
        }

        pub fn put(this: *@This(), allocator: std.mem.Allocator, key: Key, value: Value) !void {
            while (this.capacity.fetchSub(1, .monotonic) <= 1) try this.growExponential(allocator);

            const hashed_key = hash(key);

            this.ref_gate.increment();
            this.putUnsafe(key, hashed_key, value);
            this.ref_gate.decrement();
        }

        fn putUnsafe(this: *@This(), key: Key, hashed_key: Key, value: Value) void {
            const new_key_data: KeyWithMetadata = .{
                .full = 1,
                .collided = 0,
                .key = @truncate(key),
            };

            var i: usize = 0;
            const len = this.keys_with_metadata.len;
            std.debug.assert(@popCount(len) <= 1);
            const offset = hashed_key & (len - 1);
            while (i < len) : (i += 1) {
                const index = (i + offset) & (len - 1);
                if (this.keys_with_metadata[index].cmpxchgStrong(KeyWithMetadata.empty_bit, new_key_data, .monotonic, .monotonic) == null) {
                    this.values[index].store(value, .monotonic);
                    return;
                }
                _ = this.keys_with_metadata[index].fetchOr(KeyWithMetadata.collided_bit, .monotonic);
            }
        }

        pub fn growExponential(this: *@This(), allocator: std.mem.Allocator) !void {
            @branchHint(.unlikely);

            this.ref_gate.increment();
            const len = this.keys_with_metadata.len;
            std.debug.assert(@popCount(len) <= 1);
            const new_len = @max(len << 1, 256);
            this.ref_gate.decrement();

            const new_keys_with_metadata = try allocator.alloc(std.meta.Child(@TypeOf(this.keys_with_metadata)), new_len);
            for (new_keys_with_metadata) |*new_key| new_key.store(KeyWithMetadata.empty_bit, .unordered);

            const new_values = try allocator.alloc(std.meta.Child(@TypeOf(this.values)), new_len);
            for (new_values) |*new_value| new_value.store(empty_value, .unordered);

            this.ref_gate.close();

            const old_keys_with_metadata = this.keys_with_metadata;
            const old_values = this.values;

            if (new_len <= old_keys_with_metadata.len) {
                @branchHint(.unlikely);
                this.ref_gate.open();
                allocator.free(new_values);
                allocator.free(new_keys_with_metadata);
                return;
            }

            this.ref_gate.waitAllReferenceDecrement();

            this.capacity.store(@intCast(new_len - old_keys_with_metadata.len), .monotonic);

            this.keys_with_metadata = new_keys_with_metadata;
            this.values = @ptrCast(new_values.ptr);

            for (old_keys_with_metadata, old_values) |*old_kwm, *old_value| {
                const kwm = old_kwm.load(.monotonic);
                if (kwm.full == 1) this.putUnsafe(kwm.key, hash(kwm.key), old_value.load(.monotonic));
            }

            this.ref_gate.open();

            if (old_keys_with_metadata.len > 0) {
                allocator.free(old_values[0..old_keys_with_metadata.len]);
                allocator.free(old_keys_with_metadata);
            }
        }
    };
}

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

test "SparseVector: single thread functional" {
    const Vector = SegmentedSparseVector(u32, std.math.maxInt(u32));
    var vec = Vector.init;
    defer vec.deinit(std.testing.allocator);

    try vec.put(std.testing.allocator, 10, 123);
    try std.testing.expectEqual(123, vec.get(10));
    try std.testing.expectEqual(null, vec.get(11));

    try vec.put(std.testing.allocator, 5000, 999);
    try std.testing.expectEqual(123, vec.get(10));
    try std.testing.expectEqual(null, vec.get(11));

    try std.testing.expectEqual(999, vec.get(5000));
}

test "SparseVector: concurrent growth and access" {
    var allocator_status = std.heap.ThreadSafeAllocator{ .child_allocator = std.testing.allocator };
    const allocator = allocator_status.allocator();

    const Vector = SegmentedSparseVector(usize, std.math.maxInt(usize));
    var vec = Vector.init;
    defer vec.deinit(allocator);

    const thread_count = 4;
    const items_per_thread = 100_000;

    const Context = struct {
        vec: *Vector,
        id: usize,
        fn run(ctx: @This(), alloc: std.mem.Allocator) !void {
            var i: usize = 0;
            while (i < items_per_thread) : (i += 1) {
                const index = (i * thread_count) + ctx.id;
                try ctx.vec.put(alloc, index, index * 10);
            }
        }
    };

    var threads: [thread_count]std.Thread = undefined;
    for (0..thread_count) |i| {
        threads[i] = try std.Thread.spawn(.{}, Context.run, .{ Context{ .vec = &vec, .id = i }, allocator });
    }

    for (threads) |t| t.join();

    for (0..thread_count) |t_id| {
        for (0..items_per_thread) |i| {
            const index = (i * thread_count) + t_id;
            const val = vec.get(index);
            try std.testing.expectEqual(index * 10, val.?);
        }
    }
}

test "AddressMap: single thread functional" {
    var map = AddressMap(u64, std.math.maxInt(u64)).init;
    defer map.deinit(std.testing.allocator);

    try std.testing.expectEqual(null, map.get(999));

    var i: usize = 0;
    while (i < 3000) : (i += 1) {
        try map.put(std.testing.allocator, i, i * 100);
    }

    i = 0;
    while (i < 3000) : (i += 1) {
        try std.testing.expectEqual(i * 100, map.get(i).?);
    }
}

test "AddressMap: concurrent stress test" {
    var allocator_status = std.heap.ThreadSafeAllocator{ .child_allocator = std.testing.allocator };
    const allocator = allocator_status.allocator();

    const Map = AddressMap(u64, std.math.maxInt(u64));
    var map = Map.init;
    defer map.deinit(allocator);
    const thread_count = 4;
    const ops_per_thread = 10000;

    const Context = struct {
        map: *Map,
        offset: usize,
        fn run(ctx: @This(), alloc: std.mem.Allocator) !void {
            var i: usize = 0;
            while (i < ops_per_thread) : (i += 1) {
                const key = ctx.offset + i;
                try ctx.map.put(alloc, key, key * 2);
            }
        }
    };

    var threads: [thread_count]std.Thread = undefined;
    for (0..thread_count) |i| {
        threads[i] = try std.Thread.spawn(.{}, Context.run, .{ Context{ .map = &map, .offset = i * ops_per_thread }, allocator });
    }

    for (threads) |t| t.join();

    for (0..thread_count) |t_id| {
        for (0..ops_per_thread) |i| {
            const key = (t_id * ops_per_thread) + i;
            const val = map.get(key);
            try std.testing.expectEqual(key * 2, val.?);
        }
    }
}
