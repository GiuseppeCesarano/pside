// TODO: check those logics once again
const std = @import("std");

const RefGate = struct {
    const lock_bit = @as(usize, 1) << (@bitSizeOf(usize) - 1);
    const references_mask = ~lock_bit;

    reference: std.atomic.Value(usize) = .init(0),

    pub fn increment(this: *@This()) void {
        if (this.reference.fetchAdd(1, .acquire) & lock_bit != 0) {
            @branchHint(.unlikely);
            var reference = this.reference.fetchSub(1, .monotonic) & references_mask;
            while (this.reference.cmpxchgWeak(reference, reference + 1, .acquire, .monotonic)) |new_ref| {
                reference = new_ref & references_mask;
                std.atomic.spinLoopHint();
            }
        }
    }

    pub fn decrement(this: *@This()) void {
        _ = this.reference.fetchSub(1, .release);
    }

    pub fn close(this: *@This()) void {
        var reference = this.reference.load(.monotonic) & references_mask;
        while (this.reference.cmpxchgWeak(reference, reference | lock_bit, .acquire, .monotonic)) |new_ref| {
            reference = new_ref & references_mask;
            std.atomic.spinLoopHint();
        }
    }

    pub fn open(this: *@This()) void {
        _ = this.reference.fetchAnd(references_mask, .release);
    }

    pub fn waitZero(this: @This()) void {
        while (this.reference.load(.acquire) & references_mask != 0) {
            std.atomic.spinLoopHint();
        }
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

            const block = this.blocks[block_index].load(.monotonic) orelse return null;
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

            const block = this.blocks[block_index].load(.monotonic) orelse try this.createBlock(allocator, block_index);
            block[at % block_len].store(value, .monotonic);
        }

        fn createBlock(this: *@This(), allocator: std.mem.Allocator, block_index: usize) !*Block {
            @branchHint(.unlikely);
            const new_block = try allocator.create(Block);
            @memset(new_block, .{ .raw = empty_value });

            this.ref_gate.increment();
            defer this.ref_gate.decrement();

            return if (this.blocks[block_index].cmpxchgStrong(null, new_block, .monotonic, .monotonic)) |actual| blk: {
                @branchHint(.unlikely);
                allocator.destroy(new_block);
                break :blk actual.?;
            } else new_block;
        }

        fn grow(this: *@This(), allocator: std.mem.Allocator, new_len: usize) !void {
            @branchHint(.unlikely);

            const new_blocks = try allocator.alloc(std.meta.Child(@TypeOf(this.blocks)), new_len);
            for (new_blocks) |*new_block| {
                new_block.store(null, .monotonic);
            }

            this.ref_gate.close();
            this.ref_gate.waitZero();

            const blocks = this.blocks;

            // Somebody else may have grown the array already
            if (new_len <= blocks.len) {
                @branchHint(.unlikely);
                this.ref_gate.open();
                allocator.free(new_blocks);
                return;
            }

            @memcpy(blocks, new_blocks[0..this.blocks.len]);
            this.blocks = new_blocks;

            this.ref_gate.open();

            allocator.free(blocks);
        }

        pub fn deinit(this: *@This(), allocator: std.mem.Allocator) void {
            for (this.blocks) |*block| {
                if (block.load(.monotonic)) |ptr| allocator.destroy(ptr);
            }

            allocator.free(this.blocks);
        }
    };
}

/// This will thorow away top three bits of the key.
pub fn AddressMap(Value: type, empty_value: Value) type {
    return struct {
        const Key = usize;
        const KeyWithMetadata = packed struct {
            pub const empty: @This() = .{ .full = 0, .collided = 0, .key = 0 };
            pub const collided_bit: @This() = .{ .full = 0, .collided = 1, .key = 0 };

            full: u1,
            collided: u1,
            key: std.meta.Int(.unsigned, @bitSizeOf(usize) - 2),
        };

        const hash = std.hash.int;

        keys_with_metadata: []std.atomic.Value(KeyWithMetadata),
        values: [*]std.atomic.Value(Value),
        capacity: std.atomic.Value(usize),

        ref_gate: RefGate,

        pub const init: @This() = .{ .keys_with_metadata = &.{}, .values = undefined, .capacity = .init(1), .ref_gate = .{} };

        pub fn deinit(this: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(this.values[0..this.keys_with_metadata.len]);
            allocator.free(this.keys_with_metadata);
        }

        pub fn get(this: *@This(), key: Key) ?Value {
            const hashed_key = hash(key);

            this.ref_gate.increment();
            defer this.ref_gate.decrement();

            const key_index = hashed_key & (this.keys_with_metadata.len - 1);

            const value_index = blk: inline for ([2]usize{ key_index, 0 }) |i| {
                for (this.keys_with_metadata[i..], i..) |key_and_metadata, index| {
                    const k_n_m = key_and_metadata.load(.monotonic);
                    if (k_n_m.key == key) if (k_n_m.full == 1) break :blk index;
                    if (k_n_m.collided != 1) return null;
                }
            } else return null;

            // We may load between key write and value write
            const v = this.values[value_index].load(.monotonic);
            return if (v != empty_value) v else null;
        }

        pub fn put(this: *@This(), allocator: std.mem.Allocator, key: Key, value: Value) !void {
            if (this.capacity.fetchSub(1, .monotonic) == 0) try this.grow(allocator);
            const hashed_key = hash(key);

            this.ref_gate.increment();
            this.putUnsafe(key, hashed_key, value);
            this.ref_gate.decrement();
        }

        fn putUnsafe(this: *@This(), key: Key, hashed_key: Key, value: Value) void {
            const key_index = hashed_key & (this.keys_with_metadata.len - 1);
            const new_key_data: KeyWithMetadata = .{
                .full = 1,
                .collided = 0,
                .key = @truncate(key),
            };

            inline for ([2]usize{ key_index, 0 }) |i| {
                for (this.keys_with_metadata[i..], this.values[i..]) |*stored_key, *stored_value| {
                    if (stored_key.cmpxchgStrong(KeyWithMetadata.empty, new_key_data, .monotonic, .monotonic) == null) {
                        @branchHint(.likely);
                        stored_value.store(value, .monotonic);
                        return;
                    }
                    _ = stored_key.fetchOr(KeyWithMetadata.collided_bit, .monotonic);
                }
            }
        }

        pub fn grow(this: *@This(), allocator: std.mem.Allocator) !void {
            @branchHint(.unlikely);

            this.ref_gate.increment();
            const new_len = @max(this.keys_with_metadata.len * 2, 256);
            this.ref_gate.decrement();

            const new_keys = try allocator.alloc(std.meta.Child(@TypeOf(this.keys_with_metadata)), new_len);
            @memset(new_keys, .{ .raw = KeyWithMetadata.empty });

            const ValueChild = std.meta.Child(@TypeOf(this.values));
            const new_values = try allocator.alloc(ValueChild, new_len);
            @memset(new_values, .{ .raw = empty_value });

            this.ref_gate.close();
            this.ref_gate.waitZero();

            if (new_len <= this.keys_with_metadata.len) {
                @branchHint(.unlikely);
                this.ref_gate.open();
                allocator.free(new_values);
                allocator.free(new_keys);
            }

            const old_keys = this.keys_with_metadata;
            const old_values = this.values;
            this.capacity.store(new_len - old_keys.len, .monotonic);

            this.keys_with_metadata = new_keys;
            this.values = @ptrCast(new_values.ptr);

            for (old_keys, old_values) |*old_key, *old_value| {
                const k = old_key.load(.monotonic).key;
                this.putUnsafe(@intCast(k), hash(k), old_value.load(.monotonic));
            }

            this.ref_gate.open();

            if (old_keys.len > 0) {
                allocator.free(old_values[0..old_keys.len]);
                allocator.free(old_keys);
            }
        }
    };
}
