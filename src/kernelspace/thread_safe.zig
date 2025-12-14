const std = @import("std");

const DrainLock = struct {
    const lock_bit = @as(usize, 1) << 63;
    const references_mask = ~lock_bit;

    reference: std.atomic.Value(usize) = .init(0),

    pub fn increment(this: *@This()) void {
        var reference = this.reference.load(.monotonic) & references_mask;
        while (this.reference.cmpxchgWeak(reference, reference + 1, .acquire, .monotonic)) |new_ref| {
            reference = new_ref & references_mask;
            std.atomic.spinLoopHint();
        }
    }

    pub fn decrement(this: *@This()) void {
        _ = this.reference.fetchSub(1, .release);
    }

    pub fn lock(this: *@This()) void {
        var reference = this.reference.load(.monotonic) & references_mask;
        while (this.reference.cmpxchgWeak(reference, reference | lock_bit, .acquire, .monotonic)) |new_ref| {
            reference = new_ref & references_mask;
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(this: *@This()) void {
        _ = this.reference.fetchAnd(references_mask, .release);
    }

    pub fn waitDrain(this: @This()) void {
        while (this.reference.load(.acquire) & references_mask != 0) {
            std.atomic.spinLoopHint();
        }
    }
};

pub fn SegmentedSparseVector(Value: type) type {
    return struct {
        const ValueAtomic = std.atomic.Value(Value);
        const block_len = @divExact(4096, @sizeOf(ValueAtomic));

        const Block = [block_len]ValueAtomic;

        blocks: []std.atomic.Value(?*Block),
        references: DrainLock,

        pub const init = @This(){ .blocks = &.{}, .references = .{} };

        pub fn get(this: *@This(), at: usize) ?Value {
            const block_index = @divFloor(at, block_len);
            if (block_index >= this.blocks.len) return null;

            this.references.increment();
            defer this.references.decrement();

            const block = this.blocks[block_index].load(.monotonic) orelse return null;
            return block[at % block_len].load(.monotonic);
        }

        pub fn put(this: *@This(), allocator: std.mem.Allocator, at: usize, value: Value) !void {
            const block_index = @divFloor(at, block_len);

            this.references.increment();
            defer this.references.decrement();

            if (block_index >= this.blocks.len) {
                this.references.decrement();
                try this.grow(allocator, block_index + 1);
                this.references.increment();
            }

            const block = this.blocks[block_index].load(.monotonic) orelse try this.createBlock(allocator, block_index);
            block[at % block_len].store(value, .monotonic);
        }

        pub fn createBlock(this: *@This(), allocator: std.mem.Allocator, block_index: usize) !*Block {
            @branchHint(.unlikely);
            const new_block = try allocator.create(Block);

            this.references.increment();
            defer this.references.decrement();

            return if (this.blocks[block_index].cmpxchgStrong(null, new_block, .monotonic, .monotonic)) |actual| blk: {
                @branchHint(.cold);
                allocator.destroy(new_block);
                break :blk actual.?;
            } else new_block;
        }

        pub fn grow(this: *@This(), allocator: std.mem.Allocator, new_len: usize) !void {
            @branchHint(.cold);

            const new_blocks = try allocator.alloc(std.atomic.Value(?*Block), new_len);
            for (new_blocks) |*new_block| {
                new_block.store(null, .monotonic);
            }

            this.references.lock();
            this.references.waitDrain();

            const blocks = this.blocks;
            for (blocks, new_blocks[0..this.blocks.len]) |block, *new_block| {
                if (block.load(.monotonic)) |ptr| new_block.store(ptr, .monotonic);
            }
            this.blocks = new_blocks;

            this.references.unlock();

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
