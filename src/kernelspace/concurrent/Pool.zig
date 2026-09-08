const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub fn Pool(Type: type) type {
    return struct {
        const pool_len = @bitSizeOf(usize);

        entries: [pool_len]Type,
        free_bitmask: std.atomic.Value(usize) align(std.atomic.cache_line),
        next: std.atomic.Value(?*@This()),

        pub const empty: @This() = .{ .entries = undefined, .free_bitmask = .init(std.math.maxInt(usize)), .next = .init(null) };

        fn tryClaimEntry(this: *@This()) ?*Type {
            var free = this.free_bitmask.load(.monotonic);
            return for (0..5) |_| {
                if (free == 0) break null;

                const target_bit = free & -%free;
                const mask = ~target_bit;
                free = this.free_bitmask.fetchAnd(mask, .acquire);

                if ((free & target_bit) != 0) {
                    @branchHint(.likely);
                    const slot = @ctz(target_bit);
                    break &this.entries[slot];
                }
            } else null;
        }

        pub fn getEntry(this: *@This()) ?*Type {
            var pool: ?*@This() = this;

            return while (pool) |p| : (pool = p.next.load(.monotonic)) {
                if (p.tryClaimEntry()) |entry| break entry;
            } else null;
        }

        pub fn freeEntry(this: *@This(), entry_ptr: *anyopaque) void {
            var pool: ?*@This() = this;
            const entry_address = @intFromPtr(entry_ptr);

            // Range-check before dividing: pool nodes are independent heap
            // allocations, so the address gap to a non-owning node's `entries`
            // is not generally a multiple of @sizeOf(Type), and @divExact on
            // that gap would panic instead of just falling through to `next`.
            const position = while (pool) |p| : (pool = p.next.load(.monotonic)) {
                const base = @intFromPtr(&p.entries);
                const span = pool_len * @sizeOf(Type);
                if (entry_address >= base and entry_address - base < span)
                    break @divExact(entry_address - base, @sizeOf(Type));
            } else unreachable;

            const freeing_bit = @as(usize, 1) << @truncate(position);

            assert(pool.?.free_bitmask.fetchOr(freeing_bit, .release) & freeing_bit == 0);
        }

        pub fn appendPool(this: *@This(), new_pool: *@This()) void {
            var pool: ?*@This() = this;
            while (pool) |p| pool = p.next.cmpxchgStrong(null, new_pool, .monotonic, .monotonic) orelse null;
        }
    };
}

test "Pool: basic alloc/free and pointer math" {
    const P = Pool(u64);
    var pool: P = .empty;

    const ptr1 = pool.getEntry() orelse return error.TestUnexpectedFull;
    ptr1.* = 0xAAAA_BBBB;

    const ptr2 = pool.getEntry() orelse return error.TestUnexpectedFull;
    try testing.expect(ptr1 != ptr2);

    pool.freeEntry(ptr1);
}

test "Pool: exhaustion and capacity" {
    const P = Pool(u8);
    var pool: P = .empty;
    var ptrs: [@bitSizeOf(usize)]*u8 = undefined;

    for (&ptrs) |*ptr| ptr.* = pool.getEntry() orelse return error.TestUnexpectedFull;

    try testing.expectEqual(null, pool.getEntry());

    pool.freeEntry(ptrs[0]);

    const new_ptr = pool.getEntry();
    try testing.expectEqual(ptrs[0], new_ptr.?);
}

test "Pool: freeing an entry from a grown (second) node" {
    const P = Pool([41]u8);

    const head = try testing.allocator.create(P);
    head.* = .empty;
    defer testing.allocator.destroy(head);

    const second = try testing.allocator.create(P);
    second.* = .empty;
    defer testing.allocator.destroy(second);

    head.appendPool(second);

    var head_ptrs: [P.pool_len]*[41]u8 = undefined;
    for (&head_ptrs) |*p| p.* = head.getEntry().?;

    const from_second = head.getEntry().?;
    try testing.expect(@intFromPtr(from_second) >= @intFromPtr(&second.entries));

    head.freeEntry(from_second);
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
                } else std.atomic.spinLoopHint();
            }
        }
    };

    var threads: [thread_count]std.Thread = undefined;
    for (&threads, 0..) |*thread, i| thread.* = try .spawn(.{}, Context.run, .{Context{ .p = pool, .id = i }});

    for (threads) |t| t.join();

    try testing.expectEqual(std.math.maxInt(usize), pool.free_bitmask.load(.monotonic));
}
