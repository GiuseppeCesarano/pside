const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

/// Reader/writer style quiescence gate packed into a single word: the top bit
/// is a "closed" flag and the remaining bits are a live-reference count.
/// Readers increment/decrement while open; close() blocks new increments and
/// drain() waits for in-flight ones to reach zero before the writer proceeds.
const RefGate = @This();

const lock_bit = @as(usize, 1) << (@bitSizeOf(usize) - 1);
const references_mask = ~lock_bit;

references: std.atomic.Value(usize) align(std.atomic.cache_line) = .init(0),

pub inline fn increment(this: *RefGate) void {
    var ref = this.references.fetchAdd(1, .acquire);
    assert((ref & references_mask) != references_mask);

    while (ref & lock_bit != 0) {
        @branchHint(.cold);

        _ = this.references.fetchSub(1, .monotonic);

        while (this.references.load(.monotonic) & lock_bit != 0) std.atomic.spinLoopHint();

        ref = this.references.fetchAdd(1, .acquire);
        assert((ref & references_mask) != references_mask);
    }
}

pub inline fn tryIncrement(this: *RefGate) !void {
    const ref = this.references.fetchAdd(1, .acquire);
    assert((ref & references_mask) != references_mask);
    if (ref & lock_bit != 0) {
        _ = this.references.fetchSub(1, .monotonic);
        return error.WouldBlock;
    }
}

pub inline fn decrement(this: *RefGate) void {
    assert(this.references.fetchSub(1, .release) & references_mask != 0);
}

pub inline fn close(this: *RefGate) void {
    while (this.references.fetchOr(lock_bit, .acquire) & lock_bit != 0) {
        @branchHint(.cold);
        while (this.references.load(.monotonic) & lock_bit != 0) std.atomic.spinLoopHint();
    }
}

pub inline fn drain(this: *RefGate) void {
    while ((this.references.load(.acquire) & references_mask) != 0)
        std.atomic.spinLoopHint();
}

pub inline fn open(this: *RefGate) void {
    assert(this.references.fetchAnd(references_mask, .release) & lock_bit != 0);
}

test "RefGate: basic usage" {
    var gate = RefGate{};

    gate.increment();
    try testing.expectEqual(1, gate.references.load(.monotonic));
    gate.decrement();

    try testing.expectEqual(0, gate.references.load(.monotonic));
}

test "RefGate: cold path (waiting on closed gate)" {
    var gate: RefGate = .{};
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
    const thread: std.Thread = try .spawn(.{}, Context.worker, .{&ctx});

    try testing.io.sleep(.fromMilliseconds(10), .real);
    try testing.expectEqual(false, ctx.entered.load(.acquire));

    gate.open();
    thread.join();

    try testing.expectEqual(true, ctx.entered.load(.acquire));
}
