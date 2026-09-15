const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub const enabled = std.debug.runtime_safety;

pub const AtomicCounter = struct {
    const Value = if (enabled) std.atomic.Value(usize) else void;

    value: Value,

    pub const zero: AtomicCounter = .{ .value = if (enabled) .init(0) else {} };

    pub inline fn increment(this: *AtomicCounter) void {
        if (!enabled) return;
        _ = this.value.fetchAdd(1, .monotonic);
    }

    pub inline fn decrement(this: *AtomicCounter) void {
        if (!enabled) return;
        assert(this.value.fetchSub(1, .monotonic) != 0);
    }

    pub inline fn assertZero(this: *const AtomicCounter) void {
        if (!enabled) return;
        assert(this.value.load(.monotonic) == 0);
    }
};

pub fn State(comptime Tag: type) type {
    return struct {
        const This = @This();
        const Value = if (enabled) Tag else void;

        value: Value,

        pub fn init(comptime tag: Tag) This {
            return .{
                .value = if (enabled) tag else {},
            };
        }

        pub inline fn transition(this: *This, comptime tag: Tag) void {
            if (!enabled) return;
            this.value = tag;
        }

        pub inline fn assertIs(this: *const This, comptime tag: Tag) void {
            if (!enabled) return;
            assert(this.value == tag);
        }
    };
}

test "AtomicCounter: balanced pairs leave zero" {
    var counter: AtomicCounter = .zero;
    counter.assertZero();

    counter.increment();
    counter.increment();
    counter.decrement();
    counter.decrement();

    counter.assertZero();
}

test "State: transitions are observable under safety" {
    const Tag = enum { start, end };

    var state: State(Tag) = .init(.start);
    state.assertIs(.start);

    state.transition(.end);
    state.assertIs(.end);

    if (enabled) try testing.expectEqual(.end, state.value);
}

test "safety: instrumentation is zero sized when disabled" {
    if (enabled) return error.SkipZigTest;

    try testing.expectEqual(0, @sizeOf(AtomicCounter));
    try testing.expectEqual(0, @sizeOf(State(enum { a, b })));
}
