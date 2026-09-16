const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub const enabled = std.debug.runtime_safety;

pub const AtomicReferenceCounter = struct {
    const Value = if (enabled) std.atomic.Value(usize) else void;

    value: Value,

    pub const zero: AtomicReferenceCounter = .{ .value = if (enabled) .init(0) else {} };

    pub inline fn increment(this: *AtomicReferenceCounter) void {
        if (!enabled) return;
        _ = this.value.fetchAdd(1, .monotonic);
    }

    pub inline fn decrement(this: *AtomicReferenceCounter) void {
        if (!enabled) return;
        assert(this.value.fetchSub(1, .monotonic) != 0);
    }

    pub inline fn assertEql(this: *const AtomicReferenceCounter, value: usize) void {
        if (!enabled) return;
        assert(this.value.load(.monotonic) == value);
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

        pub inline fn assertIsAny(this: *const This, comptime tags: []const Tag) void {
            comptime assert(tags.len != 0);
            if (!enabled) return;
            assert(inline for (tags) |tag| {
                if (this.value == tag) break true;
            } else false);
        }
    };
}

pub fn BoundTo(callback: anytype, args: anytype) type {
    if (@typeInfo(@TypeOf(callback)) != .@"fn")
        @compileError("identify must be a function");

    const Target = @TypeOf(@call(.auto, callback, args));

    return struct {
        const This = @This();

        const Binding = enum(u8) { not_bounded, bounding, bounded };
        const Gate = if (enabled) std.atomic.Value(Binding) else void;
        const Slot = if (enabled) Target else void;

        gate: Gate,
        target: Slot,

        pub const unbound: This = .{
            .gate = if (enabled) .init(.not_bounded) else {},
            .target = if (enabled) undefined else {},
        };

        pub inline fn assertSame(this: *This) void {
            if (!enabled) return;
            this.assertSameAs(@call(.auto, callback, args));
        }

        pub fn assertSameAs(this: *This, target: Target) void {
            if (!enabled) return;

            while (true) switch (this.gate.load(.acquire)) {
                .not_bounded => if (this.gate.cmpxchgWeak(.not_bounded, .bounding, .acquire, .acquire) == null) {
                    this.target = target;
                    this.gate.store(.bounded, .release);
                    return;
                },
                .bounding => std.atomic.spinLoopHint(),
                .bounded => return assert(std.meta.eql(this.target, target)),
            };
        }

        pub inline fn boundTarget(this: *const This) ?Target {
            if (!enabled) return null;
            return if (this.gate.load(.acquire) == .bounded) this.target else null;
        }

        pub inline fn rebind(this: *This, target: Target) void {
            if (!enabled) return;
            this.target = target;
            this.gate.store(.bounded, .release);
        }

        pub inline fn unbind(this: *This) void {
            if (!enabled) return;
            this.gate.store(.not_bounded, .release);
        }
    };
}

test "AtomicReferenceCounter: balanced pairs leave zero" {
    var counter: AtomicReferenceCounter = .zero;
    counter.assertEql(0);

    counter.increment();
    counter.increment();
    counter.decrement();
    counter.assertEql(1);

    counter.decrement();
    counter.assertEql(0);
}

test "State: transitions are observable under safety" {
    const Tag = enum { start, end };

    var state: State(Tag) = .init(.start);
    state.assertIs(.start);

    state.transition(.end);
    state.assertIs(.end);

    if (enabled) try testing.expectEqual(.end, state.value);
}

test "State: assertIsAny accepts every listed tag" {
    const Tag = enum { start, middle, end };

    var state: State(Tag) = .init(.start);
    state.assertIsAny(&.{ .start, .end });

    state.transition(.end);
    state.assertIsAny(&.{ .start, .end });

    state.transition(.middle);
    state.assertIsAny(&.{.middle});
}

test "BoundTo: the first target binds it and keeps it" {
    var bound: BoundTo(std.Thread.getCurrentId, .{}) = .unbound;

    bound.assertSame();
    bound.assertSame();

    if (!enabled) return;

    try testing.expectEqual(std.Thread.getCurrentId(), bound.boundTarget().?);

    bound.rebind(std.Thread.getCurrentId() +% 1);
    try testing.expect(bound.boundTarget().? != std.Thread.getCurrentId());
}

test "BoundTo: unbind lets the next caller claim it" {
    var bound: BoundTo(std.Thread.getCurrentId, .{}) = .unbound;

    bound.assertSame();
    bound.rebind(std.Thread.getCurrentId() +% 1);
    bound.unbind();
    bound.assertSame();

    if (!enabled) return;

    try testing.expectEqual(std.Thread.getCurrentId(), bound.boundTarget().?);
}

test "BoundTo: composite identities compare by value" {
    const Id = struct { pid: u32, tid: u32 };
    const Identify = struct {
        fn identity() Id {
            return .{ .pid = 1, .tid = 2 };
        }
    };

    var bound: BoundTo(Identify.identity, .{}) = .unbound;

    bound.assertSame();
    bound.assertSame();

    if (!enabled) return;

    try testing.expectEqual(Id{ .pid = 1, .tid = 2 }, bound.boundTarget().?);
}

test "BoundTo: racing binds agree on one target" {
    if (!enabled) return error.SkipZigTest;

    const Identify = struct {
        fn identity() usize {
            return 0xB0;
        }
    };

    const Bound = BoundTo(Identify.identity, .{});

    var bound: Bound = .unbound;

    var threads: [8]std.Thread = undefined;
    for (&threads) |*thread|
        thread.* = try std.Thread.spawn(.{}, struct {
            fn run(shared: *Bound) void {
                for (0..4096) |_| shared.assertSame();
            }
        }.run, .{&bound});

    for (threads) |thread| thread.join();

    try testing.expectEqual(0xB0, bound.boundTarget().?);
}

test "safety: instrumentation is zero sized when disabled" {
    if (enabled) return error.SkipZigTest;

    try testing.expectEqual(0, @sizeOf(AtomicReferenceCounter));
    try testing.expectEqual(0, @sizeOf(State(enum { a, b })));
    try testing.expectEqual(0, @sizeOf(BoundTo(std.Thread.getCurrentId, .{})));
}

test "BoundTo: a zero identity is a real binding" {
    const Identify = struct {
        fn identity() u32 {
            return 0;
        }
    };

    var bound: BoundTo(Identify.identity, .{}) = .unbound;

    bound.assertSame();
    bound.assertSame();

    if (!enabled) return;

    try testing.expectEqual(0, bound.boundTarget().?);
}
