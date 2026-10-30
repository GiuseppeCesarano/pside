//! Collection of primitives to declare valid program state and help assert
//! that the program at runtime respects it.
//!
//! In their default configuration, in debug and safe modes the state is
//! carried and the checks are always generated, and a violation triggers a
//! panic.
//! In fast and small modes the primitives that carry state are zero-sized and
//! the checks are optimized away, so declaring valid state costs nothing there.
//!
//! User code should not branch on the internal state of these primitives, nor
//! otherwise change program behavior upon them, since in some configurations
//! they are erased entirely.

const std = @import("std");
const testing = std.testing;
const io = std.Options.debug_io;
const builtin = @import("builtin");

pub fn CapturedStackTrace(comptime frames_len: usize) type {
    return struct {
        /// Return addresses, innermost first, zero padded.
        addresses: [frames_len]usize align(if (frames_len == 0) 1 else @alignOf(usize)),

        const Capture = @This();

        /// The maximum number of frames this type can hold.
        pub const len = frames_len;
        pub const empty: Capture = .{ .addresses = @splat(0) };

        /// `capture` as a single expression, for initializing a field.
        pub fn captured(ret_addr: usize) Capture {
            var c: Capture = .empty;
            c.capture(ret_addr);
            return c;
        }

        /// Capture the current stack trace, ignoring all frames up to and including `ret_addr`.
        /// Pass `@returnAddress()` from the public entry point so that the intermediate bookkeeping
        /// code is omitted from the trace.
        pub fn capture(c: *Capture, ret_addr: usize) void {
            if (frames_len == 0) return;
            const st = std.debug.captureCurrentStackTrace(.{ .first_address = ret_addr }, &c.addresses);
            // Zero the unused frames to indicate the end of the trace.
            @memset(c.addresses[@min(st.return_addresses.len, frames_len)..], 0);
        }

        /// The captured addresses as a `StackTrace`, for use with `writeStackTrace` and
        /// `dumpStackTrace`.
        pub fn stackTrace(c: *const Capture) std.debug.StackTrace {
            if (frames_len == 0) return .{ .return_addresses = &.{}, .skipped = .unknown };
            const n = std.mem.indexOfScalar(usize, &c.addresses, 0) orelse frames_len;
            return .{
                .return_addresses = @constCast(c.addresses[0..n]),
                .skipped = if (n < frames_len) .none else .unknown,
            };
        }

        /// Formats the captured trace, annotated with source locations, for use with `{f}`.
        pub fn fmt(c: *const Capture) std.debug.FormatStackTrace {
            return .{
                .stack_trace = c.stackTrace(),
                .terminal_mode = std.log.terminalMode(),
            };
        }
    };
}

/// Invokes detectable illegal behavior when `ok` is `false`.
///
/// In debug and safe modes, calls to this function are always
/// generated, and the `unreachable` statement triggers a panic.
///
/// In fast and small modes, calls to this function are optimized
/// away, and in fact the optimizer is able to use the assertion in its
/// heuristics.
///
/// Inside a test block, it is best to use the `testing` module rather than
/// this function, because this function may not detect a test failure in
/// fast and small mode. Outside of a test block, this assert
/// function is the correct function to use.
pub fn assert(ok: bool) void {
    if (!ok) unreachable; // assertion failure
}

/// Invokes detectable illegal behavior when the provided slice is not mapped
/// or lacks read permissions.
pub fn assertReadable(slice: []const volatile u8) void {
    if (!std.debug.runtime_safety) return;
    for (slice) |*byte| _ = byte.*;
}

/// Invokes detectable illegal behavior when the provided array is not aligned
/// to the provided amount.
pub fn assertAligned(ptr: anytype, comptime alignment: std.mem.Alignment) void {
    const aligned_ptr: *align(alignment.toByteUnits()) const anyopaque = @ptrCast(@alignCast(ptr));
    _ = aligned_ptr;
}

/// Carries the configuration options and their default values for this
/// module's primitives.
pub const Config = struct {
    /// When false the primitive is zero-sized and its checks compile away,
    /// so declaring the state costs nothing.
    enabled: bool = std.lang.Optimize.runtimeSafety(builtin.optimize),
    /// Serializes the checks through the type's `CheckMutex`, so that they do
    /// not race when values are shared between threads.
    thread_safe: bool = false,
    /// How many frames each captured trace keeps. 0 captures nothing, which
    /// is what a disabled primitive is forced to regardless of this value.
    stack_trace_frames: usize = if (builtin.optimize == .debug) 6 else 0,

    fn traceFrames(config: Config) usize {
        return if (config.enabled and std.debug.sys_can_stack_trace)
            config.stack_trace_frames
        else
            0;
    }
};

// A call to fail() would result in std.debug.panicExtra, making failures non testable.
// In testing mode, while capturing, fail() will just increment this counter so we can
// test against it. Capturing is off by default, so every other test build still panics.
const violation = struct {
    var capturing: bool = false;
    var count: usize = 0;

    fn startCapture() void {
        capturing = true;
        count = 0;
    }

    fn stopCapture() void {
        capturing = false;
        count = 0;
    }

    fn expect() !void {
        try testing.expectEqual(1, count);
        count = 0;
    }

    fn expectNone() !void {
        try testing.expectEqual(0, count);
    }
};

const FailReturn = if (builtin.is_test) void else noreturn;

fn fail(
    comptime headline: []const u8,
    headline_args: anytype,
    comptime trace_label: []const u8,
    trace_label_args: anytype,
    trace: anytype,
    ret_addr: usize,
) FailReturn {
    @branchHint(.cold);

    if (builtin.is_test and violation.capturing) {
        violation.count += 1;
        return;
    }

    const stack_trace = trace.stackTrace();
    if (stack_trace.return_addresses.len == 0)
        std.debug.panicExtra(ret_addr, headline, headline_args);

    std.debug.panicExtra(
        ret_addr,
        headline ++ "\n\n" ++ trace_label ++ ":{f}\nviolation occurred at:",
        headline_args ++ trace_label_args ++ .{std.debug.FormatStackTrace{
            .stack_trace = stack_trace,
            .terminal_mode = .no_color,
        }},
    );
}

/// A mutex that makes the safety checks of `Owner` thread-safe.
/// It guards the checks only: when `config.enabled` or `config.thread_safe`
/// is false it compiles to nothing, so it must never protect program data.
pub fn CheckMutex(Owner: type, config: Config) type {
    return struct {
        pub const present = config.enabled and config.thread_safe;

        // Referencing `Owner` makes it part of this type's identity, so each
        // owner gets its own `inner` instead of all of them sharing one.
        comptime {
            _ = Owner;
        }

        var inner: std.Io.Mutex = .init;

        pub fn lock() void {
            if (present) inner.lockUncancelable(io);
        }

        pub fn unlock() void {
            if (present) inner.unlock(io);
        }
    };
}

test CheckMutex {
    // Test that each owner gets its own mutex
    const A = struct {};
    const B = struct {};
    try testing.expect(&CheckMutex(A, .{}).inner != &CheckMutex(B, .{}).inner);
    try testing.expect(&CheckMutex(A, .{}).inner == &CheckMutex(A, .{}).inner);
}

/// Text used when a state assertion fails.
pub const StateMessages = struct {
    /// Names the thing whose state this is, as in "expected the state to be
    /// used, found unused".
    name: []const u8 = "the state",
    /// Labels the trace of the most recent transition.
    last_transition: []const u8 = "last transition at",
};

pub fn ConfigurableState(States: type, config: Config, messages: StateMessages) type {
    const Enum = switch (@typeInfo(States)) {
        .@"enum" => States,
        .@"union" => |info| info.tag_type orelse
            @compileError("State needs a tagged union, found untagged " ++ @typeName(States)),
        else => @compileError("State needs an enum or a tagged union, found " ++ @typeName(States)),
    };

    return struct {
        const S = @This();

        state: if (config.enabled) Enum else void,
        last_transition: TransitionTrace,

        const TransitionTrace = CapturedStackTrace(config.traceFrames());
        const mutex = CheckMutex(S, config);

        /// Initializes the state to `initial_state`, without capturing a
        /// stack trace.
        pub fn init(initial_state: Enum) S {
            return .{
                .state = if (config.enabled) initial_state else {},
                .last_transition = .empty,
            };
        }

        /// Initializes the state to `initial_state` and captures the current
        /// stack trace.
        pub fn initAndCapture(initial_state: Enum) S {
            return .initAndCaptureAt(initial_state, @returnAddress());
        }

        /// `initAndCapture`, capturing from `ret_addr`.
        pub fn initAndCaptureAt(initial_state: Enum, ret_addr: usize) S {
            if (!config.enabled) return .{
                .state = {},
                .last_transition = .empty,
            };

            return .{
                .state = initial_state,
                .last_transition = .captured(ret_addr),
            };
        }

        /// Transitions to `next_state`.
        pub fn transition(self: *S, next_state: Enum) void {
            self.transitionAt(next_state, @returnAddress());
        }

        /// `transition`, capturing from `ret_addr`.
        pub fn transitionAt(self: *S, next_state: Enum, ret_addr: usize) void {
            if (!config.enabled) return;

            const trace: TransitionTrace = .captured(ret_addr);

            mutex.lock();
            defer mutex.unlock();

            self.state = next_state;
            self.last_transition = trace;
        }

        /// Asserts that the current state is equal to the one provided.
        pub fn assertEql(self: *const S, comptime expected: Enum) void {
            self.assertEqlAnyOfAt(&.{expected}, @returnAddress());
        }

        /// `assertEql`, reporting from `ret_addr`.
        pub fn assertEqlAt(self: *const S, comptime expected: Enum, ret_addr: usize) void {
            self.assertEqlAnyOfAt(&.{expected}, ret_addr);
        }

        /// Asserts that the current state is equal to any of the provided states.
        pub fn assertEqlAnyOf(self: *const S, comptime expect_any_of: []const Enum) void {
            self.assertEqlAnyOfAt(expect_any_of, @returnAddress());
        }

        /// `assertEqlAnyOf`, reporting from `ret_addr`.
        pub fn assertEqlAnyOfAt(
            self: *const S,
            comptime expect_any_of: []const Enum,
            ret_addr: usize,
        ) void {
            if (!config.enabled) return;

            mutex.lock();
            defer mutex.unlock();

            for (expect_any_of) |expected| {
                if (self.state == expected) return;
            }

            self.failUnsafe(expect_any_of, ret_addr);
        }

        fn failUnsafe(
            self: *const S,
            comptime expected: []const Enum,
            ret_addr: usize,
        ) FailReturn {
            @branchHint(.cold);

            const expected_list = comptime list: {
                var buf: []const u8 = "";
                for (expected, 0..) |e, i| {
                    const separator = if (i == 0)
                        ""
                    else if (i == expected.len - 1)
                        " or "
                    else
                        ", ";

                    buf = buf ++ separator ++ @tagName(e);
                }

                break :list buf;
            };

            const headline = "expected " ++ messages.name ++ " to be " ++ expected_list ++ ", found ";

            if (std.enums.tagName(Enum, self.state)) |found| fail(
                headline ++ "{s}",
                .{found},
                messages.last_transition,
                .{},
                &self.last_transition,
                ret_addr,
            ) else fail(
                headline ++ "{d}",
                .{@backingInt(self.state)},
                messages.last_transition,
                .{},
                &self.last_transition,
                ret_addr,
            );
        }
    };
}

test ConfigurableState {
    violation.startCapture();
    defer violation.stopCapture();

    const Disabled = ConfigurableState(enum { a, b }, .{ .enabled = false }, .{});

    // Test that the size is 0
    try testing.expect(@sizeOf(Disabled) == 0);

    // Test that once disabled the checks don't run
    var disabled: Disabled = .init(.a);
    disabled.assertEql(.b);
    disabled.transition(.b);
    disabled.assertEqlAnyOf(&.{.a});
    try violation.expectNone();

    // Test correct behavior
    const Enabled = ConfigurableState(enum { a, b, c }, .{ .enabled = true }, .{});
    var enabled: Enabled = .init(.a);
    enabled.assertEql(.a);
    enabled.transition(.b);
    enabled.assertEqlAnyOf(&.{ .a, .b });
    try violation.expectNone();

    // Test that a state other than the expected one fails
    enabled.assertEql(.a);
    try violation.expect();
    enabled.assertEqlAnyOf(&.{ .a, .c });
    try violation.expect();
    enabled.transition(.c);
    enabled.assertEqlAnyOf(&.{ .a, .b });
    try violation.expect();

    // Test that a tagged union is tracked by its tag
    const Body = union(enum) { none, content_length: u64, end };
    var body: Body = .{ .content_length = 3 };
    var tracked: ConfigurableState(Body, .{ .enabled = true }, .{}) = .init(body);
    tracked.assertEql(.content_length);
    body = .end;
    tracked.transition(body);
    tracked.assertEqlAnyOf(&.{ .none, .end });
    try violation.expectNone();
    tracked.assertEql(.content_length);
    try violation.expect();
    try testing.expectEqual(@sizeOf(ConfigurableState(Body, .{ .enabled = false }, .{})), 0);
}

/// Tracks which state the program is in, and asserts the transitions respect the
/// ones it declares, much like a finite state machine.
/// A failure reports the state found and where the last transition was made.
///
/// See `ConfigurableState` to name the thing being tracked, and to configure
/// enable/disabled, thread safety and more.
pub fn State(States: type) type {
    return ConfigurableState(States, .{}, .{});
}

/// Text used when an obligation assertion fails. Each headline is followed by
/// the count the assertion asked for and the one found, worded from its
/// comparison: "obligations still outstanding (expected 0 obligation(s), found 2)".
///
/// A `discharge` with nothing outstanding reports as `too_few`, since that is
/// what it is: one was expected, none was there.
pub const ObligationsMessages = struct {
    /// Fewer are outstanding than the assertion asked for.
    too_few: []const u8 = "fewer obligations outstanding than expected",
    /// More are outstanding than the assertion asked for.
    too_many: []const u8 = "obligations still outstanding",
    /// Noun for whatever is counted, as in "(expected at least 1 obligation(s), found 0)".
    counted: []const u8 = "obligation(s)",
    /// Labels the trace of the most recent discharge.
    last_discharge: []const u8 = "previously discharged at",
    /// Labels the trace of the most recent incur
    last_incur: []const u8 = "last incurred at",
};

pub fn ConfigurableObligations(config: Config, messages: ObligationsMessages) type {
    return struct {
        const O = @This();

        counter: if (config.enabled) u32 else void,
        last_incur: ObligationsTrace,
        last_discharge: ObligationsTrace,

        const ObligationsTrace = CapturedStackTrace(config.traceFrames());
        const mutex = CheckMutex(O, config);

        pub const none: O = .{
            .counter = if (config.enabled) 0 else {},
            .last_incur = .empty,
            .last_discharge = .empty,
        };

        /// Takes an obligation.
        pub fn incur(self: *O) void {
            self.incurAt(@returnAddress());
        }

        /// `incur`, capturing from `ret_addr`.
        pub fn incurAt(self: *O, ret_addr: usize) void {
            if (!config.enabled) return;

            const trace: ObligationsTrace = .captured(ret_addr);

            mutex.lock();
            defer mutex.unlock();

            self.counter += 1;
            self.last_incur = trace;
        }

        /// Asserts one obligation is outstanding, then discharges it.
        pub fn discharge(self: *O) void {
            self.dischargeAt(@returnAddress());
        }

        /// `discharge`, capturing and reporting from `ret_addr`.
        pub fn dischargeAt(self: *O, ret_addr: usize) void {
            if (!config.enabled) return;

            const trace: ObligationsTrace = .captured(ret_addr);

            mutex.lock();
            defer mutex.unlock();

            if (self.counter == 0)
                return self.failUnsafe(.gte, 1, ret_addr); // Discharge expects at least 1 outstanding

            self.counter -= 1;
            self.last_discharge = trace;
        }

        /// Asserts the outstanding count compares to `rhs` as `op` says:
        /// `assertCount(.eq, 0)` expects nothing outstanding,
        /// `assertCount(.gte, 1)` expects at least one.
        pub fn assertCount(self: *const O, op: std.math.CompareOperator, rhs: u32) void {
            self.assertCountAt(op, rhs, @returnAddress());
        }

        /// `assertCount`, reporting from `ret_addr`.
        pub fn assertCountAt(self: *const O, op: std.math.CompareOperator, rhs: u32, ret_addr: usize) void {
            if (!config.enabled) return;

            mutex.lock();
            defer mutex.unlock();

            if (!std.math.compare(self.counter, op, rhs))
                self.failUnsafe(op, rhs, ret_addr);
        }

        fn failUnsafe(self: *const O, op: std.math.CompareOperator, rhs: u32, ret_addr: usize) FailReturn {
            @branchHint(.cold);

            const too_many = switch (op) {
                .lt, .lte => true,
                .gt, .gte => false,
                .eq => self.counter > rhs,
                // Landed on the one forbidden count: an incur put it there,
                // unless the count is zero, which only a discharge reaches.
                .neq => self.counter != 0,
            };

            const op_string = switch (op) {
                .eq => "",
                .neq => "anything but ",
                .lt => "fewer than ",
                .lte => "at most ",
                .gt => "more than ",
                .gte => "at least ",
            };

            fail(
                "{s} (expected {s}{d} {s}, found {d})",
                .{
                    if (too_many) messages.too_many else messages.too_few,
                    op_string,
                    rhs,
                    messages.counted,
                    self.counter,
                },
                "{s}",
                .{if (too_many) messages.last_incur else messages.last_discharge},
                if (too_many) &self.last_incur else &self.last_discharge,
                ret_addr,
            );
        }
    };
}

test ConfigurableObligations {
    violation.startCapture();
    defer violation.stopCapture();

    const Disabled = ConfigurableObligations(.{ .enabled = false }, .{});

    // Test that the size is 0
    try testing.expect(@sizeOf(Disabled) == 0);

    // Test that once disabled the checks don't run
    var disabled: Disabled = .none;
    disabled.assertCount(.gte, 1);
    disabled.discharge();
    try violation.expectNone();

    // Test correct behavior
    const Enabled = ConfigurableObligations(.{ .enabled = true }, .{});
    var enabled: Enabled = .none;
    enabled.assertCount(.eq, 0);
    enabled.incur();
    enabled.assertCount(.gte, 1);
    enabled.discharge();
    enabled.assertCount(.eq, 0);

    // Test that obligations are counted rather than collapsed
    enabled.incur();
    enabled.incur();
    enabled.assertCount(.eq, 2);
    enabled.discharge();
    enabled.assertCount(.gte, 1);
    enabled.assertCount(.lt, 2);
    enabled.discharge();
    enabled.assertCount(.eq, 0);
    try violation.expectNone();

    // Test that discharging with nothing outstanding fails, and leaves the count at 0
    enabled.discharge();
    try violation.expect();
    enabled.assertCount(.eq, 0);
    try violation.expectNone();

    // Test that every comparison operator fails when it does not hold
    enabled.incur();
    enabled.assertCount(.eq, 0);
    try violation.expect();
    enabled.assertCount(.lt, 1);
    try violation.expect();
    enabled.assertCount(.lte, 0);
    try violation.expect();
    enabled.assertCount(.gt, 1);
    try violation.expect();
    enabled.assertCount(.neq, 1);
    try violation.expect();
    enabled.discharge();
    enabled.assertCount(.neq, 0);
    try violation.expect();
}

/// Declares that what is taken must later be given back, and asserts the
/// program does it. Every `incur` leaves one obligation outstanding until a
/// `discharge` settles it; `assertCount` checks the outstanding count wherever
/// the program has an expectation about it.
///
/// Obligations are counted, not identified: discharging the same one twice
/// while another is outstanding goes unnoticed until the count reaches zero.
///
/// See `ConfigurableObligations` to configure enable/disabled, thread safety,
/// messages and more.
pub const Obligations = ConfigurableObligations(.{}, .{});

/// Text used when a binding assertion fails.
pub const BoundToMessages = struct {
    /// The identity differs from the one bound; "(was x, now y)" is appended.
    mismatch: []const u8 = "accessed with a different identity than the one bound",
    /// Nothing is bound where a binding was expected; "(expected x)" is appended.
    unbound: []const u8 = "accessed while no identity is bound",
    /// `bind` found an identity already bound; "(was x, now y)" is appended.
    already_bound: []const u8 = "bound while an identity is already bound",
    /// Labels the trace of the bind that established the bound identity.
    last_bind: []const u8 = "bound at",
    /// Labels the trace of the `unbind` that dropped the binding.
    last_unbind: []const u8 = "unbound at",
};

pub fn ConfigurableBoundTo(
    identityFn: anytype,
    config: Config,
    messages: BoundToMessages,
) type {
    if (@typeInfo(@TypeOf(identityFn)) != .@"fn")
        @compileError("identityFn must be a function");

    if (@typeInfo(@TypeOf(identityFn)).@"fn".param_types.len != 1)
        @compileError("identityFn must take one parameter, the *const to the BoundTo instance");

    return struct {
        const B = @This();

        identity: if (config.enabled) ?Identity else void,
        last_change: Trace,

        pub const Identity = @typeInfo(@TypeOf(identityFn)).@"fn".return_type.?;
        const Trace = CapturedStackTrace(config.traceFrames());

        /// Identities that define `format` are printed through it.
        const identity_fmt = if (std.meta.hasMethod(Identity, "format")) "{f}" else "{any}";
        const mutex = CheckMutex(B, config);

        /// Nothing bound.
        pub const unbound: B = .{
            .identity = if (config.enabled) null else {},
            .last_change = .empty,
        };

        fn queryIdentity(self: *const B) Identity {
            return identityFn(self);
        }

        /// Binds `identity`, without capturing a stack trace.
        pub fn init(identity: Identity) B {
            return .{
                .identity = if (config.enabled) identity else {},
                .last_change = .empty,
            };
        }

        /// `init`, capturing the current stack trace.
        pub fn initAndCapture(identity: Identity) B {
            return .initAndCaptureAt(identity, @returnAddress());
        }

        /// `initAndCapture`, capturing from `ret_addr`.
        pub fn initAndCaptureAt(identity: Identity, ret_addr: usize) B {
            if (!config.enabled) return .{
                .identity = {},
                .last_change = .empty,
            };

            return .{
                .identity = identity,
                .last_change = .captured(ret_addr),
            };
        }

        /// Binds `identityFn`'s identity. Asserts nothing is bound.
        pub fn bind(self: *B) void {
            self.bindAt(@returnAddress());
        }

        /// `bind`, capturing and reporting from `ret_addr`.
        pub fn bindAt(self: *B, ret_addr: usize) void {
            if (!config.enabled) return;

            const identity = self.queryIdentity();
            const trace: Trace = .captured(ret_addr);

            mutex.lock();
            defer mutex.unlock();

            if (self.identity) |bound_identity|
                return self.failMismatchUnsafe(messages.already_bound, bound_identity, identity, ret_addr);

            self.bindUnsafe(identity, trace);
        }

        /// Binds `identityFn`'s identity if nothing is bound, otherwise does
        /// `assertCurrent`.
        pub fn bindOrAssert(self: *B) void {
            self.bindOrAssertAt(@returnAddress());
        }

        /// `bindOrAssert`, capturing and reporting from `ret_addr`.
        pub fn bindOrAssertAt(self: *B, ret_addr: usize) void {
            if (!config.enabled) return;

            const identity = self.queryIdentity();

            mutex.lock();
            defer mutex.unlock();

            const bound_identity = self.identity orelse
                return self.bindUnsafe(identity, .captured(ret_addr));

            if (!std.meta.eql(bound_identity, identity))
                self.failMismatchUnsafe(messages.mismatch, bound_identity, identity, ret_addr);
        }

        /// Asserts `identityFn`'s identity is the bound one.
        pub fn assertCurrent(self: *const B) void {
            self.assertCurrentAt(@returnAddress());
        }

        /// `assertCurrent`, reporting from `ret_addr`.
        pub fn assertCurrentAt(self: *const B, ret_addr: usize) void {
            if (!config.enabled) return;
            self.assertEqlAt(self.queryIdentity(), ret_addr);
        }

        /// `assertCurrent`, passing when nothing is bound.
        pub fn assertCurrentIfBound(self: *const B) void {
            self.assertCurrentIfBoundAt(@returnAddress());
        }

        /// `assertCurrentIfBound`, reporting from `ret_addr`.
        pub fn assertCurrentIfBoundAt(self: *const B, ret_addr: usize) void {
            if (!config.enabled) return;

            const identity = self.queryIdentity();

            mutex.lock();
            defer mutex.unlock();

            const bound_identity = self.identity orelse return;

            if (!std.meta.eql(bound_identity, identity))
                self.failMismatchUnsafe(messages.mismatch, bound_identity, identity, ret_addr);
        }

        /// Asserts `identity` is the bound one.
        pub fn assertEql(self: *const B, identity: Identity) void {
            self.assertEqlAt(identity, @returnAddress());
        }

        /// `assertEql`, reporting from `ret_addr`.
        pub fn assertEqlAt(self: *const B, identity: Identity, ret_addr: usize) void {
            if (!config.enabled) return;

            mutex.lock();
            defer mutex.unlock();

            const bound_identity = self.identity orelse
                return self.failUnboundUnsafe(identity, ret_addr);

            if (!std.meta.eql(bound_identity, identity))
                self.failMismatchUnsafe(messages.mismatch, bound_identity, identity, ret_addr);
        }

        /// Does `assertCurrent`, then drops the binding.
        pub fn unbind(self: *B) void {
            self.unbindAt(@returnAddress());
        }

        /// `unbind`, capturing and reporting from `ret_addr`.
        pub fn unbindAt(self: *B, ret_addr: usize) void {
            if (!config.enabled) return;

            const identity = self.queryIdentity();
            const trace: Trace = .captured(ret_addr);

            mutex.lock();
            defer mutex.unlock();

            const bound_identity = self.identity orelse
                return self.failUnboundUnsafe(identity, ret_addr);

            if (!std.meta.eql(bound_identity, identity))
                return self.failMismatchUnsafe(messages.mismatch, bound_identity, identity, ret_addr);

            self.identity = null;
            self.last_change = trace;
        }

        /// Binds `identityFn`'s identity, replacing any binding.
        pub fn rebind(self: *B) void {
            self.rebindAt(@returnAddress());
        }

        /// `rebind`, capturing from `ret_addr`.
        pub fn rebindAt(self: *B, ret_addr: usize) void {
            if (!config.enabled) return;

            const identity = self.queryIdentity();
            const trace: Trace = .captured(ret_addr);

            mutex.lock();
            defer mutex.unlock();

            self.bindUnsafe(identity, trace);
        }

        fn bindUnsafe(self: *B, identity: Identity, trace: Trace) void {
            self.identity = identity;
            self.last_change = trace;
        }

        fn failMismatchUnsafe(
            self: *const B,
            comptime headline: []const u8,
            bound_identity: Identity,
            found_identity: Identity,
            ret_addr: usize,
        ) FailReturn {
            @branchHint(.cold);

            fail(
                headline ++ " (was " ++ identity_fmt ++ ", now " ++ identity_fmt ++ ")",
                .{ bound_identity, found_identity },
                messages.last_bind,
                .{},
                &self.last_change,
                ret_addr,
            );
        }

        fn failUnboundUnsafe(self: *const B, expected_identity: Identity, ret_addr: usize) FailReturn {
            @branchHint(.cold);

            fail(
                messages.unbound ++ " (expected " ++ identity_fmt ++ ")",
                .{expected_identity},
                messages.last_unbind,
                .{},
                &self.last_change,
                ret_addr,
            );
        }
    };
}

test ConfigurableBoundTo {
    violation.startCapture();
    defer violation.stopCapture();

    const Id = struct {
        var current: usize = 0;

        fn identity(_: *const anyopaque) usize {
            return current;
        }
    };

    const Disabled = ConfigurableBoundTo(Id.identity, .{ .enabled = false }, .{});

    // Test that the size is 0
    try testing.expect(@sizeOf(Disabled) == 0);

    // Test that once disabled the checks don't run
    Id.current = 1;
    var disabled: Disabled = .unbound;
    disabled.bindOrAssert();
    Id.current = 2;
    disabled.bindOrAssert();
    disabled.assertEql(3);
    disabled.assertCurrent();
    disabled.assertCurrentIfBound();
    disabled.bind();
    disabled.unbind();
    disabled.unbind();
    try violation.expectNone();

    // Test correct behavior
    const Enabled = ConfigurableBoundTo(Id.identity, .{ .enabled = true }, .{});
    Id.current = 7;
    var enabled: Enabled = .unbound;

    // Test that `assertEql` and `assertCurrent` never bind, so they fail before the first access
    enabled.assertEql(7);
    try violation.expect();
    enabled.assertCurrent();
    try violation.expect();

    enabled.bindOrAssert(); // The first access binds.
    enabled.assertEql(7);
    enabled.assertCurrent();
    try violation.expectNone();

    // Test that a different identity fails
    Id.current = 8;
    enabled.bindOrAssert();
    try violation.expect();
    enabled.assertEql(8);
    try violation.expect();
    enabled.assertCurrent();
    try violation.expect();

    // Test that `unbind` fails under a different identity, and leaves the binding in place
    enabled.unbind();
    try violation.expect();
    enabled.assertEql(7);
    try violation.expectNone();

    // Test that a new identity needs the old binding released, or acknowledged
    Id.current = 7;
    enabled.unbind();
    Id.current = 8;
    enabled.bindOrAssert();

    Id.current = 9;
    enabled.rebind();
    enabled.bindOrAssert();

    Id.current = 10;
    enabled.rebind();
    enabled.assertEql(10);
    try violation.expectNone();

    // Test that an eager binding is in place before the first access
    var eager: Enabled = .init(11);
    try testing.expectEqual(11, eager.identity.?);
    eager.assertEql(11);
    eager.bindOrAssert(); // `Id.current` is still 10, so this checks rather than binds.
    try violation.expect();
    Id.current = 11;
    eager.bindOrAssert();
    try violation.expectNone();

    // Test that `bind` and `unbind` each assert the opposite state first
    var strict: Enabled = .unbound;
    strict.unbind();
    try violation.expect();
    strict.bind();
    strict.assertCurrent();
    try violation.expectNone();
    strict.bind();
    try violation.expect();
    strict.unbind();
    strict.assertCurrent();
    try violation.expect();
    strict.unbind();
    try violation.expect();
    strict.bind(); // Bindable again once unbound.
    strict.assertEql(11);
    try violation.expectNone();

    // Test that `assertCurrentIfBound` passes when unbound, and checks otherwise
    var stamp: Enabled = .unbound;
    stamp.assertCurrentIfBound();
    try violation.expectNone();
    stamp = .init(12);
    stamp.assertCurrentIfBound();
    try violation.expect();
    stamp = .init(11);
    stamp.assertCurrentIfBound();
    try violation.expectNone();
}

/// Asserts that every access happens under the same identity, where the
/// identity is whatever `identityFn(self)` returns: the current thread,
/// task, generation counter, and so on.
///
/// `identityFn` shall take `anytype` as its first parameter and it will be a
/// `*const` pointer to the `BoundTo` specification instance itself, which you
/// can pass to `@alignCast(@fieldParentPtr(...))` to reach other values in the
/// struct that contains it.
///
/// A failure reports the bound and found identities, and where the binding
/// was made.
///
/// See `ConfigurableBoundTo` to configure enable/disabled, thread safety,
/// messages and more.
pub fn BoundTo(identityFn: anytype) type {
    return ConfigurableBoundTo(identityFn, .{}, .{});
}

test BoundTo {
    violation.startCapture();
    defer violation.stopCapture();

    const Arena = struct {
        generation: u32 = 0,

        /// Invalidates every handle into this arena, and no other's.
        fn reset(arena: *@This()) void {
            arena.generation += 1;
        }

        fn handle(arena: *const @This()) Handle {
            return .{
                .arena_generation = &arena.generation,
                .generation = .initAndCapture(arena.generation),
            };
        }

        const Handle = struct {
            arena_generation: *const u32,
            generation: BoundToGeneration,

            const BoundToGeneration = BoundTo(currentGeneration);

            fn currentGeneration(generation: anytype) u32 {
                const h: *const Handle = @alignCast(@fieldParentPtr("generation", generation));
                return h.arena_generation.*;
            }
        };
    };

    var a: Arena = .{};
    var b: Arena = .{};

    var handle_into_a = a.handle();
    var handle_into_b = b.handle();

    handle_into_a.generation.bindOrAssert();
    handle_into_b.generation.bindOrAssert();

    b.reset();

    // `a` was not reset, so its handle is still valid.
    handle_into_a.generation.bindOrAssert();

    var new_handle_into_b = b.handle();
    new_handle_into_b.generation.bindOrAssert();

    handle_into_b.generation.bindOrAssert();
    if (@as(Config, .{}).enabled)
        try violation.expect()
    else
        try violation.expectNone();
}

fn addressOf(self: anytype) *const anyopaque {
    return self;
}

pub fn ConfigurablePinned(config: Config) type {
    return ConfigurableBoundTo(addressOf, config, .{
        .mismatch = "pinned value accessed at a different address",
        .unbound = "accessed while not pinned",
        .already_bound = "pinned while already pinned",
        .last_bind = "pinned at",
        .last_unbind = "unpinned at",
    });
}

test ConfigurablePinned {
    violation.startCapture();
    defer violation.stopCapture();

    const Disabled = ConfigurablePinned(.{ .enabled = false });

    // Test that the size is 0
    try testing.expect(@sizeOf(Disabled) == 0);

    // Test that once disabled the checks don't run
    var disabled: Disabled = .unbound;
    disabled.bindOrAssert();
    var disabled_copy = disabled;
    disabled_copy.bindOrAssert();
    disabled_copy.bind();
    disabled_copy.unbind();
    try violation.expectNone();

    // Test correct behavior
    const Enabled = ConfigurablePinned(.{ .enabled = true });
    var enabled: Enabled = .unbound;
    enabled.bindOrAssert(); // The first access pins it here.
    enabled.bindOrAssert();
    try violation.expectNone();

    // Test that a copy fails
    var copy = enabled;
    copy.bindOrAssert();
    try violation.expect();

    // Test that releasing the pin lets the value move
    enabled.unbind();
    var moved = enabled;
    moved.bindOrAssert();

    // Test that a move can be acknowledged after the fact instead
    var moved_again = moved;
    moved_again.rebind();
    moved_again.bindOrAssert();
    try violation.expectNone();

    // Test that a node pinned while linked catches double insert and double remove
    var node: Enabled = .unbound;
    node.bind(); // insert
    node.bind(); // insert again
    try violation.expect();
    node.unbind(); // remove
    node.unbind(); // remove again
    try violation.expect();

    // Test that a node moved while linked fails at its next remove, through either copy
    node.bind();
    var moved_node = node;
    moved_node.unbind();
    try violation.expect();
    moved_node.assertCurrent();
    try violation.expect();
    node.unbind(); // The original is still where it was pinned.
    try violation.expectNone();
}

/// Detects when an address-sensitive value has been copied or moved.
///
/// Embed it in any struct that other code reaches through a pointer to one of
/// its fields (`@fieldParentPtr`), or that intrusive data structures point
/// into. `bindOrAssert` pins the value at its current address the first time it
/// is called and asserts it has not moved on every later call, so it can be
/// called on every use.
///
/// A copy panics, reporting both addresses and where the original was pinned.
/// A copy carries the original's pin trace with it, so that trace shows where
/// the original was first checked, not where the copy was made.
///
/// See `ConfigurablePinned` to configure enable/disabled, thread safety and more.
pub const Pinned = ConfigurablePinned(.{});
