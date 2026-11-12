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
    /// Serializes the checks through `CheckMutex`, so that they do
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

/// Mutexes that make the safety checks thread-safe, one picked per checked
/// value by its address. They guard the checks only, so they must never
/// protect program data.
pub const CheckMutex = struct {
    var mutexes: [4 * std.atomic.cache_line / @sizeOf(std.Io.Mutex)]std.Io.Mutex align(std.atomic.cache_line) = @splat(.init);

    fn of(ptr: *const anyopaque) *std.Io.Mutex {
        return &mutexes[std.hash.int(@intFromPtr(ptr)) % mutexes.len];
    }

    pub fn For(config: Config) type {
        return struct {
            pub const present = config.enabled and config.thread_safe;

            pub fn lock(ptr: *const anyopaque) void {
                if (present) of(ptr).lockUncancelable(io);
            }

            pub fn unlock(ptr: *const anyopaque) void {
                if (present) of(ptr).unlock(io);
            }
        };
    }
};

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

        const TransitionTrace = CapturedStackTrace(config.traceFrames());

        const mutex = CheckMutex.For(config);

        state: if (config.enabled) Enum else void,
        last_transition: TransitionTrace,

        /// Initializes the state to `initial_state`, without capturing a
        /// stack trace, so it can be used as a default field value.
        pub fn init(initial_state: Enum) S {
            return .{
                .state = if (config.enabled) initial_state else {},
                .last_transition = .empty,
            };
        }

        /// Initializes the state to `initial_state` and captures the current
        /// stack trace.
        pub fn initTraced(initial_state: Enum) S {
            return .initTracedAt(initial_state, @returnAddress());
        }

        /// `initTraced`, capturing from `ret_addr`.
        pub fn initTracedAt(initial_state: Enum, ret_addr: usize) S {
            if (!config.enabled) return .init(initial_state);

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

            mutex.lock(self);
            defer mutex.unlock(self);

            self.transitionUnsafe(next_state, trace);
        }

        fn transitionUnsafe(self: *S, next_state: Enum, trace: TransitionTrace) void {
            if (!config.enabled) return;

            self.state = next_state;
            self.last_transition = trace;
        }

        /// Asserts that the current state is equal to the one provided.
        pub fn assertEql(self: *const S, comptime expected: Enum) void {
            self.assertOneOfAt(&.{expected}, @returnAddress());
        }

        /// `assertEql`, reporting from `ret_addr`.
        pub fn assertEqlAt(self: *const S, comptime expected: Enum, ret_addr: usize) void {
            self.assertOneOfAt(&.{expected}, ret_addr);
        }

        /// Asserts that the current state is one of the provided states.
        pub fn assertOneOf(self: *const S, comptime expected: []const Enum) void {
            self.assertOneOfAt(expected, @returnAddress());
        }

        /// `assertOneOf`, reporting from `ret_addr`.
        pub fn assertOneOfAt(
            self: *const S,
            comptime expected: []const Enum,
            ret_addr: usize,
        ) void {
            if (!config.enabled) return;

            mutex.lock(self);
            defer mutex.unlock(self);

            for (expected) |e| {
                if (self.state == e) return;
            }

            self.failUnsafe(expected, ret_addr);
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
    disabled.assertOneOf(&.{.a});
    try violation.expectNone();

    // Test correct behavior
    const Enabled = ConfigurableState(enum { a, b, c }, .{ .enabled = true }, .{});
    var enabled: Enabled = .init(.a);
    enabled.assertEql(.a);
    enabled.transition(.b);
    enabled.assertOneOf(&.{ .a, .b });
    try violation.expectNone();

    // Test that a state other than the expected one fails
    enabled.assertEql(.a);
    try violation.expect();
    enabled.assertOneOf(&.{ .a, .c });
    try violation.expect();
    enabled.transition(.c);
    enabled.assertOneOf(&.{ .a, .b });
    try violation.expect();

    // Test that a tagged union is tracked by its tag
    const Body = union(enum) { none, content_length: u64, end };
    var body: Body = .{ .content_length = 3 };
    var tracked: ConfigurableState(Body, .{ .enabled = true }, .{}) = .init(body);
    tracked.assertEql(.content_length);
    body = .end;
    tracked.transition(body);
    tracked.assertOneOf(&.{ .none, .end });
    try violation.expectNone();
    tracked.assertEql(.content_length);
    try violation.expect();
    try testing.expectEqual(@sizeOf(ConfigurableState(Body, .{ .enabled = false }, .{})), 0);
}

/// Tracks which state the program is in. Instead of a transition table, each
/// call site declares the transition it makes: `assertEql` or `assertOneOf`
/// for the states it may start from, then `transition` to the next one.
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

        const ObligationsTrace = CapturedStackTrace(config.traceFrames());

        const mutex = CheckMutex.For(config);

        counter: if (config.enabled) u32 else void,
        last_incur: ObligationsTrace,
        last_discharge: ObligationsTrace,

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

            mutex.lock(self);
            defer mutex.unlock(self);

            self.incurUnsafe(trace);
        }

        fn incurUnsafe(self: *O, trace: ObligationsTrace) void {
            if (!config.enabled) return;

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

            mutex.lock(self);
            defer mutex.unlock(self);

            self.dischargeUnsafe(trace, ret_addr);
        }

        fn dischargeUnsafe(self: *O, trace: ObligationsTrace, ret_addr: usize) void {
            if (!config.enabled) return;

            if (self.counter == 0)
                return self.failUnsafe(.gte, 1, ret_addr); // Discharge expects at least 1 outstanding

            self.counter -= 1;
            self.last_discharge = trace;
        }

        /// Asserts the outstanding count compares to `rhs` as `op` says:
        /// `assert(.eq, 0)` expects nothing outstanding,
        /// `assert(.gte, 1)` expects at least one.
        pub fn assert(self: *const O, op: std.math.CompareOperator, rhs: u32) void {
            self.assertAt(op, rhs, @returnAddress());
        }

        /// `assert`, reporting from `ret_addr`.
        pub fn assertAt(self: *const O, op: std.math.CompareOperator, rhs: u32, ret_addr: usize) void {
            if (!config.enabled) return;

            mutex.lock(self);
            defer mutex.unlock(self);

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
    disabled.assert(.gte, 1);
    disabled.discharge();
    try violation.expectNone();

    // Test correct behavior
    const Enabled = ConfigurableObligations(.{ .enabled = true }, .{});
    var enabled: Enabled = .none;
    enabled.assert(.eq, 0);
    enabled.incur();
    enabled.assert(.gte, 1);
    enabled.discharge();
    enabled.assert(.eq, 0);

    // Test that obligations are counted rather than collapsed
    enabled.incur();
    enabled.incur();
    enabled.assert(.eq, 2);
    enabled.discharge();
    enabled.assert(.gte, 1);
    enabled.assert(.lt, 2);
    enabled.discharge();
    enabled.assert(.eq, 0);
    try violation.expectNone();

    // Test that discharging with nothing outstanding fails, and leaves the count at 0
    enabled.discharge();
    try violation.expect();
    enabled.assert(.eq, 0);
    try violation.expectNone();

    // Test that every comparison operator fails when it does not hold
    enabled.incur();
    enabled.assert(.eq, 0);
    try violation.expect();
    enabled.assert(.lt, 1);
    try violation.expect();
    enabled.assert(.lte, 0);
    try violation.expect();
    enabled.assert(.gt, 1);
    try violation.expect();
    enabled.assert(.neq, 1);
    try violation.expect();
    enabled.discharge();
    enabled.assert(.neq, 0);
    try violation.expect();
}

/// Declares that what is taken must later be given back, and asserts the
/// program does it. Every `incur` leaves one obligation outstanding until a
/// `discharge` settles it; `assert` checks the outstanding count wherever
/// the program has an expectation about it.
///
/// Obligations are counted, not identified: discharging the same one twice
/// while another is outstanding goes unnoticed until the count reaches zero.
///
/// See `ConfigurableObligations` to configure enable/disabled, thread safety,
/// messages and more.
pub const Obligations = ConfigurableObligations(.{}, .{});

/// Text used when a lock assertion fails.
pub const LockMessages = struct {
    /// Names the lock where a message is about its exclusive claim, as in
    /// "expected the lock to be held, found free".
    name: []const u8 = "the lock",
    /// Held shared where that is not what the caller needed.
    held_shared: []const u8 = "the lock is held shared",
    /// Expected a shared holder, found none; also what `unlockShared`
    /// reports when nobody holds it.
    not_held_shared: []const u8 = "the lock is not held shared",
    /// Noun for a shared claim, as in "(expected 0 reader(s), found 2)".
    counted: []const u8 = "reader(s)",
    /// Labels the trace of the most recent `lockShared`.
    last_lock_shared: []const u8 = "last locked shared at",
    /// Labels the trace of the most recent `unlockShared`.
    last_unlock_shared: []const u8 = "previously unlocked shared at",
};

pub fn ConfigurableLock(config: Config, messages: LockMessages) type {
    return struct {
        const L = @This();

        /// The inner primitives are checked under this lock's `mutex`, so they
        /// do not take their own.
        const inner_config: Config = .{
            .enabled = config.enabled,
            .thread_safe = false,
            .stack_trace_frames = config.stack_trace_frames,
        };

        /// Tracks the exclusive claim. Shared claims leave it `free`, so this
        /// alone cannot tell readers from an idle lock; `readers` does.
        const LockState = ConfigurableState(
            enum { free, held },
            inner_config,
            .{ .name = messages.name },
        );

        /// Counts the shared claims, one obligation per reader, so the last
        /// `unlockShared` is what returns the lock to idle.
        const LockObligations = ConfigurableObligations(inner_config, .{
            .too_few = messages.not_held_shared,
            .too_many = messages.held_shared,
            .counted = messages.counted,
            .last_discharge = messages.last_unlock_shared,
            .last_incur = messages.last_lock_shared,
        });

        const mutex = CheckMutex.For(config);

        const Trace = CapturedStackTrace(config.traceFrames());

        /// Checked as one unit under `mutex`, since a claim is only valid
        /// against both halves at once.
        state: LockState = .init(.free),
        readers: LockObligations = .none,

        /// Held by nobody, exclusively or shared. Same as `.{}`.
        pub const unlocked: L = .{};

        /// Claims exclusive access. Use when mutating data.
        /// Asserts nobody holds it, exclusively or shared.
        pub fn lock(self: *L) void {
            const ret_addr = @returnAddress();
            const trace: Trace = .captured(ret_addr);
            mutex.lock(self);
            defer mutex.unlock(self);

            self.assertUnlockedUnsafe(ret_addr);
            self.state.transitionUnsafe(.held, trace);
        }

        /// Releases the exclusive claim. Asserts it is the one held.
        pub fn unlock(self: *L) void {
            const ret_addr = @returnAddress();
            const trace: Trace = .captured(ret_addr);
            mutex.lock(self);
            defer mutex.unlock(self);

            self.assertLockedUnsafe(ret_addr);
            self.state.transitionUnsafe(.free, trace);
        }

        /// Claims shared access, alongside any other readers. Use when
        /// consuming data in a read-only manner. Asserts nobody holds it
        /// exclusively.
        pub fn lockShared(self: *L) void {
            const ret_addr = @returnAddress();
            const trace: Trace = .captured(ret_addr);
            mutex.lock(self);
            defer mutex.unlock(self);

            self.state.assertEqlAt(.free, ret_addr);
            self.readers.incurUnsafe(trace);
        }

        /// Releases one shared claim. Asserts one is held, so a reader that
        /// releases twice is caught rather than cancelling out another.
        pub fn unlockShared(self: *L) void {
            const ret_addr = @returnAddress();
            const trace: Trace = .captured(ret_addr);
            mutex.lock(self);
            defer mutex.unlock(self);

            self.state.assertEqlAt(.free, ret_addr);
            self.readers.dischargeUnsafe(trace, ret_addr);
        }

        /// Asserts nobody holds it, exclusively or shared.
        pub fn assertUnlocked(self: *const L) void {
            const ret_addr = @returnAddress();
            mutex.lock(self);
            defer mutex.unlock(self);

            self.assertUnlockedUnsafe(ret_addr);
        }

        /// Asserts it is held exclusively, as a mutator should before writing.
        pub fn assertLocked(self: *const L) void {
            const ret_addr = @returnAddress();
            mutex.lock(self);
            defer mutex.unlock(self);

            self.assertLockedUnsafe(ret_addr);
        }

        /// Asserts at least one reader holds it, as a reader should before
        /// reading. Says nothing about which reader, only that a shared claim
        /// is outstanding.
        pub fn assertLockedShared(self: *const L) void {
            const ret_addr = @returnAddress();
            mutex.lock(self);
            defer mutex.unlock(self);

            self.state.assertEqlAt(.free, ret_addr);
            self.readers.assertAt(.gte, 1, ret_addr);
        }

        fn assertUnlockedUnsafe(self: *const L, ret_addr: usize) void {
            self.readers.assertAt(.eq, 0, ret_addr);
            self.state.assertEqlAt(.free, ret_addr);
        }

        fn assertLockedUnsafe(self: *const L, ret_addr: usize) void {
            self.readers.assertAt(.eq, 0, ret_addr);
            self.state.assertEqlAt(.held, ret_addr);
        }
    };
}

test ConfigurableLock {
    violation.startCapture();
    defer violation.stopCapture();

    const Disabled = ConfigurableLock(.{ .enabled = false }, .{});

    // Test that the size is 0
    try testing.expect(@sizeOf(Disabled) == 0);

    // Test that once disabled the checks don't run
    var disabled: Disabled = .{};
    disabled.assertLocked();
    disabled.unlock();
    disabled.unlockShared();
    try violation.expectNone();

    // Test correct behavior
    const Enabled = ConfigurableLock(.{ .enabled = true }, .{});
    var enabled: Enabled = .unlocked;
    enabled.assertUnlocked();
    enabled.lock();
    enabled.assertLocked();
    enabled.unlock();
    enabled.assertUnlocked();

    // Test that readers share, and that the last one returns it to idle
    enabled.lockShared();
    enabled.lockShared();
    enabled.unlockShared();
    enabled.assertLockedShared();
    enabled.unlockShared();
    enabled.assertUnlocked();
    try violation.expectNone();

    // Test that an idle lock can't be released or asserted held
    enabled.unlock();
    try violation.expect();
    enabled.unlockShared();
    try violation.expect();
    enabled.assertLocked();
    try violation.expect();
    enabled.assertLockedShared();
    try violation.expect();

    // Test that an exclusive claim excludes every other claim
    enabled.lock();
    enabled.lock();
    try violation.expect();
    enabled.assertUnlocked();
    try violation.expect();
    enabled.lockShared(); // Fails, but still counts the reader.
    try violation.expect();
    enabled.unlock();
    try violation.expect();
    enabled.unlockShared();
    enabled.assertUnlocked();
    try violation.expectNone();

    // Test that a shared claim excludes a mutator, and that releasing it twice is caught
    enabled.lockShared();
    enabled.lock();
    try violation.expect();
    enabled.unlock();
    try violation.expect();
    enabled.unlockShared();
    enabled.unlockShared();
    try violation.expect();

    // Test that the claims don't re-enter the mutex, which is not recursive
    var thread_safe: ConfigurableLock(.{ .enabled = true, .thread_safe = true }, .{}) = .{};
    thread_safe.lock();
    thread_safe.unlock();
    thread_safe.lockShared();
    thread_safe.unlockShared();
    try violation.expectNone();

    // Test that a failing check releases the mutex, or the next one would deadlock
    thread_safe.unlock();
    try violation.expect();
    thread_safe.lock();
    thread_safe.unlock();
    try violation.expectNone();
}

/// Declares who may read and who may mutate, and asserts the program keeps to
/// it. Access is either exclusive, held by one mutator, or shared, held by any
/// number of readers at once; the two never overlap.
///
/// See `ConfigurableLock` to configure enable/disabled, thread safety, messages and more.
pub const Lock = ConfigurableLock(.{}, .{});

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
    const fn_info = switch (@typeInfo(@TypeOf(identityFn))) {
        .@"fn" => |info| info,
        else => @compileError("identityFn must be a function, found " ++ @typeName(@TypeOf(identityFn))),
    };

    if (fn_info.param_types.len != 1)
        @compileError("identityFn must take exactly one parameter, of type anytype or *const anyopaque");

    if (fn_info.param_types[0]) |Param| if (Param != *const anyopaque)
        @compileError("identityFn's parameter must be anytype or *const anyopaque, found " ++ @typeName(Param));

    return struct {
        const B = @This();

        pub const Identity = fn_info.return_type orelse
            @compileError("identityFn must not have a generic return type");

        fn queryIdentity(self: *const B) Identity {
            return identityFn(self);
        }

        /// Identities that define `format` are printed through it.
        const identity_fmt = if (std.meta.hasMethod(Identity, "format")) "{f}" else "{any}";

        const Trace = CapturedStackTrace(config.traceFrames());

        const mutex = CheckMutex.For(config);

        identity: if (config.enabled) ?Identity else void,
        last_change: Trace,

        /// Nothing bound.
        pub const unbound: B = .{
            .identity = if (config.enabled) null else {},
            .last_change = .empty,
        };

        /// Binds `identity`, without capturing a stack trace, so it can be used
        /// as a default field value.
        pub fn init(identity: Identity) B {
            return .{
                .identity = if (config.enabled) identity else {},
                .last_change = .empty,
            };
        }

        /// `init`, capturing the current stack trace.
        pub fn initTraced(identity: Identity) B {
            return .initTracedAt(identity, @returnAddress());
        }

        /// `initTraced`, capturing from `ret_addr`.
        pub fn initTracedAt(identity: Identity, ret_addr: usize) B {
            if (!config.enabled) return .init(identity);

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

            mutex.lock(self);
            defer mutex.unlock(self);

            if (self.identity) |bound_identity|
                return self.failMismatchUnsafe(messages.already_bound, bound_identity, identity, ret_addr);

            self.bindUnsafe(identity, trace);
        }

        /// Binds `identityFn`'s identity if nothing is bound, otherwise does
        /// `assertUnchanged`.
        pub fn bindOrAssertUnchanged(self: *B) void {
            self.bindOrAssertUnchangedAt(@returnAddress());
        }

        /// `bindOrAssertUnchanged`, capturing and reporting from `ret_addr`.
        pub fn bindOrAssertUnchangedAt(self: *B, ret_addr: usize) void {
            if (!config.enabled) return;

            const identity = self.queryIdentity();

            mutex.lock(self);
            defer mutex.unlock(self);

            const bound_identity = self.identity orelse
                return self.bindUnsafe(identity, .captured(ret_addr));

            if (!std.meta.eql(bound_identity, identity))
                self.failMismatchUnsafe(messages.mismatch, bound_identity, identity, ret_addr);
        }

        /// Asserts `identityFn`'s identity is the bound one.
        pub fn assertUnchanged(self: *const B) void {
            self.assertUnchangedAt(@returnAddress());
        }

        /// `assertUnchanged`, reporting from `ret_addr`.
        pub fn assertUnchangedAt(self: *const B, ret_addr: usize) void {
            if (!config.enabled) return;
            self.assertEqlAt(self.queryIdentity(), ret_addr);
        }

        /// `assertUnchanged`, passing when nothing is bound.
        pub fn assertUnchangedOrUnbound(self: *const B) void {
            self.assertUnchangedOrUnboundAt(@returnAddress());
        }

        /// `assertUnchangedOrUnbound`, reporting from `ret_addr`.
        pub fn assertUnchangedOrUnboundAt(self: *const B, ret_addr: usize) void {
            if (!config.enabled) return;

            const identity = self.queryIdentity();

            mutex.lock(self);
            defer mutex.unlock(self);

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

            mutex.lock(self);
            defer mutex.unlock(self);

            const bound_identity = self.identity orelse
                return self.failUnboundUnsafe(identity, ret_addr);

            if (!std.meta.eql(bound_identity, identity))
                self.failMismatchUnsafe(messages.mismatch, bound_identity, identity, ret_addr);
        }

        /// Does `assertUnchanged`, then drops the binding.
        pub fn unbind(self: *B) void {
            self.unbindAt(@returnAddress());
        }

        /// `unbind`, capturing and reporting from `ret_addr`.
        pub fn unbindAt(self: *B, ret_addr: usize) void {
            if (!config.enabled) return;

            const identity = self.queryIdentity();
            const trace: Trace = .captured(ret_addr);

            mutex.lock(self);
            defer mutex.unlock(self);

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

            mutex.lock(self);
            defer mutex.unlock(self);

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
    disabled.bindOrAssertUnchanged();
    Id.current = 2;
    disabled.bindOrAssertUnchanged();
    disabled.assertEql(3);
    disabled.assertUnchanged();
    disabled.assertUnchangedOrUnbound();
    disabled.bind();
    disabled.unbind();
    disabled.unbind();
    try violation.expectNone();

    // Test correct behavior
    const Enabled = ConfigurableBoundTo(Id.identity, .{ .enabled = true }, .{});
    Id.current = 7;
    var enabled: Enabled = .unbound;

    // Test that `assertEql` and `assertUnchanged` never bind, so they fail before the first access
    enabled.assertEql(7);
    try violation.expect();
    enabled.assertUnchanged();
    try violation.expect();

    enabled.bindOrAssertUnchanged(); // The first access binds.
    enabled.assertEql(7);
    enabled.assertUnchanged();
    try violation.expectNone();

    // Test that a different identity fails
    Id.current = 8;
    enabled.bindOrAssertUnchanged();
    try violation.expect();
    enabled.assertEql(8);
    try violation.expect();
    enabled.assertUnchanged();
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
    enabled.bindOrAssertUnchanged();

    Id.current = 9;
    enabled.rebind();
    enabled.bindOrAssertUnchanged();

    Id.current = 10;
    enabled.rebind();
    enabled.assertEql(10);
    try violation.expectNone();

    // Test that an eager binding is in place before the first access
    var eager: Enabled = .init(11);
    try testing.expectEqual(11, eager.identity.?);
    eager.assertEql(11);
    eager.bindOrAssertUnchanged(); // `Id.current` is still 10, so this checks rather than binds.
    try violation.expect();
    Id.current = 11;
    eager.bindOrAssertUnchanged();
    try violation.expectNone();

    // Test that `bind` and `unbind` each assert the opposite state first
    var strict: Enabled = .unbound;
    strict.unbind();
    try violation.expect();
    strict.bind();
    strict.assertUnchanged();
    try violation.expectNone();
    strict.bind();
    try violation.expect();
    strict.unbind();
    strict.assertUnchanged();
    try violation.expect();
    strict.unbind();
    try violation.expect();
    strict.bind(); // Bindable again once unbound.
    strict.assertEql(11);
    try violation.expectNone();

    // Test that `assertUnchangedOrUnbound` passes when unbound, and checks otherwise
    var stamp: Enabled = .unbound;
    stamp.assertUnchangedOrUnbound();
    try violation.expectNone();
    stamp = .init(12);
    stamp.assertUnchangedOrUnbound();
    try violation.expect();
    stamp = .init(11);
    stamp.assertUnchangedOrUnbound();
    try violation.expectNone();
}

/// Asserts that every access happens under the same identity, where the
/// identity is whatever `identityFn(self)` returns: the current thread,
/// task, generation counter, and so on.
///
/// `identityFn` shall take `anytype` or `*const anyopaque` as its only
/// parameter and it will be a `*const` pointer to the `BoundTo` specification
/// instance itself, which you can pass to `@alignCast(@fieldParentPtr(...))`
/// to reach other values in the struct that contains it.
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
                .generation = .initTraced(arena.generation),
            };
        }

        const Handle = struct {
            const BoundToGeneration = BoundTo(currentGeneration);

            arena_generation: *const u32,
            generation: BoundToGeneration,

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

    handle_into_a.generation.bindOrAssertUnchanged();
    handle_into_b.generation.bindOrAssertUnchanged();

    b.reset();

    // `a` was not reset, so its handle is still valid.
    handle_into_a.generation.bindOrAssertUnchanged();

    var new_handle_into_b = b.handle();
    new_handle_into_b.generation.bindOrAssertUnchanged();

    handle_into_b.generation.bindOrAssertUnchanged();
    if (@as(Config, .{}).enabled)
        try violation.expect()
    else
        try violation.expectNone();
}

/// Detects when an address-sensitive value has been copied or moved.
///
/// Embed it in any struct that other code reaches through a pointer to one of
/// its fields (`@fieldParentPtr`), or that intrusive data structures point
/// into. `bindOrAssertUnchanged` pins the value at its current address the
/// first time it is called and asserts it has not moved on every later call,
/// so it can be called on every use.
///
/// A copy panics, reporting both addresses and where the original was pinned.
/// A copy carries the original's pin trace with it, so that trace shows where
/// the original was first checked, not where the copy was made.
///
/// See `ConfigurableBoundTo` to configure enable/disabled, thread safety and more.
pub const Pinned = ConfigurableBoundTo(addressOf, .{}, pinned_messages);

pub const pinned_messages: BoundToMessages = .{
    .mismatch = "pinned value accessed at a different address",
    .unbound = "accessed while not pinned",
    .already_bound = "pinned while already pinned",
    .last_bind = "pinned at",
    .last_unbind = "unpinned at",
};

/// An `identityFn` for `BoundTo` that returns the address of the `BoundTo`
/// itself.
pub fn addressOf(self: anytype) *const anyopaque {
    return self;
}
