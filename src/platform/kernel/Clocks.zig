const std = @import("std");
const isPowerOfTwo = std.math.isPowerOfTwo;
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const BitSearch = @import("BitSearch");
const min_cap = BitSearch.bits_per_word;
const clock_types = @import("clock_types");
pub const Ticks = clock_types.Ticks;
pub const Master = clock_types.Master;
const Epoch = clock_types.Epoch;
const Value = clock_types.Value;
pub const Slot = clock_types.Slot;
const no_recent_hit = clock_types.no_recent_hit;
const kernel = @import("kernel");
const Task = kernel.Task;
const RefGate = @import("RefGate");
const safety = @import("safety");

/// Concurrent map optimized for thread-local clock propagation.
const Clocks = @This();

master: std.atomic.Value(Master) align(std.atomic.cache_line),
ref: RefGate,
pairs: []Pair,
used: BitSearch,
atomically_allocated: bool,
reservations: Reservations,
references: References,
allocator: Allocator,
atomic_allocator: Allocator,

const Key = bitpack struct(usize) {
    data: usize,

    // Task pointers are always aligned so the first bit will always be 0
    // and we can use that as collide flag
    const collided_bit: usize = 1;
    const empty: Key = .{ .data = 0 };
    const empty_collided: Key = .{ .data = collided_bit };
    const reserved: Key = .{ .data = std.math.maxInt(usize) & ~collided_bit };

    fn isEql(this: Key, other: Key) bool {
        return (this.data | collided_bit) == (other.data | collided_bit);
    }

    fn hasCollided(this: Key) bool {
        return (this.data & collided_bit) != 0;
    }

    fn hash(this: Key) usize {
        return std.hash.int(this.data);
    }

    fn withCollisionBit(this: Key) Key {
        return .{ .data = this.data | collided_bit };
    }

    fn withoutCollisionBit(this: Key) Key {
        return .{ .data = this.data & ~collided_bit };
    }
};

const Pair = struct {
    key: std.atomic.Value(Key),
    slot: Slot,

    const empty: Pair = .{ .key = .init(.empty), .slot = .{ .value = undefined, .since_hit = .init(no_recent_hit) } };
};

const Reservations = safety.ConfigurableObligations(.{ .thread_safe = true }, .{});
const References = safety.ConfigurableObligations(.{ .thread_safe = true }, .{});
const reserve = 1024;

const InsertError = error{NoSpace};
pub const Error = InsertError || Allocator.Error;

pub const iteration_freezes = true;

pub const Guard = struct {
    clocks: *Clocks,

    pub fn release(this: Guard) void {
        this.clocks.ref.decrement();
        kernel.preempt.enable();
    }

    pub fn master(this: Guard) Master {
        return this.clocks.master.load(.monotonic);
    }

    pub fn advanceMaster(this: Guard, epoch: Epoch, ticks: Ticks) void {
        var observed = this.master();
        while (observed.epoch == epoch and observed.ticks < ticks) {
            const advanced: Master = .{ .ticks = ticks, .epoch = epoch };
            observed = this.clocks.master.cmpxchgWeak(observed, advanced, .monotonic, .monotonic) orelse return;
        }
    }

    pub fn slot(this: Guard, task: *const Task) ?*Slot {
        const pair = this.clocks.getSlotUnsafe(keyFromTask(task)) orelse return null;
        return &pair.slot;
    }
};

pub fn init(allocator: Allocator, atomic_allocator: Allocator) Allocator.Error!Clocks {
    return initCapacity(allocator, atomic_allocator, reserve);
}

fn initCapacity(allocator: Allocator, atomic_allocator: Allocator, capacity: usize) Allocator.Error!Clocks {
    assert(isPowerOfTwo(capacity));
    assert(capacity >= min_cap);

    const pairs = try allocator.alloc(Pair, capacity);
    errdefer allocator.free(pairs);
    @memset(pairs, Pair.empty);

    return .{
        .master = .init(.begin(0)),
        .ref = .{},
        .pairs = pairs,
        .used = try .init(allocator, capacity),
        .atomically_allocated = false,
        .reservations = .none,
        .references = .none,
        .allocator = allocator,
        .atomic_allocator = atomic_allocator,
    };
}

pub fn deinit(this: *Clocks) void {
    kernel.preempt.disable();
    defer kernel.preempt.enable();

    this.ref.close();
    this.ref.drain();
    this.reservations.assert(.eq, 0);

    var it = this.used.iterate();
    while (it.next()) |index| this.release(taskFromKey(this.pairs[index].key.raw));
    this.references.assert(.eq, 0);

    const table_allocator = if (this.atomically_allocated) this.atomic_allocator else this.allocator;
    table_allocator.free(this.pairs);
    this.used.deinit(table_allocator);

    this.* = undefined;
}

pub fn track(this: *Clocks, owned: *Task) void {
    const guard = this.takeGuard();
    defer guard.release();

    this.references.assert(.eq, 0);
    this.references.incur();
    // Only the first key, the reserve always has room for it.
    this.insertKey(keyFromTask(owned), .at(guard.master())) catch unreachable;
}

pub fn takeGuard(this: *Clocks) Guard {
    kernel.preempt.disable();
    this.ref.increment();
    return .{ .clocks = this };
}

/// Null when the map is gated: callers in irq context cannot spin on a gate
/// this cpu may itself hold.
pub fn tryTakeGuard(this: *Clocks) ?Guard {
    kernel.preempt.disable();
    this.ref.tryIncrement() catch {
        kernel.preempt.enable();
        return null;
    };
    return .{ .clocks = this };
}

pub fn beginEpoch(this: *Clocks) void {
    this.master.store(.begin(this.master.load(.monotonic).epoch + 1), .monotonic);
}

pub fn insert(this: *Clocks, task: *Task) Error!void {
    this.tryInsert(task) catch |err| switch (err) {
        InsertError.NoSpace => {
            try this.grow();
            try this.tryInsert(task);
        },
    };
}

fn tryInsert(this: *Clocks, task: *Task) InsertError!void {
    const guard = this.takeGuard();
    defer guard.release();

    try this.insertKey(keyFromTask(task), .at(guard.master()));
    this.retain(task);
}

pub fn remove(this: *Clocks, task: *Task) void {
    {
        const guard = this.takeGuard();
        defer guard.release();

        const removed = this.removeKey(keyFromTask(task));
        assert(removed);
    }

    this.release(task);
}

pub fn forEachExclusive(this: *Clocks, context: anytype, comptime E: type, comptime visit: fn (@TypeOf(context), *Task, *Slot, Master) E!void) E!Master {
    kernel.preempt.disable();
    defer kernel.preempt.enable();

    this.ref.close();
    this.ref.drain();
    defer this.ref.open();

    // Read after the gate closed, a tick still in flight would push a clock
    // past it and underflow the lag
    const master = this.master.load(.monotonic);

    var it = this.used.iterate();
    while (it.next()) |index| {
        const pair = &this.pairs[index];
        try visit(context, taskFromKey(pair.key.raw), &pair.slot, master);
    }

    return master;
}

fn retain(this: *Clocks, task: *Task) void {
    kernel.preempt.disable();
    defer kernel.preempt.enable();

    task.get();
    this.references.incur();
}

fn release(this: *Clocks, task: *Task) void {
    kernel.preempt.disable();
    defer kernel.preempt.enable();

    task.put();
    this.references.discharge();
}

fn keyFromTask(task: *const Task) Key {
    assert(@intFromPtr(task) % 2 == 0);
    return .{ .data = @intFromPtr(task) };
}

fn taskFromKey(key: Key) *Task {
    return @ptrFromInt(key.withoutCollisionBit().data);
}

fn insertKey(this: *Clocks, key: Key, value: Value) InsertError!void {
    const pair = try this.reserveSlotUnsafe(key);
    pair.slot.value.store(value, .monotonic);
    this.publishReservedUnsafe(key, pair);
}

fn reserveSlotUnsafe(this: *Clocks, key: Key) InsertError!*Pair {
    const len = this.pairs.len;

    // bit 0 is reserved for the collision flag; callers must pass it clear.
    assert(!key.hasCollided());
    assert(isPowerOfTwo(len));
    const index_mask = len - 1;
    const max_retries = @max(16, len / 32);
    const hash = key.hash();

    var i: usize = 0;
    while (i < max_retries) : (i += 1) {
        const index = (hash + i) & index_mask;
        const current_key = this.pairs[index].key.load(.monotonic);

        // Double insertion of the same key would mean broken logic
        assert(!current_key.isEql(key));

        // or will preserve the collided bit.
        const reservation: Key = .{ .data = Key.reserved.data | current_key.data };

        if (current_key.isEql(.empty) and
            this.pairs[index].key.cmpxchgStrong(current_key, reservation, .acquire, .monotonic) == null)
        {
            this.reservations.incur();
            return &this.pairs[index];
        }

        if (!current_key.hasCollided())
            _ = this.pairs[index].key.fetchOr(Key.empty_collided, .monotonic);
    }

    return InsertError.NoSpace;
}

fn publishReservedUnsafe(this: *Clocks, key: Key, ptr: *Pair) void {
    assert(ptr.key.load(.unordered).isEql(.reserved));

    this.used.take(this.getIndexUnsafe(ptr));
    ptr.slot.since_hit.store(no_recent_hit, .monotonic);

    _ = ptr.key.fetchAnd(key.withCollisionBit(), .release);

    this.reservations.discharge();
}

/// Looks up the clock slot for a given key.
///
/// A task is tracked from its fork until its exit probe removes it. Probes that
/// act on a live profiled task (fork parent, sleep, wakee) must find it, so a
/// null there is a tracking failure and should be asserted with .?.
///
/// The sampler cannot assert: the perf event stays armed after the exit probe
/// until perf_event_exit_task, so an exiting thread can still be sampled once
/// its slot is gone, and that sample is dropped. A task with no slot otherwise
/// counts as having no accumulated delay, so it is treated as level with the
/// Master Clock (the waker case).
fn getSlotUnsafe(this: *const Clocks, key: Key) ?*Pair {
    const len = this.pairs.len;

    assert(isPowerOfTwo(len));
    const index_mask = len - 1;
    const hash = key.hash();

    var i: usize = 0;
    var current_key: Key = .empty_collided;
    return slot: while (current_key.hasCollided() and i < len) : (i += 1) {
        const index = (hash + i) & index_mask;
        current_key = this.pairs[index].key.load(.acquire);
        if (current_key.isEql(key)) break :slot &this.pairs[index];
    } else null;
}

fn getIndexUnsafe(this: *const Clocks, elm: *const Pair) usize {
    const elm_addr: usize = @intFromPtr(elm);
    const starting_addr: usize = @intFromPtr(this.pairs.ptr);
    return @divExact(elm_addr - starting_addr, @sizeOf(Pair));
}

fn removeKey(this: *Clocks, key: Key) bool {
    const pair = this.getSlotUnsafe(key) orelse return false;
    this.used.release(this.getIndexUnsafe(pair));
    _ = pair.key.fetchAnd(Key.empty_collided, .release);

    return true;
}

fn grow(this: *Clocks) Allocator.Error!void {
    kernel.preempt.disable();
    defer kernel.preempt.enable();

    const atomic_allocator = this.atomic_allocator;

    // Allocate before closing: readers spin on a closed gate, so nothing that
    // can sleep may run inside it. That makes old_len a guess, re-read below.
    this.ref.increment();
    const old_len = this.pairs.len;
    this.ref.decrement();

    const new_len = old_len * 2;
    assert(isPowerOfTwo(new_len));
    const new_pairs = try atomic_allocator.alloc(Pair, new_len);
    errdefer atomic_allocator.free(new_pairs);
    @memset(new_pairs, Pair.empty);

    var new_used: BitSearch = try .init(atomic_allocator, new_len);

    this.ref.close();
    this.ref.drain();
    this.reservations.assert(.eq, 0);

    // Another grower got there first; its table is already the size we wanted.
    if (this.pairs.len != old_len) {
        this.ref.open();
        atomic_allocator.free(new_pairs);
        new_used.deinit(atomic_allocator);
        return;
    }

    const index_mask = new_len - 1;
    var it = this.used.iterate();
    while (it.next()) |slot| {
        const pair = &this.pairs[slot];
        // The bit belongs to the old position, not to the key.
        const key = pair.key.raw.withoutCollisionBit();
        const value = pair.slot.value.raw;
        const hash = key.hash();

        for (0..new_len) |i| {
            const index = (hash + i) & index_mask;

            if (new_pairs[index].key.raw.isEql(.empty)) {
                new_pairs[index] = .{ .key = .init(key), .slot = .{ .value = .init(value), .since_hit = .init(pair.slot.since_hit.raw) } };
                new_used.takeUnordered(index);
                break;
            }

            // getSlotUnsafe walks while the previous slot carries this bit, so
            // an unmarked slot we probed past would strand the key we place
            // further along and report a tracked thread as untracked.
            new_pairs[index].key.raw.data |= Key.collided_bit;
        } else unreachable;
    }

    const old_pairs = this.pairs;
    const old_used = this.used;
    const old_allocator = if (this.atomically_allocated) atomic_allocator else this.allocator;

    this.pairs = new_pairs;
    this.used = new_used;
    this.atomically_allocated = true;

    this.ref.open();

    old_allocator.free(old_pairs);
    old_used.deinit(old_allocator);
}

fn valueOf(this: *Clocks, key: Key) Value {
    this.ref.increment();
    defer this.ref.decrement();

    return this.getSlotUnsafe(key).?.slot.value.load(.monotonic);
}

fn ticksOf(this: *Clocks, key: Key) Ticks {
    return this.valueOf(key).ticks;
}

fn isTaken(this: *const Clocks, key: Key) bool {
    const slot = this.getSlotUnsafe(key) orelse return false;

    return this.used.isTaken(this.getIndexUnsafe(slot));
}

const TestError = error{Busy};

fn testTick(clocks: *Clocks, key: Key) TestError!void {
    const guard = clocks.tryTakeGuard() orelse return TestError.Busy;
    defer guard.release();

    const epoch = guard.master().epoch;
    if (guard.slot(taskFromKey(key)).?.tick(epoch)) |ticks| guard.advanceMaster(epoch, ticks);
}

fn testFork(clocks: *Clocks, parent: Key, child: Key) InsertError!Ticks {
    const guard = clocks.takeGuard();
    defer guard.release();

    const master = guard.master();
    try clocks.insertKey(child, .at(master));
    clocks.retain(taskFromKey(child));
    return guard.slot(taskFromKey(parent)).?.catchUp(master, 0) orelse 0;
}

fn testPut(clocks: *Clocks, key: Key, ticks: Ticks) InsertError!void {
    const guard = clocks.takeGuard();
    defer guard.release();

    try clocks.insertKey(key, .at(.{ .ticks = ticks, .epoch = guard.master().epoch }));
    clocks.retain(taskFromKey(key));
}

fn testRemove(clocks: *Clocks, key: Key) bool {
    const removed = removed: {
        const guard = clocks.takeGuard();
        defer guard.release();

        break :removed clocks.removeKey(key);
    };

    if (removed) clocks.release(taskFromKey(key));
    return removed;
}

test "Clocks: basic lifecycle" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    const key1: Key = .{ .data = 100 };
    const key2: Key = .{ .data = 200 };

    try testPut(&clocks, key1, 10);
    try testPut(&clocks, key2, 20);

    try testing.expectEqual(10, clocks.ticksOf(key1));
    try testing.expectEqual(20, clocks.ticksOf(key2));
}

test "Clocks: tick and master propagation" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    const key: Key = .{ .data = 2 };
    try testPut(&clocks, key, 5);

    try testTick(&clocks, key);
    try testing.expectEqual(6, clocks.ticksOf(key));
    try testing.expectEqual(6, clocks.master.load(.monotonic).ticks);

    try testTick(&clocks, key);
    try testing.expectEqual(7, clocks.ticksOf(key));
    try testing.expectEqual(7, clocks.master.load(.monotonic).ticks);
}

test "Clocks: fork" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    const parent: Key = .{ .data = 2 };
    const child: Key = .{ .data = 4 };

    try testPut(&clocks, parent, 50);
    clocks.master.store(.{ .ticks = 100, .epoch = 0 }, .monotonic);

    const delay = try testFork(&clocks, parent, child);

    try testing.expectEqual(50, delay);
    try testing.expectEqual(100, clocks.ticksOf(parent));
    try testing.expectEqual(100, clocks.ticksOf(child));
}

test "Clocks: collision path" {
    const allocator = testing.allocator;

    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    // Use enough entries that collisions are plausible (half capacity).
    var keys: [min_cap / 2]Key = undefined;
    var expected: [min_cap / 2]Ticks = undefined;
    for (&keys, &expected, 0..) |*key, *expected_elm, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        expected_elm.* = @intCast((i + 1) * 10);
    }

    for (keys, expected) |key, ticks| try testPut(&clocks, key, ticks);
    for (keys, expected) |key, ticks| try testing.expectEqual(ticks, clocks.ticksOf(key));
}

test "Clocks: concurrent stress" {
    const allocator = testing.allocator;

    var clocks = try Clocks.initCapacity(allocator, allocator, 128);
    defer clocks.deinit();

    const thread_count = 8;
    const ops_per_thread = 10_000;

    const Context = struct {
        clocks: *Clocks,
        id: usize,
        registered: *std.atomic.Value(u32),

        fn run(ctx: *@This()) void {
            var prng = std.Random.DefaultPrng.init(ctx.id * 0xDEAD_BEEF);
            const random = prng.random();

            const key: Key = .{ .data = @intCast((ctx.id + 1) * 2) };

            _ = ctx.registered.fetchAdd(1, .monotonic);
            while (ctx.registered.load(.monotonic) < thread_count) std.atomic.spinLoopHint();

            for (0..ops_per_thread) |i|
                switch (random.uintLessThan(u8, 3)) {
                    1 => testTick(ctx.clocks, key) catch {},
                    2 => {
                        const child_virtual_key: Key = .{ .data = @intCast((ctx.id * ops_per_thread + i) * 2 + 100) };
                        if (testFork(ctx.clocks, key, child_virtual_key)) |_| {
                            for (0..3) |_| testTick(ctx.clocks, child_virtual_key) catch break;
                        } else |_| continue;
                    },
                    else => {},
                };
        }
    };

    const root: Key = .{ .data = 2 };
    try testPut(&clocks, root, 0);
    for (1..thread_count) |i| {
        const child: Key = .{ .data = @intCast((i + 1) * 2) };
        _ = try testFork(&clocks, root, child);
    }

    var registered = std.atomic.Value(u32).init(0);
    var contexts: [thread_count]Context = undefined;
    var threads: [thread_count]std.Thread = undefined;

    for (&contexts, &threads, 0..) |*context, *thread, i| {
        context.* = .{ .clocks = &clocks, .id = i, .registered = &registered };
        thread.* = try .spawn(.{}, Context.run, .{context});
    }
    for (threads) |t| t.join();

    const master = clocks.master.load(.monotonic).ticks;

    for (0..thread_count) |i| {
        const key: Key = .{ .data = @intCast((i + 1) * 2) };
        try testing.expect(master >= clocks.ticksOf(key));
    }

    for (clocks.pairs) |pair| {
        const key = pair.key.load(.monotonic);
        if (key.isEql(.empty) or key.isEql(.reserved)) continue;
        const ticks = pair.slot.value.load(.monotonic).ticks;
        try testing.expect(master >= ticks);
    }
}

test "Clocks: concurrent grow" {
    const allocator = testing.allocator;

    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    const root: Key = .{ .data = 2 };
    try testPut(&clocks, root, 0);

    const thread_count = 4;

    const Context = struct {
        clocks: *Clocks,
        id: usize,

        fn run(ctx: *@This()) void {
            const key: Key = .{ .data = @intCast((ctx.id + 2) * 2) };
            const root_key: Key = .{ .data = 2 };
            _ = testFork(ctx.clocks, root_key, key) catch return;

            for (0..5_000) |_| testTick(ctx.clocks, key) catch break;
        }
    };

    const GrowContext = struct {
        clocks: *Clocks,

        fn run(ctx: *@This()) void {
            std.atomic.spinLoopHint();

            ctx.clocks.grow() catch return;
        }
    };

    var worker_contexts: [thread_count]Context = undefined;
    var threads: [thread_count + 1]std.Thread = undefined;
    var grow_ctx = GrowContext{ .clocks = &clocks };

    threads[thread_count] = try .spawn(.{}, GrowContext.run, .{&grow_ctx});
    for (&worker_contexts, threads[0 .. threads.len - 1], 0..) |*context, *thread, i| {
        context.* = .{ .clocks = &clocks, .id = i };
        thread.* = try .spawn(.{}, Context.run, .{context});
    }
    for (threads) |t| t.join();

    try testing.expect(clocks.pairs.len >= min_cap);

    const master = clocks.master.load(.monotonic).ticks;
    for (0..thread_count) |i| {
        const key: Key = .{ .data = @intCast((i + 2) * 2) };
        try testing.expect(master >= clocks.ticksOf(key));
    }
}

test "Clocks: tryTakeGuard on a closed gate returns null instead of blocking" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    clocks.ref.close();
    clocks.ref.drain();
    try testing.expectEqual(null, clocks.tryTakeGuard());

    clocks.ref.open();
    const guard = clocks.tryTakeGuard().?;
    guard.release();
}

test "Clocks: remove tolerates untracked keys" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    const tracked: Key = .{ .data = 2 };
    const untracked: Key = .{ .data = 4 };

    try testPut(&clocks, tracked, 10);

    try testing.expectEqual(false, testRemove(&clocks, untracked));
    try testing.expectEqual(1, clocks.used.countTaken());

    try testing.expectEqual(true, testRemove(&clocks, tracked));
    try testing.expectEqual(0, clocks.used.countTaken());
}

test "Clocks: put takes the slot, remove releases it" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    try testing.expectEqual(0, clocks.used.countTaken());

    const key: Key = .{ .data = 42 };
    try testPut(&clocks, key, 0);

    try testing.expect(clocks.isTaken(key));
    try testing.expectEqual(1, clocks.used.countTaken());

    _ = testRemove(&clocks, key);

    try testing.expect(!clocks.isTaken(key));
    try testing.expectEqual(0, clocks.used.countTaken());
}

test "Clocks: taken count tracks live entries across puts and removes" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    var keys: [16]Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try testPut(&clocks, key.*, 0);
        try testing.expectEqual(i + 1, clocks.used.countTaken());
    }

    var live = keys.len;
    for (&keys, 0..) |*key, i| {
        if (i % 2 == 1) continue;
        _ = testRemove(&clocks, key.*);
        live -= 1;
        try testing.expectEqual(live, clocks.used.countTaken());
    }
}

test "Clocks: fork takes the child slot without releasing the parent" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    const parent: Key = .{ .data = 2 };
    const child: Key = .{ .data = 4 };

    try testPut(&clocks, parent, 10);
    clocks.master.store(.{ .ticks = 10, .epoch = 0 }, .monotonic); // master must be >= ticks to avoid underflow in fork
    try testing.expectEqual(1, clocks.used.countTaken());

    _ = try testFork(&clocks, parent, child);

    try testing.expect(clocks.isTaken(parent));
    try testing.expect(clocks.isTaken(child));
    try testing.expectEqual(2, clocks.used.countTaken());
}

test "Clocks: grow migrates every taken slot and releases none" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    var keys: [8]Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try testPut(&clocks, key.*, @intCast(i * 10));
    }

    try testing.expectEqual(keys.len, clocks.used.countTaken());

    try clocks.grow();

    for (keys) |key| try testing.expect(clocks.isTaken(key));

    try testing.expectEqual(keys.len, clocks.used.countTaken());
}

test "Clocks: grow with partial removes, only live entries stay taken" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    var keys: [12]Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try testPut(&clocks, key.*, 0);
    }

    for (&keys, 0..) |key, i| _ = if (i % 2 == 0) testRemove(&clocks, key);

    try testing.expectEqual(keys.len / 2, clocks.used.countTaken());

    try clocks.grow();

    try testing.expectEqual(keys.len / 2, clocks.used.countTaken());

    for (&keys, 0..) |key, i|
        if (i % 2 == 0)
            try testing.expect(!clocks.isTaken(key))
        else
            try testing.expect(clocks.isTaken(key));
}

test "Clocks: grow preserves ticks and pending lag" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    var keys: [8]Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try testPut(&clocks, key.*, @intCast(i * 10));
    }

    for (keys, 0..) |key, i| if (i % 2 == 0) {
        const pair = clocks.getSlotUnsafe(key).?;
        pair.slot.value.store(.{ .ticks = @intCast(i * 10), .master_at_sleep = 100, .epoch = 0 }, .monotonic);
    };

    try clocks.grow();

    for (keys, 0..) |key, i| {
        const value = clocks.valueOf(key);
        try testing.expectEqual(i * 10, value.ticks);
        try testing.expectEqual(if (i % 2 == 0) 100 else i * 10, value.master_at_sleep);
    }
}

test "Clocks: repeated grow keeps every entry reachable" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    var keys: [min_cap / 2]Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try testPut(&clocks, key.*, @intCast(i));
    }

    for (0..2) |_| {
        try clocks.grow();
    }

    try testing.expectEqual(min_cap * 4, clocks.pairs.len);
    try testing.expectEqual(keys.len, clocks.used.countTaken());
    for (keys, 0..) |key, i| try testing.expectEqual(i, clocks.ticksOf(key));
}

test "Clocks: slot reuse after remove" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    const key: Key = .{ .data = 42 };

    try testPut(&clocks, key, 7);
    _ = testRemove(&clocks, key);
    try testPut(&clocks, key, 9);

    try testing.expectEqual(9, clocks.ticksOf(key));
    try testing.expectEqual(1, clocks.used.countTaken());
}

test "Clocks: racing growers keep every entry" {
    const allocator = testing.allocator;

    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    var keys: [min_cap / 2]Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try testPut(&clocks, key.*, @intCast(i));
    }

    const grower_count = 4;

    const GrowContext = struct {
        clocks: *Clocks,
        ready: *std.atomic.Value(u32),

        fn run(ctx: *@This()) void {
            _ = ctx.ready.fetchAdd(1, .monotonic);
            while (ctx.ready.load(.monotonic) < grower_count) std.atomic.spinLoopHint();

            ctx.clocks.grow() catch return;
        }
    };

    var ready: std.atomic.Value(u32) = .init(0);
    var contexts: [grower_count]GrowContext = undefined;
    var threads: [grower_count]std.Thread = undefined;

    for (&contexts, &threads) |*context, *thread| {
        context.* = .{ .clocks = &clocks, .ready = &ready };
        thread.* = try .spawn(.{}, GrowContext.run, .{context});
    }
    for (threads) |t| t.join();

    try testing.expectEqual(keys.len, clocks.used.countTaken());
    for (keys, 0..) |key, i| try testing.expectEqual(i, clocks.ticksOf(key));
}

test "Clocks: the taken bits of a grown map point at live entries" {
    const allocator = testing.allocator;
    var clocks = try Clocks.initCapacity(allocator, allocator, min_cap);
    defer clocks.deinit();

    var keys: [20]Key = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = .{ .data = @intCast((i + 1) * 2) };
        try testPut(&clocks, key.*, 0);
    }

    for (&keys, 0..) |key, i| _ = if (i % 2 == 0) testRemove(&clocks, key);

    try clocks.grow();

    var live: usize = 0;
    var it = clocks.used.iterate();
    while (it.next()) |index| : (live += 1) {
        const key = clocks.pairs[index].key.raw.withoutCollisionBit();

        try testing.expect(!key.isEql(.empty));
        try testing.expect(!key.isEql(.reserved));
        try testing.expect(clocks.isTaken(key));
    }

    try testing.expectEqual(keys.len / 2, live);
}
