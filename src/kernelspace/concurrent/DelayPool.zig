const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const BitSearch = @import("BitSearch");
const chunk_len = BitSearch.bits_per_word;
const kernel = @import("kernel");
const safety = @import("safety");

const DelayPool = @This();

io: std.Io,
chunks: *Chunk,
users_count: std.atomic.Value(u32),
all_released: std.Io.Event,
pending: safety.Obligations,
state: safety.State(Lifecycle),
address: safety.Pinned,

const Chunk = struct {
    entries: [chunk_len]DelayWork,
    free: BitSearch,
    pending: BitSearch,
    free_words: [chunk_words]std.atomic.Value(usize) align(std.atomic.cache_line),
    pending_words: [chunk_words]std.atomic.Value(usize) align(std.atomic.cache_line),
    next: std.atomic.Value(?*Chunk),
    atomically_allocated: bool,
};

const DelayWork = struct {
    work: kernel.CallbackHead,
    task: *kernel.Task,
    time: std.atomic.Value(usize),
    pool: *DelayPool,
};

const Lifecycle = enum { uninitialized, ready };
pub const Error = Allocator.Error || kernel.Task.WorkAddError;
const chunk_words = @divExact(chunk_len, BitSearch.bits_per_word);
const entries_span = chunk_len * @sizeOf(DelayWork);
const uninitialized = std.math.maxInt(u32);

pub const empty: DelayPool = .{
    .io = undefined,
    .chunks = undefined,
    .users_count = .init(uninitialized),
    .all_released = .unset,
    .pending = .none,
    .state = .init(.uninitialized),
    .address = .unbound,
};

pub fn init(this: *DelayPool, io: std.Io, allocator: Allocator) !void {
    this.state.assertEql(.uninitialized);
    this.state.transition(.ready);
    errdefer this.state.transition(.uninitialized);
    this.address.bind();

    this.chunks = try allocator.create(Chunk);
    this.initChunk(this.chunks, false);

    this.io = io;
    this.all_released = .unset;

    this.users_count = .init(1);
}

pub fn deinit(this: *DelayPool, allocator: Allocator, atomic_allocator: Allocator) void {
    if (this.users_count.load(.monotonic) == uninitialized) return;

    this.address.assertCurrent();

    // A pending delay still counts as a user and nothing is left to flush it
    this.cancelAllPending();
    this.pending.assertCount(.eq, 0);
    this.waitAllDelays();
    assert(this.users_count.load(.monotonic) == 0);

    var chunk: ?*Chunk = this.chunks;

    while (chunk) |c| {
        chunk = c.next.load(.acquire);
        (if (c.atomically_allocated) atomic_allocator else allocator).destroy(c);
    }

    this.* = undefined;
}

pub fn delay(this: *DelayPool, allocator: Allocator, atomic_allocator: Allocator, task: *kernel.Task, delay_time: usize) Error!void {
    this.state.assertEql(.ready);

    const slot = try this.reserve(allocator, atomic_allocator, task, delay_time);
    errdefer this.cancel(slot);

    try task.workAdd(&slot.work, .@"resume");
}

pub fn pendDelay(this: *DelayPool, allocator: Allocator, atomic_allocator: Allocator, task: *kernel.Task, delay_time: usize) Allocator.Error!void {
    this.state.assertEql(.ready);

    const slot = try this.reserve(allocator, atomic_allocator, task, delay_time);
    const chunk = this.chunkOf(slot);

    chunk.pending.take(indexOf(chunk, slot));
    this.pending.incur();
}

pub fn flushPending(this: *DelayPool) kernel.Task.WorkAddError!void {
    this.state.assertEql(.ready);

    var failure: ?kernel.Task.WorkAddError = null;
    var chunk: ?*Chunk = this.chunks;

    while (chunk) |c| : (chunk = c.next.load(.acquire)) {
        var it = c.pending.iterate();

        while (it.next()) |index| {
            const slot = &c.entries[index];
            c.pending.release(index);
            this.pending.discharge();

            slot.task.workAdd(&slot.work, .signal) catch |err| {
                this.cancel(slot);

                if (err != error.TooLateShuttingDown) failure = err;
            };
        }
    }

    this.pending.assertCount(.eq, 0);

    if (failure) |err| return err;
}

pub fn waitAllDelays(this: *DelayPool) void {
    this.releaseUser();
    this.all_released.waitUncancelable(this.io);
}

fn reserve(this: *DelayPool, allocator: Allocator, atomic_allocator: Allocator, task: *kernel.Task, delay_time: usize) Allocator.Error!*DelayWork {
    this.address.assertCurrent();
    assert(delay_time != 0);

    _ = this.users_count.fetchAdd(1, .monotonic);
    errdefer this.releaseUser();

    const slot = this.getEntry() orelse try this.reserveInNewAllocation(allocator, atomic_allocator);

    task.get();
    slot.task = task;
    slot.time.store(delay_time, .release);

    return slot;
}

fn getEntry(this: *DelayPool) ?*DelayWork {
    var chunk: ?*Chunk = this.chunks;

    return while (chunk) |c| : (chunk = c.next.load(.acquire)) {
        if (c.free.takeFirstFree()) |index| break &c.entries[index];
    } else null;
}

fn initChunk(this: *DelayPool, chunk: *Chunk, atomically_allocated: bool) void {
    chunk.free_words = @splat(.init(0));
    chunk.pending_words = @splat(.init(0));
    chunk.free = .{ .words = &chunk.free_words };
    chunk.pending = .{ .words = &chunk.pending_words };
    chunk.next = .init(null);
    chunk.atomically_allocated = atomically_allocated;

    for (&chunk.entries) |*entry| entry.* = .{
        .work = .{ .func = executeDelay, .next = undefined },
        .task = undefined,
        .pool = this,
        .time = undefined,
    };
}

fn reserveInNewAllocation(this: *DelayPool, allocator: Allocator, atomic_allocator: Allocator) Allocator.Error!*DelayWork {
    const atomic = !kernel.preemptible();
    const chunk_allocator = if (atomic) atomic_allocator else allocator;

    const new_chunk = try chunk_allocator.create(Chunk);
    errdefer chunk_allocator.destroy(new_chunk);

    this.initChunk(new_chunk, atomic);

    const slot = &new_chunk.entries[new_chunk.free.takeFirstFree().?];
    this.appendChunk(new_chunk);

    return slot;
}

fn appendChunk(this: *DelayPool, new_chunk: *Chunk) void {
    var chunk = this.chunks;
    while (chunk.next.cmpxchgStrong(null, new_chunk, .release, .acquire)) |taken| chunk = taken.?;
}

fn chunkOf(this: *DelayPool, slot: *DelayWork) *Chunk {
    const slot_address = @intFromPtr(slot);

    var chunk: ?*Chunk = this.chunks;
    return while (chunk) |c| : (chunk = c.next.load(.acquire)) {
        const base = @intFromPtr(&c.entries);
        if (slot_address >= base and slot_address - base < entries_span) break c;
    } else unreachable;
}

fn indexOf(chunk: *Chunk, slot: *DelayWork) usize {
    const slot_address: usize = @intFromPtr(slot);
    const starting_address: usize = @intFromPtr(&chunk.entries);
    return @divExact(slot_address - starting_address, @sizeOf(DelayWork));
}

fn freeEntry(this: *DelayPool, slot: *DelayWork) void {
    const chunk = this.chunkOf(slot);
    chunk.free.release(indexOf(chunk, slot));
}

fn cancel(this: *DelayPool, slot: *DelayWork) void {
    slot.task.put();
    this.freeEntry(slot);
    this.releaseUser();
}

fn cancelAllPending(this: *DelayPool) void {
    var chunk: ?*Chunk = this.chunks;

    while (chunk) |c| : (chunk = c.next.load(.acquire)) {
        var it = c.pending.iterate();

        while (it.next()) |index| {
            c.entries[index].task.put();
            c.pending.release(index);
            this.pending.discharge();
            c.free.release(index);
            this.releaseUser();
        }
    }
}

fn releaseUser(this: *DelayPool) void {
    if (this.users_count.fetchSub(1, .acq_rel) == 1) this.all_released.set(this.io);
}

fn executeDelay(work: *kernel.CallbackHead) callconv(.c) void {
    const slot: *DelayWork = @fieldParentPtr("work", work);
    const delay_time = slot.time.load(.acquire);
    const this: *DelayPool = slot.pool;
    const task = slot.task;

    this.freeEntry(slot);
    task.put();

    this.io.sleep(.fromMicroseconds(@intCast(delay_time)), .awake) catch unreachable;

    this.releaseUser();
}
