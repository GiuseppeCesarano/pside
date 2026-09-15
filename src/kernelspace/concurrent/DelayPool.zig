const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const BitSearch = @import("BitSearch");
const chunk_len = BitSearch.bits_per_word;
const kernel = @import("kernel");
const allocator = kernel.heap.allocator;
const atomic_allocator = kernel.heap.atomic_allocator;

const DelayPool = @This();

pub const Error = Allocator.Error || kernel.Task.WorkAddError;

const chunk_words = @divExact(chunk_len, BitSearch.bits_per_word);
const entries_span = chunk_len * @sizeOf(DelayWork);

const DelayWork = struct {
    work: kernel.Task.Work,
    task: *kernel.Task,
    time: std.atomic.Value(usize),
    pool: *DelayPool,
};

const Chunk = struct {
    entries: [chunk_len]DelayWork,
    free: BitSearch,
    pending: BitSearch,
    free_words: [chunk_words]std.atomic.Value(usize) align(std.atomic.cache_line),
    pending_words: [chunk_words]std.atomic.Value(usize) align(std.atomic.cache_line),
    next: std.atomic.Value(?*Chunk),
};

const uninitialized = std.math.maxInt(u32);

chunks: *Chunk,
users_count: std.atomic.Value(u32),
completion: kernel.Completion,

pub const empty: DelayPool = .{
    .chunks = undefined,
    .users_count = .init(uninitialized),
    .completion = undefined,
};

pub fn init(this: *DelayPool) !void {
    if (this.users_count.load(.monotonic) != uninitialized) return;

    this.users_count = .init(0);

    this.chunks = try allocator.create(Chunk);
    this.initChunk(this.chunks);

    this.completion.init();
}

pub fn deinit(this: *DelayPool) void {
    if (this.users_count.load(.monotonic) == uninitialized) return;

    // A pending delay still counts as a user and nothing is left to flush it
    this.cancelAllPending();
    this.waitAllDelays();

    var chunk: ?*Chunk = this.chunks.next.load(.monotonic);

    while (chunk) |c| {
        chunk = c.next.load(.monotonic);
        atomic_allocator.destroy(c);
    }

    allocator.destroy(this.chunks);

    this.* = undefined;
}

pub fn delay(this: *DelayPool, task: *kernel.Task, delay_time: usize) Error!void {
    const slot = try this.reserve(task, delay_time);
    errdefer this.cancel(slot);

    try task.addWork(&slot.work, .@"resume");
}

pub fn pendDelay(this: *DelayPool, task: *kernel.Task, delay_time: usize) Allocator.Error!void {
    const slot = try this.reserve(task, delay_time);
    const chunk = this.chunkOf(slot);

    chunk.pending.take(indexOf(chunk, slot));
}

pub fn flushPending(this: *DelayPool) kernel.Task.WorkAddError!void {
    var failure: ?kernel.Task.WorkAddError = null;
    var chunk: ?*Chunk = this.chunks;

    while (chunk) |c| : (chunk = c.next.load(.monotonic)) {
        var it = c.pending.iterate();

        while (it.next()) |index| {
            const slot = &c.entries[index];
            c.pending.release(index);

            slot.task.addWork(&slot.work, .signal) catch |err| {
                this.cancel(slot);

                if (err != error.TooLateShuttingDown) failure = err;
            };
        }
    }

    if (failure) |err| return err;
}

pub fn waitAllDelays(this: *DelayPool) void {
    this.completion.reinit();
    if (this.users_count.load(.monotonic) != 0) this.completion.wait();
}

fn reserve(this: *DelayPool, task: *kernel.Task, delay_time: usize) Allocator.Error!*DelayWork {
    assert(delay_time != 0);

    _ = this.users_count.fetchAdd(1, .monotonic);
    errdefer this.releaseUser();

    const slot = this.getEntry() orelse try this.reserveInNewAllocation();

    task.incrementReferences();
    slot.task = task;
    slot.time.store(delay_time, .release);

    return slot;
}

fn getEntry(this: *DelayPool) ?*DelayWork {
    var chunk: ?*Chunk = this.chunks;

    return while (chunk) |c| : (chunk = c.next.load(.monotonic)) {
        if (c.free.takeFirstFree()) |index| break &c.entries[index];
    } else null;
}

fn initChunk(this: *DelayPool, chunk: *Chunk) void {
    chunk.free_words = @splat(.init(0));
    chunk.pending_words = @splat(.init(0));
    chunk.free = .{ .words = &chunk.free_words };
    chunk.pending = .{ .words = &chunk.pending_words };
    chunk.next = .init(null);

    for (&chunk.entries) |*entry| entry.* = .{
        .work = .{ .func = executeDelay, .next = undefined },
        .task = undefined,
        .pool = this,
        .time = undefined,
    };
}

fn reserveInNewAllocation(this: *DelayPool) Allocator.Error!*DelayWork {
    const new_chunk = try atomic_allocator.create(Chunk);
    errdefer atomic_allocator.destroy(new_chunk);

    this.initChunk(new_chunk);

    const slot = &new_chunk.entries[new_chunk.free.takeFirstFree().?];
    this.appendChunk(new_chunk);

    return slot;
}

fn appendChunk(this: *DelayPool, new_chunk: *Chunk) void {
    var chunk = this.chunks;
    while (chunk.next.cmpxchgStrong(null, new_chunk, .monotonic, .monotonic)) |taken| chunk = taken.?;
}

fn chunkOf(this: *DelayPool, slot: *DelayWork) *Chunk {
    const slot_address = @intFromPtr(slot);

    var chunk: ?*Chunk = this.chunks;
    return while (chunk) |c| : (chunk = c.next.load(.monotonic)) {
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
    slot.task.decrementReferences();
    this.freeEntry(slot);
    this.releaseUser();
}

fn cancelAllPending(this: *DelayPool) void {
    var chunk: ?*Chunk = this.chunks;

    while (chunk) |c| : (chunk = c.next.load(.monotonic)) {
        var it = c.pending.iterate();

        while (it.next()) |index| {
            c.entries[index].task.decrementReferences();
            c.pending.release(index);
            c.free.release(index);
            this.releaseUser();
        }
    }
}

fn releaseUser(this: *DelayPool) void {
    if (this.users_count.fetchSub(1, .monotonic) == 1) this.completion.signal();
}

fn executeDelay(work: *kernel.Task.Work) callconv(.c) void {
    const slot: *DelayWork = @fieldParentPtr("work", work);
    const delay_time = slot.time.load(.acquire);
    const this: *DelayPool = slot.pool;
    const task = slot.task;

    this.freeEntry(slot);
    task.decrementReferences();

    kernel.time.sleep.us(delay_time);

    this.releaseUser();
}
