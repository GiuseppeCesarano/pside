const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const BitSearch = @This();

const AtomicWord = std.atomic.Value(usize);
pub const bits_per_word = @bitSizeOf(usize);

words: []AtomicWord,

pub fn init(allocator: std.mem.Allocator, reserve: usize) !BitSearch {
    const words = try allocator.alloc(AtomicWord, @divExact(reserve, bits_per_word));
    @memset(words, .init(0));

    return .{ .words = words };
}

pub fn deinit(this: BitSearch, allocator: std.mem.Allocator) void {
    allocator.free(this.words);
}

fn wordOf(index: usize) usize {
    return index / bits_per_word;
}

fn bitOf(index: usize) usize {
    return @as(usize, 1) << @intCast(index % bits_per_word);
}

pub fn take(this: *BitSearch, index: usize) void {
    const word = &this.words[wordOf(index)];
    const bit = bitOf(index);
    assert(word.fetchOr(bit, .monotonic) & bit == 0);
}

pub fn takeUnordered(this: *BitSearch, index: usize) void {
    const word = &this.words[wordOf(index)];
    const bit = bitOf(index);
    assert(word.raw & bit == 0);
    word.raw |= bit;
}

pub fn takeFirstFree(this: *BitSearch) ?usize {
    return search: for (this.words, 0..) |*word, word_index| {
        var free = ~word.load(.monotonic);

        while (free != 0) {
            const target_bit = free & -%free;
            const previous = word.fetchOr(target_bit, .monotonic);

            if (previous & target_bit == 0) {
                @branchHint(.likely);
                break :search word_index * bits_per_word + @ctz(target_bit);
            }
            free &= ~previous;
        }
    } else null;
}

pub fn countTaken(this: *const BitSearch) usize {
    var total: usize = 0;
    for (this.words) |word|
        total += @popCount(word.load(.monotonic));
    return total;
}

pub fn isTaken(this: *const BitSearch, index: usize) bool {
    const word = &this.words[wordOf(index)];
    return word.load(.monotonic) & bitOf(index) != 0;
}

pub fn release(this: *BitSearch, index: usize) void {
    const word = &this.words[wordOf(index)];
    const bit = bitOf(index);
    assert(word.fetchAnd(~bit, .monotonic) & bit != 0);
}

pub fn releaseUnordered(this: *BitSearch, index: usize) void {
    const word = &this.words[wordOf(index)];
    const bit = bitOf(index);
    assert(word.raw & bit != 0);
    word.raw &= ~bit;
}

pub const Iterator = struct {
    words: []const AtomicWord,
    current_word: usize,
    remaining: usize,

    pub fn next(this: *Iterator) ?usize {
        while (this.remaining == 0)
            if (!this.advance()) return null;

        const tz = @ctz(this.remaining);
        this.remaining &= this.remaining - 1;

        return this.current_word * bits_per_word + tz;
    }

    fn advance(this: *Iterator) bool {
        if (this.current_word >= this.words.len - 1) return false;

        this.current_word += 1;
        this.remaining = this.words[this.current_word].load(.monotonic);

        return true;
    }
};

pub fn iterate(this: *const BitSearch) Iterator {
    return .{
        .words = this.words,
        .current_word = 0,
        .remaining = this.words[0].load(.monotonic),
    };
}

fn collectTaken(this: *const BitSearch, out: []usize) []usize {
    var count: usize = 0;

    var it = this.iterate();
    while (it.next()) |index| : (count += 1) out[count] = index;

    return out[0..count];
}

test "BitSearch: take, release and count" {
    const allocator = testing.allocator;
    var search: BitSearch = try .init(allocator, 128);
    defer search.deinit(allocator);

    try testing.expectEqual(0, search.countTaken());

    search.take(7);
    search.take(70);

    try testing.expect(search.isTaken(7));
    try testing.expect(search.isTaken(70));
    try testing.expect(!search.isTaken(8));
    try testing.expectEqual(2, search.countTaken());

    search.release(7);

    try testing.expect(!search.isTaken(7));
    try testing.expectEqual(1, search.countTaken());
}

test "BitSearch: unordered take and release match the atomic ones" {
    const allocator = testing.allocator;
    var search: BitSearch = try .init(allocator, 128);
    defer search.deinit(allocator);

    search.takeUnordered(5);
    search.takeUnordered(64);

    try testing.expect(search.isTaken(5));
    try testing.expect(search.isTaken(64));
    try testing.expectEqual(2, search.countTaken());

    search.releaseUnordered(5);
    search.releaseUnordered(64);

    try testing.expectEqual(0, search.countTaken());
}

test "BitSearch: takeFirstFree hands out the lowest free index" {
    const allocator = testing.allocator;
    var search: BitSearch = try .init(allocator, 128);
    defer search.deinit(allocator);

    for (0..128) |index| try testing.expectEqual(index, search.takeFirstFree());

    try testing.expectEqual(null, search.takeFirstFree());
    try testing.expectEqual(128, search.countTaken());
}

test "BitSearch: takeFirstFree skips taken indices and reuses released ones" {
    const allocator = testing.allocator;
    var search: BitSearch = try .init(allocator, 128);
    defer search.deinit(allocator);

    for (0..70) |index| search.take(index);

    try testing.expectEqual(70, search.takeFirstFree());

    search.release(3);
    search.release(65);

    try testing.expectEqual(3, search.takeFirstFree());
    try testing.expectEqual(65, search.takeFirstFree());
    try testing.expectEqual(71, search.takeFirstFree());
}

test "BitSearch: concurrent takeFirstFree never hands out an index twice" {
    const allocator = testing.allocator;

    const thread_count = 4;
    const takes_per_thread = 128;
    const capacity = thread_count * takes_per_thread * 2;

    var search: BitSearch = try .init(allocator, capacity);
    defer search.deinit(allocator);

    const Context = struct {
        search: *BitSearch,
        ready: *std.atomic.Value(u32),
        taken: [takes_per_thread]usize = undefined,

        fn run(ctx: *@This()) void {
            _ = ctx.ready.fetchAdd(1, .release);
            while (ctx.ready.load(.acquire) < thread_count) std.atomic.spinLoopHint();

            // Never null: only half the capacity is ever claimed.
            for (&ctx.taken) |*index| index.* = ctx.search.takeFirstFree().?;
        }
    };

    var ready: std.atomic.Value(u32) = .init(0);
    var contexts: [thread_count]Context = undefined;
    var threads: [thread_count]std.Thread = undefined;

    for (&contexts, &threads) |*context, *thread| {
        context.* = .{ .search = &search, .ready = &ready };
        thread.* = try .spawn(.{}, Context.run, .{context});
    }
    for (threads) |t| t.join();

    var seen: [capacity]bool = @splat(false);
    for (contexts) |context| for (context.taken) |index| {
        try testing.expect(!seen[index]);
        seen[index] = true;
    };

    try testing.expectEqual(thread_count * takes_per_thread, search.countTaken());
}

test "BitSearch: iterate yields every taken index in ascending order" {
    const allocator = testing.allocator;
    var search: BitSearch = try .init(allocator, 256);
    defer search.deinit(allocator);

    const taken = [_]usize{ 0, 1, 63, 64, 65, 130, 191, 192, 255 };
    for (taken) |index| search.take(index);

    var buffer: [taken.len]usize = undefined;

    try testing.expectEqualSlices(usize, &taken, collectTaken(&search, &buffer));
}

test "BitSearch: iterate yields nothing when no index is taken" {
    const allocator = testing.allocator;
    var search: BitSearch = try .init(allocator, 128);
    defer search.deinit(allocator);

    var it = search.iterate();
    try testing.expectEqual(null, it.next());
    try testing.expectEqual(null, it.next());
}

test "BitSearch: iterate walks a single fully taken word" {
    const allocator = testing.allocator;
    var search: BitSearch = try .init(allocator, bits_per_word);
    defer search.deinit(allocator);

    for (0..bits_per_word) |index| search.take(index);

    var it = search.iterate();
    for (0..bits_per_word) |index| try testing.expectEqual(index, it.next());

    try testing.expectEqual(null, it.next());
}

test "BitSearch: iterate skips released indices" {
    const allocator = testing.allocator;
    var search: BitSearch = try .init(allocator, 128);
    defer search.deinit(allocator);

    for (0..128) |index| search.take(index);
    for (0..128) |index| if (index % 3 != 0) search.release(index);

    var buffer: [128]usize = undefined;
    const live = collectTaken(&search, &buffer);

    try testing.expectEqual(43, live.len);
    for (live, 0..) |index, nth| try testing.expectEqual(nth * 3, index);
}

test "BitSearch: releasing the current index does not disturb the walk" {
    const allocator = testing.allocator;
    var search: BitSearch = try .init(allocator, 128);
    defer search.deinit(allocator);

    for (0..128) |index| search.take(index);

    var seen: usize = 0;
    var it = search.iterate();
    while (it.next()) |index| : (seen += 1) search.releaseUnordered(index);

    try testing.expectEqual(128, seen);
    try testing.expectEqual(0, search.countTaken());
}
