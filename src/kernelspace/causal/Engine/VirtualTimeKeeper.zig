const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const ThreadClocks = @import("thread_safe/ThreadClocks.zig");
pub const Key = ThreadClocks.Key;
pub const Value = ThreadClocks.Value;
pub const Ticks = ThreadClocks.Ticks;

pub const KeyAndLag = struct {
    key: Key,
    lag: Ticks,
};

pub fn init(allocator: Allocator, canBeRemoved: fn (*Key) bool, releaseKey: fn (*Key) void) !GenericVirtualTimeKeeper(canBeRemoved, releaseKey) {
    return GenericVirtualTimeKeeper(canBeRemoved, releaseKey).init(allocator);
}

pub fn GenericVirtualTimeKeeper(canBeRemoved: fn (*Key) bool, releaseKey: fn (*Key) void) type {
    return struct {
        const VirtualTimeKeeper = @This();

        clocks: ThreadClocks,

        fn init(allocator: Allocator) !VirtualTimeKeeper {
            return .{ .clocks = try .init(allocator, 1024) };
        }

        pub fn deinit(this: *VirtualTimeKeeper, allocator: Allocator) void {
            const scoped = struct {
                pub fn release(key: *Key) bool {
                    releaseKey(key);
                    return true;
                }
            };

            this.clocks.removeIf(scoped.release, .{});
            this.clocks.deinit(allocator);
        }

        pub fn addFirst(this: *VirtualTimeKeeper, key: Key) void {
            this.clocks.put(key, 0) catch unreachable;
            // This function shall only be called to add the first key,
            // there should always be space for the first key.
        }

        pub fn delayEveryoneLagging(this: *VirtualTimeKeeper, applyDelay: anytype, args: anytype) void {
            const KeysAndLags = struct {
                data: [64]KeyAndLag = undefined,
                used: usize = 0,
            };
            const scoped = struct {
                pub fn delay(master: Ticks, key: *Key, value: *Value, keys_and_lags: *KeysAndLags, apply: anytype, inner: anytype) void {
                    assert(keys_and_lags.used < 64);

                    const lag = master - value.ticks;
                    value.* = .{ .ticks = master, .master_at_sleep = master };

                    keys_and_lags.data[keys_and_lags.used] = .{ .key = key.*, .lag = lag };
                    keys_and_lags.used += 1;

                    if (keys_and_lags.used == 64) {
                        keys_and_lags.used = 0;
                        @call(.auto, apply, inner ++ .{keys_and_lags.data[0..]});
                    }
                }
            };
            var keys_and_lags: KeysAndLags = .{};

            this.clocks.forEach(scoped.delay, .{ &keys_and_lags, applyDelay, args });
            @call(.auto, applyDelay, args ++ .{keys_and_lags.data[0..keys_and_lags.used]});
        }

        pub fn getMasterClock(this: *VirtualTimeKeeper) Ticks {
            return this.clocks.master.load(.monotonic);
        }

        pub fn onTick(this: *VirtualTimeKeeper, key: Key) void {
            this.clocks.tick(key) catch {};
            // .tick() will error on locked map, we discard the error (and the clock tick itself)
            // since the causal attribution agorithm is robust against missed samples.
        }

        pub fn onFork(this: *VirtualTimeKeeper, allocator: Allocator, parent: Key, child: Key) ![2]KeyAndLag {
            const lag = this.clocks.fork(parent, child) catch blk: {
                this.sweep();

                break :blk this.clocks.fork(parent, child) catch {
                    const clocks, const bits = try this.clocks.grow(allocator);
                    defer allocator.free(clocks);
                    defer allocator.free(bits);

                    break :blk try this.clocks.fork(parent, child);
                };
            };

            return .{
                .{ .key = parent, .lag = lag },
                .{ .key = child, .lag = lag },
            };
        }

        pub fn onSleep(this: *VirtualTimeKeeper, key: Key) void {
            this.clocks.prepareForSleep(key);
        }

        pub fn onWake(this: *VirtualTimeKeeper, waker: Key, wakee: Key) [2]KeyAndLag {
            const waker_lag, const wakee_lag = this.clocks.wake(waker, wakee);
            return .{
                .{ .key = waker, .lag = waker_lag },
                .{ .key = wakee, .lag = wakee_lag },
            };
        }

        pub fn onExternalWake(this: *VirtualTimeKeeper, wakee: Key) [1]KeyAndLag {
            const lag = this.clocks.externalWake(wakee);
            return .{.{ .key = wakee, .lag = lag }};
        }

        fn sweep(this: *VirtualTimeKeeper) void {
            const scoped = struct {
                pub fn remove(key: *Key) bool {
                    const can_be_removed = canBeRemoved(key);
                    if (can_be_removed) releaseKey(key);
                    return can_be_removed;
                }
            };

            this.clocks.removeIf(scoped.remove, .{});
        }
    };
}

const testing = std.testing;

var test_reap_threshold: usize = std.math.maxInt(usize);
var test_released_count: usize = 0;

fn testCanBeRemoved(key: *Key) bool {
    return key.withoutCollisionBit().data >= test_reap_threshold;
}

fn testReleaseKey(key: *Key) void {
    _ = key;
    test_released_count += 1;
}

test "VirtualTimeKeeper: deinit releases every tracked key" {
    test_reap_threshold = std.math.maxInt(usize);
    test_released_count = 0;

    var keeper = try init(testing.allocator, testCanBeRemoved, testReleaseKey);

    keeper.addFirst(.{ .data = 2 });
    _ = try keeper.onFork(testing.allocator, .{ .data = 2 }, .{ .data = 4 });
    _ = try keeper.onFork(testing.allocator, .{ .data = 2 }, .{ .data = 6 });

    keeper.deinit(testing.allocator);
    try testing.expectEqual(3, test_released_count);
}

test "VirtualTimeKeeper: fork and wake lag accounting" {
    test_reap_threshold = std.math.maxInt(usize);
    test_released_count = 0;

    var keeper = try init(testing.allocator, testCanBeRemoved, testReleaseKey);
    defer keeper.deinit(testing.allocator);

    const root: Key = .{ .data = 2 };
    const child: Key = .{ .data = 4 };

    keeper.addFirst(root);
    keeper.clocks.master.store(40, .release);

    const fork_delays = try keeper.onFork(testing.allocator, root, child);
    try testing.expectEqual(40, fork_delays[0].lag);
    try testing.expectEqual(40, fork_delays[1].lag);

    keeper.onSleep(child);
    keeper.clocks.master.store(100, .release);

    const wake_delays = keeper.onWake(root, child);
    try testing.expectEqual(60, wake_delays[0].lag);
    try testing.expectEqual(60, wake_delays[1].lag);

    try testing.expectEqual(0, keeper.onExternalWake(child)[0].lag);
    try testing.expectEqual(100, keeper.getMasterClock());
}

test "VirtualTimeKeeper: fork pressure grows the map without losing entries" {
    test_reap_threshold = std.math.maxInt(usize);
    test_released_count = 0;

    var keeper = try init(testing.allocator, testCanBeRemoved, testReleaseKey);
    defer keeper.deinit(testing.allocator);

    const root: Key = .{ .data = 2 };
    keeper.addFirst(root);

    const fork_count = 3000;
    for (0..fork_count) |i| {
        const child: Key = .{ .data = (i + 2) * 2 };
        _ = try keeper.onFork(testing.allocator, root, child);
    }

    try testing.expect(keeper.clocks.pairs.len >= 4096);
    for (0..fork_count) |i| {
        const child: Key = .{ .data = (i + 2) * 2 };
        try testing.expectEqual(0, keeper.clocks.get(child, .ticks));
    }
}

test "VirtualTimeKeeper: fork pressure sweeps reaped tasks instead of growing" {
    test_reap_threshold = 100;
    test_released_count = 0;

    var keeper = try init(testing.allocator, testCanBeRemoved, testReleaseKey);
    defer keeper.deinit(testing.allocator);

    const root: Key = .{ .data = 2 };
    keeper.addFirst(root);

    for (0..5000) |i| {
        const child: Key = .{ .data = (i + 50) * 2 };
        _ = try keeper.onFork(testing.allocator, root, child);
    }

    try testing.expectEqual(1024, keeper.clocks.pairs.len);
    try testing.expect(test_released_count > 0);
}

test "VirtualTimeKeeper: delayEveryoneLagging visits everyone across batches" {
    test_reap_threshold = std.math.maxInt(usize);
    test_released_count = 0;

    var keeper = try init(testing.allocator, testCanBeRemoved, testReleaseKey);
    defer keeper.deinit(testing.allocator);

    const root: Key = .{ .data = 2 };
    keeper.addFirst(root);

    for (0..99) |i| {
        const child: Key = .{ .data = (i + 2) * 2 };
        _ = try keeper.onFork(testing.allocator, root, child);
    }

    keeper.clocks.master.store(77, .release);

    const Collector = struct {
        fn apply(visited: *usize, lag_sum: *usize, keys_and_lags: []const KeyAndLag) void {
            visited.* += keys_and_lags.len;
            for (keys_and_lags) |kl| lag_sum.* += kl.lag;
        }
    };

    var visited: usize = 0;
    var lag_sum: usize = 0;
    keeper.delayEveryoneLagging(Collector.apply, .{ &visited, &lag_sum });

    try testing.expectEqual(100, visited);
    try testing.expectEqual(77 * 100, lag_sum);
    try testing.expectEqual(0, keeper.clocks.get(root, .lag));

    visited = 0;
    lag_sum = 0;
    keeper.delayEveryoneLagging(Collector.apply, .{ &visited, &lag_sum });

    try testing.expectEqual(100, visited);
    try testing.expectEqual(0, lag_sum);
}
