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
