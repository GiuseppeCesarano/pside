const std = @import("std");
const atomic = std.atomic;

/// Directlly accessing the map field wihtout calling .acquireAccess() will result in ub.
/// Once .acquireAccess has ben called, the user must also call releaseAccess().
///
/// Unsafe methods also require calling .acquireAccess() before calling them; and 
/// releaseAccess() after
pub fn ThreadSafeMap(Key: type, Value: type) type {
    return struct {
        map: std.AutoHashMapUnmanaged(Key, Value),
        can_read: atomic.Value(bool) align(atomic.cache_line),
        users: atomic.Value(u32) align(atomic.cache_line),

        pub fn init(allocator: std.mem.Allocator, size: u32) !@This() {
            var ret: @This() = .{ .map = .empty, .can_read = .init(true), .users = .init(0) };
            try ret.map.ensureTotalCapacity(allocator, size);

            return ret;
        }

        pub fn deinit(this: *@This(), allocator: std.mem.Allocator) void {
            // TODO: maybe we should signal that the map has to be destroyed
            // setting can_read at a special value?
            while (this.users.load(.monotonic) != 0) {
                atomic.spinLoopHint();
            }

            this.map.deinit(allocator);
        }

        pub fn acquireAccess(this: *@This()) void {
            while (!this.can_read.load(.acquire)) {
                atomic.spinLoopHint();
            }

            _ = this.users.fetchAdd(1, .monotonic);
        }

        pub fn releaseAccess(this: *@This()) void {
            _ = this.users.fetchSub(1, .monotonic);
        }

        pub fn put(this: *@This(), allocator: std.mem.Allocator, key: Key, value: Value) !void {
            this.acquireAccess();
            defer this.releaseAccess();

            if (this.map.available == 0) try this.growUnsafe(allocator);

            this.map.putAssumeCapacity(key, value);
        }

        pub fn putAssumeCapacity(this: *@This(), key: Key, value: Value) void {
            this.acquireAccess();
            defer this.releaseAccess();

            this.map.putAssumeCapacity(key, value);
        }

        pub fn get(this: *@This(), key: Key) ?Value {
            this.acquireAccess();
            defer this.releaseAccess();

            return this.map.get(key);
        }

        pub fn growUnsafe(this: *@This(), allocator: std.mem.Allocator) !void {
            this.can_read.store(false, .monotonic);
            defer this.can_read.store(true, .release);

            // The only user allowed is the one which also called grow
            while (this.users.load(.monotonic) != 1) {
                atomic.spinLoopHint();
            }

            // TODO: maybe we should't set can_read to true if we faild allocation
            try this.map.ensureTotalCapacity(allocator, this.map.capacity() * 2);
        }

        pub fn clear(this: *@This()) void {
            this.can_read.store(false, .monotonic);
            defer this.can_read.store(true, .release);

            while (this.users.load(.monotonic) != 0) {
                atomic.spinLoopHint();
            }

            this.map.clearRetainingCapacity();
        }
    };
}
