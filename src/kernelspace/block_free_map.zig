const std = @import("std");
const atomic = std.atomic;

/// Before accessing the map field acquireAcess must be called.
/// Once all the needed access to the map are done the user
/// must call releaseAccess
pub fn BlockFreeMap(Map: type) type {
    return struct {
        map: Map,
        can_read: atomic.Value(bool) align(atomic.cache_line),
        users: atomic.Value(u32) align(atomic.cache_line),

        /// Init should be called before the map is accessible by
        /// more than one thread; so no syncronization is required.
        pub fn init(allocator: std.mem.Allocator, size: u32) !@This() {
            var ret: @This() = .{ .map = Map.empty, .can_read = .init(true), .users = .init(0) };
            try ret.map.ensureTotalCapacity(allocator, size);

            return ret;
        }

        /// To deinit user must not call acquire access.
        /// Since signaling possible access to a destructed map is broken semantic.
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

        pub fn grow(this: *@This(), allocator: std.mem.Allocator) !void {
            this.can_read.store(false, .monotonic);
            defer this.can_read.store(true, .release);

            // The only user allowed is the one which also called grow
            while (this.users.load(.monotonic) != 1) {
                atomic.spinLoopHint();
            }

            // TODO: maybe we should't set can_read to true if we faild allocation
            try this.map.ensureTotalCapacity(allocator, this.map.capacity() * 2);
        }

        /// Clear must be used without calling acquireAcess.
        pub fn clear(this: *@This()) void {
            this.can_read.store(false, .monotonic);
            defer this.can_read.store(true, .release);

            // The only user allowed is the one which also called clear
            while (this.users.load(.monotonic) != 1) {
                atomic.spinLoopHint();
            }

            this.map.clearRetainingCapacity();
        }
    };
}
