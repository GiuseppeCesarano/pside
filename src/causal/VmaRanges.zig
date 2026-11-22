const std = @import("std");

const platform = @import("platform");
pub const Range = platform.VmaRange;
pub const SnapshotError = platform.VmaSnapshotError;

const VmaRanges = @This();
entries: []Range,

pub const empty: VmaRanges = .{ .entries = &.{} };

pub fn snapshot(allocator: std.mem.Allocator, task: *platform.Task, filter: [:0]const u8) SnapshotError!VmaRanges {
    return .{ .entries = try platform.executableVmas(allocator, task, filter) };
}

pub fn deinit(this: VmaRanges, allocator: std.mem.Allocator) void {
    if (this.entries.len != 0)
        allocator.free(this.entries);
}

pub fn findBase(this: VmaRanges, ip: usize) ?usize {
    return for (this.entries) |range| {
        if (range.contains(ip)) break range.begin;
    } else null;
}
