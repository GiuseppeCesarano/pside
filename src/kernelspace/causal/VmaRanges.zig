const std = @import("std");

const kernel = @import("kernel");
const allocator = kernel.heap.allocator;

const VmaRanges = @This();

pub const Range = extern struct {
    begin: usize,
    end: usize,

    pub fn contains(this: Range, ip: usize) bool {
        return ip -% this.begin < this.end - this.begin;
    }
};

entries: []Range,

pub const empty: VmaRanges = .{ .entries = &.{} };

extern fn c_snapshot_executable_vmas(
    *kernel.Task,
    ?[*:0]const u8,
    [*]Range,
    c_int,
) c_int;

pub fn snapshot(task: *kernel.Task, filter: [:0]const u8) !VmaRanges {
    const vma_ranges = try allocator.alloc(Range, 32);
    errdefer allocator.free(vma_ranges);

    const filter_z: ?[*:0]const u8 = if (filter.len > 0) @ptrCast(filter.ptr) else null;
    const count: usize = @intCast(c_snapshot_executable_vmas(task, filter_z, vma_ranges.ptr, 32));

    std.debug.assert(allocator.resize(vma_ranges, count));

    return .{ .entries = vma_ranges[0..count] };
}

pub fn deinit(this: VmaRanges) void {
    if (this.entries.len != 0)
        allocator.free(this.entries);
}

pub fn contains(this: VmaRanges, ip: usize) bool {
    return for (this.entries) |range| {
        if (range.contains(ip)) break true;
    } else false;
}

pub fn findBase(this: VmaRanges, ip: usize) ?usize {
    return for (this.entries) |range| {
        if (range.contains(ip)) break range.begin;
    } else null;
}
