const std = @import("std");
const sort = std.sort;
const Allocator = std.mem.Allocator;
const Coverage = std.debug.Coverage;

data: std.MultiArrayList(Entry),

pub const empty: LineMap = .{ .data = .empty };

const Entry = struct {
    start: usize,
    site: Site,
};

pub const Site = bitpack struct(u64) {
    file: Coverage.File.Index,
    line: u32,

    pub const none: Site = .{ .file = .invalid, .line = 0 };
};

const LineMap = @This();

pub fn emit(this: *LineMap, allocator: Allocator, start: usize, site: Site) Allocator.Error!void {
    const starts = this.data.items(.start);
    if (starts.len > 0 and starts[starts.len - 1] == start) _ = this.data.pop();

    const sites = this.data.items(.site);
    if (sites.len > 0 and sites[sites.len - 1] == site) return;

    try this.data.append(allocator, .{ .start = start, .site = site });
}

fn order(a: u64, b: u64) std.math.Order {
    return std.math.order(a, b);
}

pub fn deinit(this: *LineMap, allocator: Allocator) void {
    this.data.deinit(allocator);
    this.* = undefined;
}

pub fn isWellFormed(this: LineMap) bool {
    const slices = this.data.slice();
    if (slices.len == 0) return false;
    if (slices.items(.site)[slices.len - 1] != Site.none) return false;

    const starts = slices.items(.start);
    for (starts[1..], starts[0 .. starts.len - 1]) |start, previous| if (start <= previous) return false;

    return true;
}

pub fn getSite(this: LineMap, ip: usize) ?Site {
    const slices = this.data.slice();
    const starts = slices.items(.start);
    const sites = slices.items(.site);

    const index = sort.upperBound(usize, starts, ip, order);
    return if (index == 0) null else sites[index - 1];
}
