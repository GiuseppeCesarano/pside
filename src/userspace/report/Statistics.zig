const std = @import("std");

const ParseResult = @import("OutputFileParserResult");
pub const ThroughputNoIP = ParseResult.ThroughputNoIP;
pub const ThroughputIpMap = ParseResult.ThroughputIpMap;

const Server = @import("Server.zig");
const Point = Server.Point;
const IpPoints = Server.IpSeries;

const bootstrap_iterations = 10_000;
const confidence_interval_low: usize = @intFromFloat(bootstrap_iterations * 0.05);
const confidence_interval_high: usize = @intFromFloat(bootstrap_iterations * 0.95);

pub fn computeSection(
    allocator: std.mem.Allocator,
    ip_map: *const ThroughputIpMap,
    rng: std.Random,
) ![]IpPoints {
    var section = try std.ArrayList(IpPoints).initCapacity(allocator, 10);
    errdefer {
        for (section.items) |s| s.deinit(allocator);
        section.deinit(allocator);
    }

    var ip_it = ip_map.iterator();
    while (ip_it.next()) |entry| try section.append(allocator, try computeIpSeries(allocator, entry.key_ptr.*, entry.value_ptr.items, rng));

    return section.toOwnedSlice(allocator);
}

fn computeIpSeries(
    allocator: std.mem.Allocator,
    ip: u64,
    records: []const ThroughputNoIP,
    rng: std.Random,
) !IpPoints {
    @setFloatMode(.optimized);

    var bucket: [21]std.ArrayListUnmanaged(f64) = @splat(.empty);
    defer for (&bucket) |*e| e.deinit(allocator);

    for (records) |r| {
        const wall: f64 = @floatFromInt(r.wall);
        const injected_delay: f64 = @floatFromInt(r.injected_delay);

        const virtual_wall = wall - injected_delay;
        if (virtual_wall <= 0) continue;

        const tp = @as(f64, @floatFromInt(r.progress_delta)) / virtual_wall;
        const index = r.speedup_percent / 5;

        try bucket[index].append(allocator, tp);
    }

    const baseline_p75 = sortAndGet75Percentile(bucket[0].items);
    if (baseline_p75 == 0) return .{ .ip = ip, .points = &.{} };

    var points: std.ArrayListUnmanaged(Point) = .empty;
    errdefer points.deinit(allocator);

    var resample: std.ArrayListUnmanaged(f64) = .empty;
    defer resample.deinit(allocator);

    var boot_dist = try std.ArrayListUnmanaged(f64).initCapacity(allocator, bootstrap_iterations);
    defer boot_dist.deinit(allocator);

    for (&bucket, 0..) |*b, i| {
        if (b.items.len == 0) continue;

        const speedup_pct: f64 = @as(f64, @floatFromInt(i)) * 5.0;
        const p75_norm = 100.0 * sortAndGet75Percentile(b.items) / baseline_p75;

        boot_dist.clearRetainingCapacity();
        try resample.resize(allocator, b.items.len);

        for (0..bootstrap_iterations) |_| {
            for (resample.items) |*s| s.* = b.items[rng.uintLessThan(usize, b.items.len)];
            try boot_dist.append(allocator, 100.0 * sortAndGet75Percentile(resample.items) / baseline_p75);
        }
        std.mem.sort(f64, boot_dist.items, {}, std.sort.asc(f64));

        try points.append(allocator, .{
            .speedup = speedup_pct,
            .median = p75_norm,
            .ci_low = boot_dist.items[confidence_interval_low],
            .ci_high = boot_dist.items[confidence_interval_high],
            .singleton = b.items.len == 1,
        });
    }

    return .{ .ip = ip, .points = try points.toOwnedSlice(allocator) };
}

fn sortAndGet75Percentile(data: []f64) f64 {
    @setFloatMode(.optimized);

    return switch (data.len) {
        0 => 0,
        1 => data[0],
        else => r: {
            std.mem.sort(f64, data, {}, std.sort.asc(f64));

            const idx: f64 = 0.75 * @as(f64, @floatFromInt(data.len - 1));
            const lo: usize = @intFromFloat(@floor(idx));
            const hi = lo + 1;

            break :r if (hi >= data.len) data[lo] else data[lo] + (idx - @as(f64, @floatFromInt(lo))) * (data[hi] - data[lo]);
        },
    };
}
