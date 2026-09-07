const std = @import("std");

const serialization = @import("serialization");
const speedup_levels_len = serialization.speedup_levels_len;

const Graph = @This();

pub const Error = error{NotEnoughSamples};

pub const min_samples_per_level = 5;

const confidence = 0.95;
const lower_tail = (1.0 - confidence) / 2.0;
const upper_tail = 1.0 - lower_tail;

const Point = struct {
    ci_high: f32,
    median: f32,
    ci_low: f32,

    fn compute(samples: []f32) Point {
        const float = struct {
            pub fn lessThan(_: void, a: f32, b: f32) bool {
                @setFloatMode(.optimized);
                return a < b;
            }
        };

        std.sort.insertion(f32, samples, {}, float.lessThan);

        return .{
            .ci_high = ciBound(samples, upper_tail),
            .median = median(samples),
            .ci_low = ciBound(samples, lower_tail),
        };
    }
};

location: []const u8,
points: [speedup_levels_len]Point,
ci_low_total_area: f32,

pub fn init(location: []const u8, levels: [speedup_levels_len][]f32) Error!Graph {
    if (!enoughSamples(levels)) return Error.NotEnoughSamples;

    var graph: Graph = .{
        .location = location,
        .points = undefined,
        .ci_low_total_area = 0,
    };

    for (&graph.points, levels) |*point, samples|
        point.* = .compute(samples);

    for (graph.points) |point|
        graph.ci_low_total_area += point.ci_low;

    return graph;
}

pub fn byArea(_: void, lhs: Graph, rhs: Graph) bool {
    return lhs.ci_low_total_area > rhs.ci_low_total_area;
}

fn enoughSamples(levels: [speedup_levels_len][]f32) bool {
    return for (&levels) |level| {
        if (level.len < min_samples_per_level) break false;
    } else true;
}

fn median(sorted: []const f32) f32 {
    const mid = sorted.len / 2;

    return if (sorted.len % 2 == 1)
        sorted[mid]
    else
        (sorted[mid - 1] + sorted[mid]) / 2.0;
}

fn ciBound(sorted: []const f32, tail: f64) f32 {
    const draws: f64 = @floatFromInt(sorted.len);

    var low: usize = 0;
    var high: usize = sorted.len - 1;

    while (low < high) {
        const mid = (low + high) / 2;
        const share = @as(f64, @floatFromInt(mid + 1)) / draws;

        if (medianAtOrBelow(sorted.len, share) >= tail) high = mid else low = mid + 1;
    }

    return sorted[low];
}

fn medianAtOrBelow(draws: usize, share: f64) f64 {
    std.debug.assert(share > 0.0 and share < 1.0);

    const all: f64 = @floatFromInt(draws);
    const odds = share / (1.0 - share);
    const majority = (draws + 1) / 2;
    const peak: usize = @intFromFloat((all + 1.0) * share);

    var mass: f64 = 1.0;
    var majority_mass: f64 = if (peak >= majority) 1.0 else 0.0;

    var weight: f64 = 1.0;
    for (0..peak) |step| {
        const landed = peak - step;
        const edge: f64 = @floatFromInt(landed);

        weight *= edge / (all - edge + 1.0) / odds;
        if (weight == 0.0) break;

        mass += weight;
        if (landed - 1 >= majority) majority_mass += weight;
    }

    weight = 1.0;
    for (peak..draws) |landed| {
        const edge: f64 = @floatFromInt(landed);

        weight *= (all - edge) / (edge + 1.0) * odds;
        if (weight == 0.0) break;

        mass += weight;
        if (landed + 1 >= majority) majority_mass += weight;
    }

    return majority_mass / mass;
}

test "bootstrap bounds bracket the median and stay inside the sample" {
    var prng: std.Random.DefaultPrng = .init(0);
    const rng = prng.random();

    for ([_]usize{ 5, 6, 7, 10, 11, 32, 33, 100, 1924 }) |n| {
        const samples = try std.testing.allocator.alloc(f32, n);
        defer std.testing.allocator.free(samples);

        for (samples) |*sample| sample.* = rng.float(f32);

        const point: Point = .compute(samples);

        try std.testing.expect(point.ci_low <= point.median);
        try std.testing.expect(point.median <= point.ci_high);
        try std.testing.expect(point.ci_low >= samples[0]);
        try std.testing.expect(point.ci_high <= samples[n - 1]);
    }
}

test "a constant level collapses to a zero width interval" {
    var samples: [16]f32 = @splat(0.25);
    const point: Point = .compute(&samples);

    try std.testing.expectEqual(@as(f32, 0.25), point.ci_low);
    try std.testing.expectEqual(@as(f32, 0.25), point.median);
    try std.testing.expectEqual(@as(f32, 0.25), point.ci_high);
}

test "medianAtOrBelow matches the binomial tail, and survives a long one" {
    const cases = [_]struct { draws: usize, share: f64, expected: f64 }{
        .{ .draws = 2, .share = 0.5, .expected = 0.75 },
        .{ .draws = 3, .share = 0.5, .expected = 0.5 },
        .{ .draws = 4, .share = 0.5, .expected = 0.6875 },
        .{ .draws = 5, .share = 0.5, .expected = 0.5 },
        .{ .draws = 3, .share = 1.0 / 3.0, .expected = 0.259259259259259 },
        .{ .draws = 9, .share = 1.0 / 3.0, .expected = 0.144845806025504 },
        .{ .draws = 1924, .share = 0.5, .expected = 0.509093919400759 },
    };

    for (cases) |check| {
        const actual = medianAtOrBelow(check.draws, check.share);
        try std.testing.expectApproxEqAbs(check.expected, actual, 1e-9);
    }

    var previous: f64 = 0.0;
    for (1..11) |rank| {
        const share = @as(f64, @floatFromInt(rank)) / 11.0;
        const rising = medianAtOrBelow(11, share);

        try std.testing.expect(rising > previous);
        previous = rising;
    }
}
