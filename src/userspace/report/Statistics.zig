const std = @import("std");

const Collapsed = @import("Collapsed.zig");

const bootstrap_iterations = 1_000;
const confidence_interval_low: usize = @intFromFloat(bootstrap_iterations * 0.025);
const confidence_interval_high: usize = @intFromFloat(bootstrap_iterations * 0.975);

// A line is reported once it has a baseline and at least this many distinct
// speedup levels; empty buckets in between are skipped, not fatal.
const min_baseline_samples = 5;
const min_speedup_points = 3;

fn sortAndGet75Percentile(data: []f32) f32 {
    @setFloatMode(.optimized);
    std.mem.sort(f32, data, {}, std.sort.asc(f32));

    const idx: f32 = 0.75 * @as(f32, @floatFromInt(data.len - 1));
    const lo: usize = @intFromFloat(@floor(idx));
    const hi = lo + 1;

    return if (hi >= data.len) data[lo] else data[lo] + (idx - @as(f32, @floatFromInt(lo))) * (data[hi] - data[lo]);
}

pub const Throughput = struct {
    pub const Vma = struct {
        pub const Graph = struct {
            pub const Point = struct {
                present: bool,
                percent: f32,
                ci_low: f32,
                ci_high: f32,
                singleton: bool,
            };

            location: []const u8,
            points: [Collapsed.Throughput.Vma.Experiments.speedups]Point,
            impact: f32,
        };

        name: []const u8,
        graphs: []Graph,
    };

    vmas: []Vma,

    pub fn compute(allocator: std.mem.Allocator, collapsed: Collapsed.Throughput) !Throughput {
        const vmas = try allocator.alloc(Vma, collapsed.vmas.len);

        for (vmas, collapsed.vmas) |*vma, collapsed_vma| {
            vma.name = try allocator.dupe(u8, collapsed_vma.name);
            vma.graphs = try allocator.alloc(Throughput.Vma.Graph, collapsed_vma.experiments.len);

            var i: usize = 0;
            for (collapsed_vma.experiments) |experiment|
                if (try computeGraph(allocator, experiment)) |graph| {
                    vma.graphs[i] = graph;
                    i += 1;
                };

            if (!allocator.resize(vma.graphs, i)) {
                const new_alloc = try allocator.dupe(Throughput.Vma.Graph, vma.graphs[0..i]);
                allocator.free(vma.graphs);
                vma.graphs = new_alloc;
            } else vma.graphs = vma.graphs[0..i];

            std.mem.sort(Throughput.Vma.Graph, vma.graphs, {}, sortGraphsByImpactDescending);
        }

        return .{ .vmas = vmas };
    }

    fn computeGraph(allocator: std.mem.Allocator, experiments: Collapsed.Throughput.Vma.Experiments) !?Throughput.Vma.Graph {
        @setFloatMode(.optimized);

        if (experiments.datapoints[0].items.len < min_baseline_samples) return null;

        var present_speedups: usize = 0;
        for (experiments.datapoints[1..]) |datapoint| {
            if (datapoint.items.len != 0) present_speedups += 1;
        }
        if (present_speedups < min_speedup_points) return null;

        var graph: Throughput.Vma.Graph = .{
            .location = try allocator.dupe(u8, experiments.location),
            .points = undefined,
            .impact = undefined,
        };

        var rng_ctx: std.Random.DefaultPrng = .init(std.hash.Wyhash.hash(0, experiments.location));
        const rng = rng_ctx.random();
        const bootstrap_distribution = try allocator.create([bootstrap_iterations]f32);
        defer allocator.destroy(bootstrap_distribution);
        var resampled = try allocator.alloc(f32, 50);
        defer allocator.free(resampled);

        const baseline = sortAndGet75Percentile(experiments.datapoints[0].items);

        for (graph.points[0..], experiments.datapoints) |*graph_point, datapoints| {
            if (datapoints.items.len == 0) {
                graph_point.* = .{ .present = false, .percent = 0, .ci_low = 0, .ci_high = 0, .singleton = false };
                continue;
            }

            if (resampled.len < datapoints.items.len) {
                allocator.free(resampled);
                resampled = try allocator.alloc(f32, datapoints.items.len);
            }

            for (bootstrap_distribution[0..]) |*bootstrap_elment| {
                for (resampled[0..datapoints.items.len]) |*sample| sample.* = datapoints.items[rng.uintLessThan(usize, datapoints.items.len)];
                bootstrap_elment.* = 100.0 * sortAndGet75Percentile(resampled[0..datapoints.items.len]) / baseline;
            }

            std.mem.sort(f32, bootstrap_distribution[0..], {}, std.sort.asc(f32));

            graph_point.* = .{
                .present = true,
                .percent = 100.0 * sortAndGet75Percentile(datapoints.items) / baseline,
                .ci_low = bootstrap_distribution[confidence_interval_low],
                .ci_high = bootstrap_distribution[confidence_interval_high],
                .singleton = datapoints.items.len == 1,
            };
        }

        graph.impact = rankMetric(&graph.points);

        return graph;
    }

    pub fn deinit(this: Throughput, allocator: std.mem.Allocator) void {
        for (this.vmas) |vma| {
            allocator.free(vma.name);
            for (vma.graphs) |graph| allocator.free(graph.location);
            allocator.free(vma.graphs);
        }
        allocator.free(this.vmas);
    }
};

fn theilSen(points: []const Throughput.Vma.Graph.Point) f32 {
    @setFloatMode(.optimized);
    const num_points = Collapsed.Throughput.Vma.Experiments.speedups;

    const num_pairs = (num_points * (num_points - 1)) / 2;
    var slopes: [num_pairs]f32 = undefined;
    var k: usize = 0;
    var i: usize = 0;

    while (i < num_points) : (i += 1) {
        if (!points[i].present) continue;
        var j: usize = i + 1;
        while (j < num_points) : (j += 1) {
            if (!points[j].present) continue;
            const dy = points[j].percent - points[i].percent;
            const dx = @as(f32, @floatFromInt(j - i)) * 5.0;
            slopes[k] = dy / dx;
            k += 1;
        }
    }

    if (k == 0) return 0.0;

    std.mem.sort(f32, slopes[0..k], {}, std.sort.asc(f32));

    const mid = k / 2;
    return if (k % 2 == 0)
        (slopes[mid - 1] + slopes[mid]) / 2.0
    else
        slopes[mid];
}

// Ranking metric: opportunity * trust. A positive slope is the payoff of
// optimizing this line; it's discounted by singletons (squared, so they weigh
// most) and by how many points sit confidently above the baseline.
fn rankMetric(points: []const Throughput.Vma.Graph.Point) f32 {
    @setFloatMode(.optimized);

    var present: f32 = 0;
    var singletons: f32 = 0;
    var beneficial: f32 = 0;
    for (points) |point| {
        if (!point.present) continue;
        present += 1;
        if (point.singleton) singletons += 1;
        if (point.ci_low > 100.0) beneficial += 1;
    }

    const opportunity = @max(theilSen(points) * 100.0, 0.0);
    const cleanliness = 1.0 - singletons / present;
    const confidence = 0.5 + 0.5 * beneficial / present;

    return opportunity * cleanliness * cleanliness * confidence;
}

fn sortGraphsByImpactDescending(_: void, lhs: Throughput.Vma.Graph, rhs: Throughput.Vma.Graph) bool {
    return lhs.impact > rhs.impact;
}
