const std = @import("std");

const Collapsed = @import("Collapsed.zig");

const bootstrap_iterations = 1_000;
const confidence_interval_low: usize = @intFromFloat(bootstrap_iterations * 0.025);
const confidence_interval_high: usize = @intFromFloat(bootstrap_iterations * 0.975);

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
                percent: f32,
                ci_low: f32,
                ci_high: f32,
                singleton: bool,
            };

            location: []const u8,
            points: [Collapsed.Throughput.Vma.Experiments.speedups]Point,
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
        }

        return .{ .vmas = vmas };
    }

    fn computeGraph(allocator: std.mem.Allocator, experiments: Collapsed.Throughput.Vma.Experiments) !?Throughput.Vma.Graph {
        @setFloatMode(.optimized);

        if (experiments.datapoints[0].items.len < 5) return null;
        for (experiments.datapoints[1..]) |datapoint| if (datapoint.items.len == 0) return null;

        var graph: Throughput.Vma.Graph = .{
            .location = try allocator.dupe(u8, experiments.location),
            .points = undefined,
        };

        var rng_ctx: std.Random.DefaultPrng = .init(experiments.datapoints.len);
        const rng = rng_ctx.random();
        const bootstrap_distribution = try allocator.create([bootstrap_iterations]f32);
        defer allocator.destroy(bootstrap_distribution);
        var resampled = try allocator.alloc(f32, 50);
        defer allocator.free(resampled);

        const baseline = sortAndGet75Percentile(experiments.datapoints[0].items);

        for (graph.points[0..], experiments.datapoints) |*graph_point, datapoints| {
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
                .percent = 100.0 * sortAndGet75Percentile(datapoints.items) / baseline,
                .ci_low = bootstrap_distribution[confidence_interval_low],
                .ci_high = bootstrap_distribution[confidence_interval_high],
                .singleton = experiments.datapoints.len == 1,
            };
        }

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
