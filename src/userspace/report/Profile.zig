const std = @import("std");

const serialization = @import("serialization");
const payload = serialization.payload;
const speedup_levels_len = serialization.speedup_levels_len;
const speedup_step_per_level = serialization.speedup_step_per_level;

const Graph = @import("Graph.zig");
const Symbolizer = @import("Symbolizer.zig");

const Profile = @This();

pub const Error = error{
    FileUnreadable,
    NotAPsideFile,
    MissingBinaryPath,
    MalformedVmaFrame,
    MalformedRecordsFrame,
    UnknownVmaId,
    BadSpeedupPercent,
    DebugInfoUnreadable,
    OutOfMemory,
};

pub const Vma = struct {
    name: []const u8,
    graphs: []Graph,

    pub fn deinit(this: Vma, gpa: std.mem.Allocator) void {
        for (this.graphs) |graph| gpa.free(graph.location);

        gpa.free(this.graphs);
        gpa.free(this.name);
    }
};

vmas: []Vma,

pub fn fromFilePath(gpa: std.mem.Allocator, io: std.Io, path: []const u8) Error!Profile {
    var file_map = try mapFile(io, path);
    defer file_map.destroy(io);

    var reader: std.Io.Reader = .fixed(file_map.memory);
    _ = try serialization.Header.read(&reader);

    const binary_path = findBinaryPath(reader) orelse return Error.MissingBinaryPath;

    var parser: Parser = try .init(gpa, io, binary_path);
    errdefer parser.deinit(io);

    var frames: payload.Frame.Iterator = .init(&reader);
    while (frames.next()) |frame| try parser.take(frame);

    return .{ .vmas = try parser.finish(io) };
}

pub fn deinit(this: *Profile, gpa: std.mem.Allocator) void {
    for (this.vmas) |vma| vma.deinit(gpa);

    gpa.free(this.vmas);
    this.* = undefined;
}

fn mapFile(io: std.Io, path: []const u8) Error!std.Io.File.MemoryMap {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return Error.FileUnreadable;
    defer file.close(io);

    const length = file.length(io) catch return Error.FileUnreadable;
    if (length < @sizeOf(serialization.Header)) return Error.NotAPsideFile;

    return std.Io.File.MemoryMap.create(io, file, .{
        .len = @intCast(length),
        .protection = .{ .read = true, .write = false },
    }) catch return Error.FileUnreadable;
}

fn findBinaryPath(from: std.Io.Reader) ?[]const u8 {
    var reader = from;
    var frames: payload.Frame.Iterator = .init(&reader);

    var binary_path: ?[]const u8 = null;
    while (frames.next()) |frame| {
        if (frame.tag == .binary_path) binary_path = frame.body;
    }

    return binary_path;
}

const Parser = struct {
    const Levels = [speedup_levels_len]std.ArrayListUnmanaged(f32);
    const Sites = std.StringArrayHashMapUnmanaged(Levels);

    // Symbolizer does small allocations, and arena doesn't reuse freed memory,
    // on some profiles this costed 5 more GiB, using gpa instead.
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    symbolizer: Symbolizer,
    buckets: std.StringArrayHashMapUnmanaged(Sites) = .empty,
    names: std.AutoHashMapUnmanaged(payload.VmaId, []const u8) = .empty,

    fn init(gpa: std.mem.Allocator, io: std.Io, binary_path: []const u8) Error!Parser {
        return .{
            .gpa = gpa,
            .arena = .init(gpa),
            .symbolizer = Symbolizer.init(gpa, io, binary_path) catch return Error.DebugInfoUnreadable,
        };
    }

    fn deinit(this: *Parser, io: std.Io) void {
        this.symbolizer.deinit(this.gpa, io);
        this.arena.deinit();
        this.* = undefined;
    }

    fn take(this: *Parser, frame: payload.Frame) Error!void {
        switch (frame.tag) {
            .vma => try this.takeVma(frame.body),
            .records => try this.takeRecords(frame.body),
            else => {},
        }
    }

    fn takeVma(this: *Parser, body: []const u8) Error!void {
        const allocator = this.arena.allocator();

        const declared = payload.Vma.decode(body) orelse return Error.MalformedVmaFrame;

        const vma = try this.buckets.getOrPut(allocator, declared.name);
        if (!vma.found_existing) {
            vma.key_ptr.* = try allocator.dupe(u8, declared.name);
            vma.value_ptr.* = .empty;
        }

        try this.names.put(allocator, declared.id, vma.key_ptr.*);
    }

    fn takeRecords(this: *Parser, body: []const u8) Error!void {
        const allocator = this.arena.allocator();

        const batch = payload.records.Batch.decode(body) orelse return Error.MalformedRecordsFrame;
        if (batch.header.kind != .throughput) return;

        const name = this.names.get(batch.header.vma_id) orelse return Error.UnknownVmaId;
        const sites = this.buckets.getPtr(name).?;

        var samples = batch.iterate(payload.records.Throughput) orelse return Error.MalformedRecordsFrame;
        while (samples.next()) |sample| {
            const speedup = sample.speedup_percent;
            if (speedup > 100 or speedup % speedup_step_per_level != 0) return Error.BadSpeedupPercent;

            const location = try this.symbolizer.locate(this.gpa, sample.relative_ip);

            const site = try sites.getOrPut(allocator, location);
            if (!site.found_existing) {
                site.key_ptr.* = try allocator.dupe(u8, location);
                site.value_ptr.* = @splat(.empty);
            }

            const level = &site.value_ptr[@divExact(speedup, speedup_step_per_level)];
            try level.append(allocator, sample.throughput);
        }
    }

    fn finish(this: *Parser, io: std.Io) Error![]Vma {
        const vmas = try this.gpa.alloc(Vma, this.buckets.count());

        var built: usize = 0;
        errdefer {
            for (vmas[0..built]) |vma| vma.deinit(this.gpa);
            this.gpa.free(vmas);
        }

        for (this.buckets.keys(), this.buckets.values()) |name, *sites| {
            vmas[built] = try this.buildVma(name, sites);
            built += 1;
        }

        this.deinit(io);

        return vmas;
    }

    fn buildVma(this: *Parser, name: []const u8, sites: *Sites) Error!Vma {
        const owned_name = try this.gpa.dupe(u8, name);
        errdefer this.gpa.free(owned_name);

        const graphs = try this.gpa.alloc(Graph, sites.count());

        var measured: usize = 0;
        errdefer {
            for (graphs[0..measured]) |graph| this.gpa.free(graph.location);
            this.gpa.free(graphs);
        }

        for (sites.keys(), sites.values()) |location, *levels| {
            var samples: [speedup_levels_len][]f32 = undefined;
            for (&samples, levels) |*level, list| level.* = list.items;

            graphs[measured] = Graph.init(location, samples) catch continue;
            graphs[measured].location = try this.gpa.dupe(u8, location);
            measured += 1;
        }

        const measured_graphs = try this.gpa.realloc(graphs, measured);
        std.mem.sort(Graph, measured_graphs, {}, Graph.byArea);

        return .{ .name = owned_name, .graphs = measured_graphs };
    }
};
