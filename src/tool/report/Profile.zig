const std = @import("std");

const serialization = @import("serialization");
const payload = serialization.payload;
const speedup_levels_len = serialization.speedup_levels_len;
const speedup_step_per_level = serialization.speedup_step_per_level;

const Graph = @import("Graph.zig");

const Profile = @This();

vmas: []Vma,

pub const Vma = struct {
    name: []const u8,
    graphs: []Graph,

    pub fn deinit(this: Vma, gpa: std.mem.Allocator) void {
        for (this.graphs) |graph| gpa.free(graph.location);

        gpa.free(this.graphs);
        gpa.free(this.name);
    }
};

pub const Error = error{
    FileUnreadable,
    NotAPsideFile,
    MalformedVmaFrame,
    MalformedFileFrame,
    MalformedRecordsFrame,
    UnknownVmaId,
    UnknownFileId,
    BadSpeedupPercent,
    OutOfMemory,
};

pub fn fromFilePath(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !Profile {
    var file_map = try mapFile(io, path);
    defer file_map.destroy(io);

    var reader: std.Io.Reader = .fixed(file_map.memory);
    _ = try serialization.Header.read(&reader);

    var parser: Parser = .init(gpa);
    defer parser.deinit();

    var frames: payload.Frame.Iterator = .init(&reader);
    while (frames.next()) |frame| try parser.take(frame);

    return .{ .vmas = try parser.finish() };
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

const Parser = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    buckets: std.array_hash_map.String(Sites) = .empty,
    names: std.AutoHashMapUnmanaged(payload.VmaId, []const u8) = .empty,
    file_names: std.AutoHashMapUnmanaged(payload.FileId, []const u8) = .empty,

    const Levels = [speedup_levels_len]std.ArrayList(f32);
    const Sites = std.array_hash_map.Auto(Site, Levels);
    const Site = struct { file: payload.FileId, line: u32 };

    const min_progress = 5;

    fn init(gpa: std.mem.Allocator) Parser {
        return .{ .gpa = gpa, .arena = .init(gpa) };
    }

    fn deinit(this: *Parser) void {
        this.arena.deinit();
        this.* = undefined;
    }

    fn take(this: *Parser, frame: payload.Frame) Error!void {
        switch (frame.tag) {
            .vma => try this.takeVma(frame.body),
            .file => try this.takeFile(frame.body),
            .records => try this.takeRecords(frame.body),
            else => {},
        }
    }

    fn takeFile(this: *Parser, body: []const u8) Error!void {
        const allocator = this.arena.allocator();

        const declared = payload.File.decode(body) orelse return Error.MalformedFileFrame;

        const file_name = try this.file_names.getOrPut(allocator, declared.id);
        if (!file_name.found_existing) file_name.value_ptr.* = try allocator.dupe(u8, declared.name);
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
            if (sample.progress_delta < min_progress or sample.injected_us >= sample.time_delta_us) continue;

            const virtual_time: f32 = @floatFromInt(sample.time_delta_us - sample.injected_us);
            const throughput = @as(f32, @floatFromInt(sample.progress_delta)) / virtual_time;

            const site = try sites.getOrPut(allocator, .{ .file = sample.file, .line = sample.line });
            if (!site.found_existing) site.value_ptr.* = @splat(.empty);

            const level = &site.value_ptr[@divExact(speedup, speedup_step_per_level)];
            try level.append(allocator, throughput);
        }
    }

    fn finish(this: *Parser) Error![]Vma {
        const vmas = try this.gpa.alloc(Vma, this.buckets.count());

        var built: usize = 0;
        errdefer {
            for (vmas[0..built]) |vma| vma.deinit(this.gpa);
            this.gpa.free(vmas);
        }

        for (this.buckets.keys(), this.buckets.values()) |name, sites| {
            vmas[built] = try this.buildVma(name, sites);
            built += 1;
        }

        return vmas;
    }

    fn buildVma(this: *Parser, name: []const u8, sites: Sites) Error!Vma {
        const owned_name = try this.gpa.dupe(u8, name);
        errdefer this.gpa.free(owned_name);

        const graphs = try this.gpa.alloc(Graph, sites.count());

        var measured: usize = 0;
        errdefer {
            for (graphs[0..measured]) |graph| this.gpa.free(graph.location);
            this.gpa.free(graphs);
        }

        for (sites.keys(), sites.values()) |site, levels| {
            var samples: [speedup_levels_len][]f32 = undefined;
            for (&samples, levels) |*level, list| level.* = list.items;

            const file_name = this.file_names.get(site.file) orelse return Error.UnknownFileId;
            const location_name = try std.fmt.allocPrint(this.gpa, "{s}:{}", .{ file_name, site.line });
            graphs[measured] = Graph.init(location_name, samples) catch {
                this.gpa.free(location_name);
                continue;
            };
            measured += 1;
        }

        const measured_graphs = try this.gpa.realloc(graphs, measured);
        std.mem.sort(Graph, measured_graphs, {}, Graph.byArea);

        return .{ .name = owned_name, .graphs = measured_graphs };
    }
};
