const std = @import("std");
const assert = std.debug.assert;

const serialization = @import("serialization");

const OutputFileParseResults = @This();

pub const Vmas = struct {
    pub const VmaThroughputExperimentsMap = std.StringHashMapUnmanaged(std.ArrayListUnmanaged(serialization.record.Throughput));
    pub const VmaLatencyExperimentsMap = std.StringHashMapUnmanaged(std.ArrayListUnmanaged(serialization.record.Latency));

    throughput: VmaThroughputExperimentsMap,
    latency: VmaLatencyExperimentsMap,

    pub const empty: Vmas = .{ .throughput = .empty, .latency = .empty };
};

vmas: Vmas,
hash: [32]u8,
path: []const u8,

pub fn parse(arena_allocator: std.mem.Allocator, io: std.Io, path: [:0]const u8) !OutputFileParseResults {
    var res: OutputFileParseResults = undefined;

    const MiB = 1024 * 1024;
    const buffer = try arena_allocator.alignedAlloc(u8, .fromByteUnits(std.heap.pageSize()), 2 * MiB);
    defer arena_allocator.free(buffer);

    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var reader = file.reader(io, buffer);

    try checkHeader(&reader.interface);

    res.hash = (try reader.interface.takeArray(@sizeOf(serialization.Hash))).*;
    res.path = try arena_allocator.dupe(u8, (try reader.interface.takeSentinel(0))[0..]);

    res.vmas = try parseExperiments(arena_allocator, &reader.interface);

    return res;
}

fn checkHeader(reader: *std.Io.Reader) !void {
    const header = try reader.takeStructPointer(serialization.Header);
    if (!std.mem.eql(u8, &header.magic, &serialization.Header.default.magic)) return error.WrongMagic;
    if (header.version.major != serialization.Header.default.version.major) return error.VersionMajorNotMatching;
}

fn parseExperiments(
    arena_allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
) !Vmas {
    var res: Vmas = .empty;

    return while (reader.takeStructPointer(serialization.SectionHeader)) |section| {
        const vma = (try reader.takeSentinel(0))[0..];

        switch (section.kind) {
            .throughput => {
                const pair = try res.throughput.getOrPut(arena_allocator, vma);
                if (!pair.found_existing) {
                    pair.key_ptr.* = try arena_allocator.dupe(u8, vma);
                    pair.value_ptr.* = .empty;
                }
                var record = try reader.takeStructPointer(serialization.record.Throughput);
                while (!record.isEmpty()) : (record = try reader.takeStructPointer(serialization.record.Throughput))
                    try pair.value_ptr.append(arena_allocator, record.*);
            },

            .latency => {
                return error.UnsupportedSectionKind; // TODO
            },
        }
    } else |err| if (err == std.Io.Reader.Error.EndOfStream) res else err;
}
