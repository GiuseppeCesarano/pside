const std = @import("std");

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
    var res: OutputFileParseResults = .{ .vmas = .empty, .hash = undefined, .path = "" };

    const MiB = 1024 * 1024;
    const buffer = try arena_allocator.alignedAlloc(u8, .fromByteUnits(std.heap.pageSize()), 2 * MiB);
    defer arena_allocator.free(buffer);

    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var reader = file.reader(io, buffer);
    const r = &reader.interface;

    const header = try r.takeStructPointer(serialization.Header);
    if (!header.isValid()) return error.NotAPsideFile;
    res.hash = header.binary_hash;

    var vma_names: std.AutoHashMapUnmanaged(u32, []const u8) = .empty;

    while (r.takeStructPointer(serialization.FrameHeader)) |frame| {
        const tag = frame.tag;
        const length = frame.length;

        const payload = r.take(length) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };

        switch (tag) {
            .binary_path => res.path = try arena_allocator.dupe(u8, payload),
            .vma => {
                var pr: std.Io.Reader = .fixed(payload);
                const vma_frame = try pr.takeStructPointer(serialization.VmaFrame);
                const name = try arena_allocator.dupe(u8, payload[@sizeOf(serialization.VmaFrame)..]);
                try vma_names.put(arena_allocator, vma_frame.vma_id, name);
            },
            .records => {
                var pr: std.Io.Reader = .fixed(payload);
                const records_frame = try pr.takeStructPointer(serialization.RecordsFrame);
                try parseRecords(arena_allocator, &pr, records_frame, length, &res.vmas, vma_names);
            },
            else => {},
        }

        const pad = serialization.pad8(length) - length;
        if (pad != 0) r.discardAll(pad) catch break;
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    }

    return res;
}

fn parseRecords(
    arena_allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    frame: *align(1) const serialization.RecordsFrame,
    length: u32,
    vmas: *Vmas,
    vma_names: std.AutoHashMapUnmanaged(u32, []const u8),
) !void {
    if (frame.record_size == 0) return error.MalformedRecordsFrame;

    const count = (length - @sizeOf(serialization.RecordsFrame)) / frame.record_size;

    switch (frame.kind) {
        .throughput => {
            if (frame.record_size < @sizeOf(serialization.record.Throughput)) return error.MalformedRecordsFrame;

            const name = vma_names.get(frame.vma_id) orelse return error.UnknownVmaId;
            const pair = try vmas.throughput.getOrPut(arena_allocator, name);
            if (!pair.found_existing) pair.value_ptr.* = .empty;

            const extra = frame.record_size - @sizeOf(serialization.record.Throughput);
            for (0..count) |_| {
                const sample = try reader.takeStructPointer(serialization.record.Throughput);
                try pair.value_ptr.append(arena_allocator, sample.*);
                if (extra != 0) try reader.discardAll(extra);
            }
        },
        .latency => return error.UnsupportedSectionKind,
        else => {},
    }
}
