const std = @import("std");
const cli = @import("cli");
const ThroughputRecord = @import("communications").ThroughputRecord;

pub fn report(options: cli.Options, init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    const parsed_options = options.parse(struct {});
    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    var positional = parsed_options.positional_arguments orelse {
        std.log.err("Usage: report <file.pside>", .{});
        return error.MissingArgument;
    };
    const path = positional.next().?;

    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const file_size = try file.length(io);
    if (file_size % @sizeOf(ThroughputRecord) != 0) {
        std.log.err("File size {d} is not a multiple of record size {d}, file may be corrupt", .{ file_size, @sizeOf(ThroughputRecord) });
        return error.CorruptFile;
    }

    const record_count = file_size / @sizeOf(ThroughputRecord);
    const records = try allocator.alloc(ThroughputRecord, record_count);
    defer allocator.free(records);

    const bytes = std.mem.sliceAsBytes(records);
    const bytes_read = try file.readPositionalAll(io, bytes, 0);
    if (bytes_read != bytes.len) {
        std.log.err("Expected {d} bytes, read {d}", .{ bytes.len, bytes_read });
        return error.UnexpectedEof;
    }

    printRecords(records);
}

fn printRecords(records: []const ThroughputRecord) void {
    std.log.info("{d} records found", .{records.len});
    for (records, 0..) |r, i| {
        std.log.info(
            "[{d}] ip=0x{x} prog_delta={d} wall={d}us total_delay={d}us delay_per_tick={d}",
            .{ i, r.ip, r.prog_delta, r.wall, r.total_delay, r.delay_per_tick },
        );
    }
}

fn validateOptions(optional_errors: ?cli.Options.Iterator, comptime msg: []const u8) !void {
    if (optional_errors) |errors| {
        @branchHint(.cold);
        var it = errors;
        while (it.next()) |flag| {
            std.log.err("{s}{s}", .{ msg, flag });
        }
        return error.InvalidOption;
    }
}
