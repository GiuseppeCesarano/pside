const std = @import("std");

const cli = @import("cli");
const OutputFileParserResult = @import("OutputFileParserResult");

const Server = @import("Server.zig");

pub fn report(options: cli.Options, init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const parsed_options = options.parse(struct {});
    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    var positional = parsed_options.positional_arguments orelse {
        std.log.err("Usage: report <file.pside>", .{});
        return error.MissingArgument;
    };
    const path = positional.next().?;
    const path_null = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(path_null);

    var parsed_results: OutputFileParserResult = try .parse(allocator, io, path_null);
    defer parsed_results.deinit(allocator);

    var server: Server = try .init(allocator, io);
    defer server.deinit(allocator, io);

    server.openInBrowser(io);
    std.log.info("Server running: http://[::1]:{}", .{server.port()});
    try server.run(allocator, io);
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
