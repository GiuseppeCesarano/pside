const std = @import("std");

const cli = @import("cli");
const OutputFileParseResults = @import("OutputFileParseResults");
const Statistics = @import("Statistics.zig");

const Server = @import("Server.zig");

const Collapsed = @import("Collapsed.zig");

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

    var arena: std.heap.ArenaAllocator = .init(allocator);
    const arena_allocator = arena.allocator();

    const parsed_results: OutputFileParseResults = try .parse(arena_allocator, io, path_null);
    const collapsed: Collapsed = try .onDwarfSymbol(arena_allocator, io, parsed_results);

    const throughput = try Statistics.Throughput.compute(allocator, collapsed.throughput);
    defer throughput.deinit(allocator);

    arena.deinit();

    var server: Server = try .init(allocator, io, &throughput);
    defer server.deinit(allocator, io);
    var server_run = try io.concurrent(Server.run, .{ &server, allocator, io });

    io.sleep(.fromMilliseconds(5), .real) catch {};

    server.openInBrowser(io);
    std.log.info("Server running: http://[::1]:{}", .{server.port()});

    _ = try server_run.await(io);
}

fn validateOptions(optional_errors: ?cli.Options.Iterator, comptime msg: []const u8) !void {
    if (optional_errors) |errors| {
        @branchHint(.cold);
        var it = errors;
        while (it.next()) |flag| std.log.err("{s}{s}", .{ msg, flag });
        return error.InvalidOption;
    }
}
