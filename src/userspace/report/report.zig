const std = @import("std");

const cli = @import("cli");
const OutputFileParseResults = @import("OutputFileParseResults");
const Statistics = @import("Statistics.zig");

const Server = @import("Server.zig");

const Collapsed = @import("Collapsed.zig");

pub fn report(options: cli.Options, init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const parsed_options = options.parse(struct { json: bool = false });
    try cli.validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try cli.validateOptions(parsed_options.parse_errors, "Could not parse: ");

    var positional = parsed_options.positional_arguments orelse {
        std.log.err("Usage: pside report <file.pside>", .{});
        return error.MissingArgument;
    };

    const path = positional.next().?;
    const path_null = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(path_null);

    const throughput = throughput: {
        var arena: std.heap.ArenaAllocator = .init(allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        const parsed_results: OutputFileParseResults = parse: {
            errdefer std.log.err("Could not read profile '{s}' (missing, not a pside file, or wrong version).", .{path});
            break :parse try .parse(arena_allocator, io, path_null);
        };

        const collapsed: Collapsed = collapse: {
            errdefer std.log.err("Could not resolve symbols from '{s}' (is the profiled binary present and built with -g?).", .{parsed_results.path});
            break :collapse try .onDwarfSymbol(arena_allocator, io, parsed_results);
        };

        break :throughput try Statistics.Throughput.compute(allocator, collapsed.throughput);
    };
    defer throughput.deinit(allocator);

    if (parsed_options.flags.json) {
        try writeJson(allocator, io, path, throughput);
        return;
    }

    var server: Server = try .init(allocator, io, &throughput);
    defer server.deinit(allocator, io);
    var server_run = try io.concurrent(Server.run, .{ &server, allocator, io });

    server.openInBrowser(io);
    std.log.info("Server running: http://[::1]:{}", .{server.port()});

    _ = try server_run.await(io);
}

fn writeJson(allocator: std.mem.Allocator, io: std.Io, path: []const u8, throughput: Statistics.Throughput) !void {
    const suffix = ".pside";
    const stem = if (std.mem.endsWith(u8, path, suffix)) path[0 .. path.len - suffix.len] else path;
    const out_name = try std.mem.concat(allocator, u8, &.{ stem, ".json" });
    defer allocator.free(out_name);

    const body = try std.json.Stringify.valueAlloc(allocator, throughput.vmas, .{});
    defer allocator.free(body);

    const file = try std.Io.Dir.cwd().createFile(io, out_name, .{});
    defer file.close(io);

    var buf: [4096]u8 = undefined;
    var writer = file.writer(io, &buf);
    try writer.interface.writeAll(body);
    try writer.flush();

    std.log.info("JSON report written to {s}", .{out_name});
}
