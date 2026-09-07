const std = @import("std");

const cli = @import("cli");

const Graph = @import("Graph.zig");
const Profile = @import("Profile.zig");
const Server = @import("Server.zig");

pub fn report(options: cli.Options, init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const parsed_options = options.parse(struct { json: bool = false });
    cli.validateOptions(parsed_options.unknown_flags, "Unknown flag: ") catch std.process.exit(1);
    cli.validateOptions(parsed_options.parse_errors, "Could not parse: ") catch std.process.exit(1);

    var positional = parsed_options.positional_arguments orelse
        std.process.fatal("Usage: pside report <file.pside>", .{});

    const path = positional.next().?;

    var profile = Profile.fromFilePath(allocator, io, path) catch |err| switch (err) {
        Profile.Error.DebugInfoUnreadable => std.process.fatal("Could not read debug info for the binary recorded in '{s}'.", .{path}),
        else => std.process.fatal("Could not read profile '{s}' ({s}).", .{ path, @errorName(err) }),
    };
    defer profile.deinit(allocator);

    if (parsed_options.flags.json) {
        writeJson(allocator, io, path, profile) catch |err|
            std.process.fatal("Could not write json file ({s})", .{@errorName(err)});

        return;
    }

    var server: Server = try .init(allocator, io, &profile);
    defer server.deinit(allocator, io);
    var server_run = try io.concurrent(Server.run, .{ &server, allocator, io });

    server.openInBrowser(io);
    std.log.info("Server running: http://[::1]:{}", .{server.port()});

    _ = try server_run.await(io);
}

fn writeJson(allocator: std.mem.Allocator, io: std.Io, path: []const u8, profile: Profile) !void {
    const suffix = ".pside";
    const stem = if (std.mem.endsWith(u8, path, suffix)) path[0 .. path.len - suffix.len] else path;

    const out_name = try std.mem.concat(allocator, u8, &.{ stem, ".json" });
    defer allocator.free(out_name);

    const body = try std.json.Stringify.valueAlloc(allocator, profile.vmas, .{});
    defer allocator.free(body);

    const file = try std.Io.Dir.cwd().createFile(io, out_name, .{});
    defer file.close(io);

    var buf: [4096]u8 = undefined;
    var writer = file.writer(io, &buf);
    try writer.interface.writeAll(body);
    try writer.flush();

    std.log.info("JSON report written to {s}", .{out_name});
}

test {
    _ = Profile;
    _ = Graph;
}
