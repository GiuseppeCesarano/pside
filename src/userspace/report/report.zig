const std = @import("std");

const cli = @import("cli");

pub fn report(options: cli.Options, init: std.process.Init) !void {
    const io = init.io;

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
