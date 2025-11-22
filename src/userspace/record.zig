const std = @import("std");
const cli = @import("cli");
const KernelModule = @import("KernelModule");

pub fn record(options: cli.Options, allocator: std.mem.Allocator, io: std.Io) !void {
    const parsed_options = options.parse(struct {});

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    var future_module = io.async(KernelModule.loadFromDefaultModulePath, .{ allocator, io, "pside" });
    defer if (future_module.cancel(io)) |module| module.unload(io) catch {} else |_| {};

    const module = try future_module.await(io);
    defer module.unload(io) catch {};
}

inline fn validateOptions(optinal_errors: ?cli.Options.Iterator, comptime msg: []const u8) !void {
    if (optinal_errors) |errors| {
        @branchHint(.cold);
        var it = errors;
        while (it.next()) |flag| {
            std.log.err("{s}{s}", .{ msg, flag });
        }

        return error.InvalidOption;
    }
}
