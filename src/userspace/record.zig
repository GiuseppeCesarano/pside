const std = @import("std");
const cli = @import("cli");
const KernelModule = @import("kernel_module").KernelModule;

pub fn record(options: cli.Options, allocator: std.mem.Allocator, io: std.Io) !void {
    const parsed_options = options.parse(struct {
        c: []const u8 = "",
    });

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    var future_module = io.async(KernelModule("pside").loadFromDefaultPath, .{ allocator, io });
    defer if (future_module.cancel(io)) |module| module.unload(io) catch {} else |_| {
        std.log.warn("Could not remove the kernel module, please try manually with:\n\nsudo rmmod pside", .{});
    };

    const command = try createCommand(parsed_options, allocator);
    defer allocator.free(command);

    // TODO: Drop permissions to userspace using SUDO_USER
    var child: std.process.Child = .init(command, allocator);
    try child.spawn();

    var module = try future_module.await(io);

    try module.chardev_writer.interface.writeInt(@TypeOf(child.id), child.id, @import("builtin").target.cpu.arch.endian());
}

fn validateOptions(optinal_errors: ?cli.Options.Iterator, comptime msg: []const u8) !void {
    if (optinal_errors) |errors| {
        @branchHint(.cold);
        var it = errors;
        while (it.next()) |flag| {
            std.log.err("{s}{s}", .{ msg, flag });
        }

        return error.InvalidOption;
    }
}

fn createCommand(parsed: anytype, allocator: std.mem.Allocator) ![][]const u8 {
    if (!std.mem.eql(u8, parsed.flags.c, "")) {
        if (parsed.positional_arguments != null) return error.ExtraPositionalArguments;

        return try createCommandFromString(parsed.flags.c, allocator);
    }

    if (parsed.positional_arguments) |args| {
        var it = args;
        if (it.count() == 1) return try createCommandFromString(it.next().?, allocator);

        const buffer = try allocator.alloc([]const u8, it.count());

        for (buffer) |*str| {
            str.* = it.next().?;
        }

        return buffer;
    }

    return error.UnspecifiedCommand;
}

fn createCommandFromString(string: []const u8, allocator: std.mem.Allocator) ![][]const u8 {
    const buffer = try allocator.alloc([]const u8, std.mem.countScalar(u8, string, ' ') + 1);
    var it = std.mem.splitScalar(u8, string, ' ');

    for (buffer) |*str| {
        str.* = it.next().?;
    }

    return buffer;
}
