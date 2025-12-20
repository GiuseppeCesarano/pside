const std = @import("std");
const cli = @import("cli");
const PsideKernelModule = @import("PsideKernelModule.zig");
const UserProgram = @import("UserProgram.zig");

pub fn record(options: cli.Options, allocator: std.mem.Allocator, io: std.Io) !void {
    const parsed_options = options.parse(struct {
        c: []const u8 = "",
    });

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    var future_module = io.async(PsideKernelModule.loadFromDefaultPath, .{ allocator, io });
    defer if (future_module.cancel(io)) |module| module.unload(allocator, io) catch {} else |_| {
        std.log.warn("Could not remove the kernel module, please try manually with:\n\n\tsudo rmmod pside\n", .{});
    };

    const user_program: UserProgram = try .initFromParsedOptions(parsed_options, allocator, io);
    defer user_program.deinit(allocator);

    // TODO: Drop permissions to userspace using SUDO_USER
    var module = try future_module.await(io);
    var child: std.process.Child = .init(user_program.buffer, allocator);
    child.start_suspended = true;
    try child.spawn();

    try module.setPidForFilter(child.id);

    _ = std.posix.waitpid(child.id, std.os.linux.W.UNTRACED);
    try std.posix.kill(child.id, .CONT);

    _ = try child.wait();
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
