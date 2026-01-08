const std = @import("std");
const cli = @import("cli");
const PsideKernelModule = @import("PsideKernelModule.zig");
const UserProgram = @import("UserProgram.zig");
const Tracee = @import("Tracee.zig");

pub fn record(options: cli.Options, init: std.process.Init) !void {
    const parsed_options = options.parse(struct {
        c: []const u8 = "",
    });

    const io = init.io;
    const allocator = init.gpa;

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    const chardev_owner = blk: {
        const env = init.minimal.environ;

        const gid = try std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse break :blk null, 10);
        const uid = try std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse break :blk null, 10);

        break :blk PsideKernelModule.ChardevOwner{ .uid = uid, .gid = gid };
    };

    var future_module = io.async(PsideKernelModule.loadFromDefaultPath, .{ chardev_owner, allocator, io });
    defer if (future_module.cancel(io)) |module| module.unload(io) catch {
        std.log.warn("Could not remove the kernel module, please try manually with:\n\n\tsudo rmmod pside\n", .{});
    } else |_| {};

    const user_program: UserProgram = try .initFromParsedOptions(parsed_options, init.minimal.environ, allocator, io);
    defer user_program.deinit(allocator);

    const tracee: Tracee = try .spawn(user_program, io);

    var module = try future_module.await(io);
    try module.startProfilerOnPid(tracee.pid);

    std.log.info("Remote getpid returns: {}", .{try tracee.syscall(.getpid, .{})});
    std.log.info("Remote time returns: {}", .{try tracee.syscall(.time, .{0})});

    try tracee.patchProgressPoint("");

    try tracee.start();
    _ = try tracee.wait();
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
