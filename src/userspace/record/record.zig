const std = @import("std");
const cli = @import("cli");
const KernelInterface = @import("KernelInterface.zig");
const Program = @import("Program.zig");
const Tracee = @import("Tracee.zig");
const elf_section_parser = @import("elf_section_parser.zig");

const linux = std.os.linux;

// Needs to be global so we can kill it inside SIGINT handler
var gtracee: ?Tracee = null;

pub fn record(options: cli.Options, init: std.process.Init) !void {
    const parsed_options = options.parse(struct {
        c: []const u8 = "",
        p: []const u8 = "",
    });

    const io = init.io;
    const allocator = init.gpa;

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    setIntHandler();

    const user_program: Program = try .initFromParsedOptions(parsed_options, init.minimal.environ, allocator, io);
    defer user_program.deinit(allocator);

    var future_patch_addresses = io.async(elf_section_parser.getPatchAddr, .{ user_program, parsed_options.flags.p, allocator, io });
    defer if (future_patch_addresses.cancel(io)) |addresses| allocator.free(addresses) else |_| {};

    var future_module = io.async(KernelInterface.loadModuleFromDefaultPath, .{ try getChardevOwner(init.minimal.environ), allocator, io });
    defer if (future_module.cancel(io)) |module| module.unload(io) catch |err| {
        std.log.warn("Could not remove the kernel module ({s}), please try manually with:\n\n\tsudo rmmod pside\n", .{@errorName(err)});
    } else |_| {};

    gtracee = try .spawn(user_program, io);
    const tracee = &gtracee.?;
    errdefer tracee.kill() catch std.log.err("Another error has occurred and could not kill the user program", .{});

    var module = try future_module.await(io);
    try module.startProfilerOnPid(tracee.pid);

    for (try future_patch_addresses.await(io)) |address|
        if (address != 0) try tracee.patchProgressPoint(address);

    try tracee.start();
    _ = tracee.wait() catch std.log.warn("Traced process died, experiment output could be incomplete or bad", .{});
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

fn removeModuleOnSig(sig: linux.SIG) callconv(.c) void {
    if (sig == .INT) if (gtracee) |*t| t.kill() catch {};
}

fn setIntHandler() void {
    const sa = linux.Sigaction{
        .flags = 0,
        .handler = .{ .handler = removeModuleOnSig },
        .mask = linux.sigemptyset(),
    };
    if (linux.errno(linux.sigaction(.INT, &sa, null)) != .SUCCESS)
        std.log.warn(
            \\Could not set SIGINT handler.
            \\If SIGINT is received, you will need to manually remove the kernel module with:
            \\
            \\    sudo rmmod {s}
            \\
        , .{KernelInterface.name});
}

fn getChardevOwner(env: std.process.Environ) !?KernelInterface.ChardevOwner {
    const gid = try std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse return null, 10);
    const uid = try std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse return null, 10);

    return .{ .uid = uid, .gid = gid };
}
