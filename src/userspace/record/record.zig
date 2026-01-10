const std = @import("std");
const cli = @import("cli");
const KernelInterface = @import("KernelInterface.zig");
const Program = @import("Program.zig");
const Tracee = @import("Tracee.zig");
const elf_section_parser = @import("elf_section_parser.zig");

pub fn record(options: cli.Options, init: std.process.Init) !void {
    const parsed_options = options.parse(struct {
        c: []const u8 = "",
        p: []const u8 = "",
    });

    const io = init.io;
    const allocator = init.gpa;

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    const user_program: Program = try .initFromParsedOptions(parsed_options, init.minimal.environ, allocator, io);
    defer user_program.deinit(allocator);

    var future_patch_addresses = io.async(elf_section_parser.getPatchAddr, .{ user_program, parsed_options.flags.p, allocator, io });
    defer if (future_patch_addresses.cancel(io)) |addresses| {
        var a = addresses;
        a.deinit(allocator);
    } else |_| {};

    var future_module = io.async(KernelInterface.loadModuleFromDefaultPath, .{ try getChardevOwner(init.minimal.environ), allocator, io });
    defer if (future_module.cancel(io)) |module| module.unload(io) catch {
        std.log.warn("Could not remove the kernel module, please try manually with:\n\n\tsudo rmmod pside\n", .{});
    } else |_| {};

    const tracee: Tracee = try .spawn(user_program, io);
    errdefer tracee.kill() catch std.log.err("Another error has occurred and could not kill the user program", .{});

    var module = try future_module.await(io);
    try module.startProfilerOnPid(tracee.pid);

    var patch_addresses = try future_patch_addresses.await(io);
    for (patch_addresses.items) |addresses| try tracee.patchProgressPoint(addresses);

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

fn getChardevOwner(env: std.process.Environ) !?KernelInterface.ChardevOwner {
    const gid = try std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse return null, 10);
    const uid = try std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse return null, 10);

    return .{ .uid = uid, .gid = gid };
}
