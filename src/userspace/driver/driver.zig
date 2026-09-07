const std = @import("std");

const cli = @import("cli");
const UserIds = @import("UserIds");

const KernelModule = @import("KernelModule.zig");

const Flags = struct {
    @"-silent": bool = false,
};

pub fn driver(options: cli.Options, init: std.process.Init) !void {
    try cli.execute(options.args, help, .{ load, unload }, .{init});
}

fn load(options: cli.Options, init: std.process.Init) !void {
    const parsed_options = options.parse(Flags);

    cli.validateOptions(parsed_options.unknown_flags, "Unknown flag: ") catch std.process.exit(1);
    cli.validateOptions(parsed_options.parse_errors, "Could not parse: ") catch std.process.exit(1);

    const owner = try UserIds.sudoCallerFromEnviron(init.minimal.environ) orelse
        std.process.fatal("Loading the kernel module requires root, run with sudo", .{});

    KernelModule.load(owner, init.gpa, init.io) catch |err| switch (err) {
        KernelModule.LoadError.ModuleAlreadyLoaded => std.process.fatal("The pside module is already loaded\n\trun: sudo pside driver unload", .{}),
        KernelModule.LoadError.NotPrivilegedOrLoadingDisabled => std.process.fatal("Loading the kernel module requires root, run with sudo", .{}),
        else => std.process.fatal("Could not load the kernel module ({s})", .{@errorName(err)}),
    };

    if (parsed_options.flags.@"-silent") return;

    std.log.info("pside driver loaded. You can now run `pside record` without sudo.", .{});
    std.log.warn(
        \\While loaded, any process running as this user can profile any
        \\process on the system through /dev/pside. It drives perf via the
        \\in-kernel API, so it is effectively perf_event_paranoid = -1 for
        \\this user. Unload it when you are done:
        \\
        \\    sudo pside driver unload
        \\
    , .{});
}

fn unload(options: cli.Options, init: std.process.Init) !void {
    const parsed_options = options.parse(Flags);

    cli.validateOptions(parsed_options.unknown_flags, "Unknown flag: ") catch std.process.exit(1);
    cli.validateOptions(parsed_options.parse_errors, "Could not parse: ") catch std.process.exit(1);

    const was_loaded = try KernelModule.unload(init.io);

    if (parsed_options.flags.@"-silent") return;

    if (was_loaded)
        std.log.info("pside driver unloaded.", .{})
    else
        std.log.warn("The pside module was not loaded.", .{});
}

fn help(_: cli.Options, _: std.process.Init) void {
    std.log.info(
        \\pside driver: manage the profiler's kernel module
        \\
        \\USAGE
        \\  sudo pside driver load     Load the module and hand its devices to
        \\                             the invoking user, so `pside record` can
        \\                             then run without sudo.
        \\  sudo pside driver unload   Remove the module.
        \\
        \\FLAGS
        \\  --silent                   Suppress the informational output; errors
        \\                             are still reported.
        \\
    , .{});
}
