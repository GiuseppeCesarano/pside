const std = @import("std");

const cli = @import("cli");

const calling_user = @import("calling_user.zig");
const KernelInterface = @import("KernelInterface.zig");

pub fn driver(options: cli.Options, init: std.process.Init) !void {
    try cli.execute(options.args, help, .{ load, unload }, .{init});
}

fn load(_: cli.Options, init: std.process.Init) !void {
    const owner = try calling_user.get(init.minimal.environ) orelse {
        std.log.err("Loading the kernel module requires root, run with sudo", .{});
        return error.NotPrivileged;
    };

    try KernelInterface.driverLoad(owner, init.gpa, init.io);

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

fn unload(_: cli.Options, init: std.process.Init) !void {
    if (try KernelInterface.driverUnload(init.io))
        std.log.info("pside driver unloaded.", .{})
    else
        std.log.warn("The pside module was not loaded.", .{});
}

fn help(_: cli.Options, _: std.process.Init) void {
    std.log.info(
        \\pside driver — manage the profiler's kernel module
        \\
        \\USAGE
        \\  sudo pside driver load     Load the module and hand its devices to
        \\                             the invoking user, so `pside record` can
        \\                             then run without sudo.
        \\  sudo pside driver unload   Remove the module.
        \\
    , .{});
}
