const std = @import("std");
const linux = std.os.linux;

const cli = @import("cli");

const elf_section_parser = @import("elf_section_parser.zig");
const KernelInterface = @import("KernelInterface.zig");
const OutputFile = @import("OutputFile.zig");
const Program = @import("Program.zig");
const TracedProcess = @import("TracedProcess.zig");

// Needs to be global so we can kill it inside SIGINT handler
var global_traced_process: ?TracedProcess = null;
var stopped: std.atomic.Value(bool) = .init(false);

pub fn record(options: cli.Options, init: std.process.Init) !void {
    const parsed_options = options.parse(struct {
        c: []const u8 = "",
        p: []const u8 = "",
        l: []const u8 = "",
        n: u32 = 1,
    });

    const io = init.io;
    const allocator = init.gpa;

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    setIntHandler();

    const user_program: Program = try .initFromParsedOptions(parsed_options, init.minimal.environ, allocator, io);
    defer user_program.deinit(allocator);

    const calling_user = try getCallingUser(init.minimal.environ);

    var module = try KernelInterface.loadModuleFromDefaultPath(calling_user, allocator, io);
    defer module.unload(io) catch |err| {
        std.log.warn("Could not remove the kernel module ({s}), please try manually with:\n\n\tsudo rmmod pside\n", .{@errorName(err)});
    };

    const vma_name = resolveVmaName(parsed_options.flags.l, user_program.path);

    var future_patch_addresses = io.async(elf_section_parser.getPatchAddr, .{ user_program, parsed_options.flags.p, allocator, io });

    const patch_addresses = try future_patch_addresses.await(io);
    defer allocator.free(patch_addresses);

    const output_file: OutputFile = try .open(allocator, io, std.mem.span(user_program.path), calling_user);
    defer output_file.close(io);

    var i: usize = 0;
    while (i < parsed_options.flags.n and !stopped.load(.monotonic)) : (i += 1) {
        std.log.info("Run {}/{}", .{ i + 1, parsed_options.flags.n });

        global_traced_process = try .spawn(user_program, io);
        const traced_process = &global_traced_process.?;

        errdefer traced_process.kill() catch std.log.err("Failed to kill process after error", .{});

        try module.startProfilerOnPid(traced_process.pid, output_file.file.handle, vma_name);

        for (patch_addresses) |address| if (address != 0) try traced_process.patchProgressPoint(address);

        try traced_process.start();

        _ = traced_process.wait() catch |err| std.log.warn("Traced process {d} exited with error: {s}", .{ traced_process.pid, @errorName(err) });

        try module.stop();

        global_traced_process = null;

        try std.Io.sleep(io, .fromMilliseconds(1), .real);
    }
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

fn setIntHandler() void {
    const sa = linux.Sigaction{
        .flags = 0,
        .handler = .{ .handler = stop },
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

fn stop(sig: linux.SIG) callconv(.c) void {
    if (sig == .INT) {
        if (global_traced_process) |*t| t.kill() catch {};
        stopped.store(true, .monotonic);
    }
}

fn getCallingUser(env: std.process.Environ) !?[2]u32 {
    const gid = try std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse return null, 10);
    const uid = try std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse return null, 10);

    return .{ uid, gid };
}

fn resolveVmaName(flag: []const u8, program_path: [*:0]const u8) []const u8 {
    if (flag.len != 0) return flag;

    const path = std.mem.span(program_path);
    const base = std.fs.path.basename(path);

    return if (std.mem.lastIndexOfScalar(u8, base, '.')) |dot|
        base[0..dot]
    else
        base;
}
