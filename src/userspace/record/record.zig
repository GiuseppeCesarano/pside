const std = @import("std");
const linux = std.os.linux;

const cli = @import("cli");
const communications = @import("communications");

const calling_user = @import("calling_user.zig");
const elf_section_parser = @import("elf_section_parser.zig");
const KernelInterface = @import("KernelInterface.zig");
const OutputFile = @import("OutputFile.zig");
const Program = @import("Program.zig");
const TracedProcess = @import("TracedProcess.zig");

pub const driver = @import("driver.zig").driver;

var global_traced_pid: std.atomic.Value(linux.pid_t) = .init(0);
var stopped: std.atomic.Value(bool) = .init(false);

pub fn record(options: cli.Options, init: std.process.Init) !void {
    const parsed_options = options.parse(struct {
        c: []const u8 = "",
        p: []const u8 = "",
        l: []const u8 = "",
        n: u32 = 1,
        k: bool = false,
    });

    const io = init.io;
    const allocator = init.gpa;

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    setIntHandler();

    const user_program: Program = try .initFromParsedOptions(parsed_options, init.minimal.environ, allocator, io);
    defer user_program.deinit(allocator);

    const owner = try calling_user.get(init.minimal.environ);

    var loaded_by_us = false;
    var module = KernelInterface.openControlDevice(io) catch |err| blk: {
        if (err == error.FileNotFound and linux.geteuid() == 0) {
            if (owner) |o| {
                try KernelInterface.driverLoad(o, allocator, io);
                loaded_by_us = true;
                break :blk KernelInterface.openControlDevice(io) catch |reopen_err| {
                    _ = KernelInterface.driverUnload(io) catch {};
                    return reopen_err;
                };
            }
        }

        switch (err) {
            error.FileNotFound => std.log.err("The pside module is not loaded\n\trun: sudo pside driver load", .{}),
            error.AccessDenied => std.log.err("Cannot open {s}: load the module as the same user with `sudo pside driver load`", .{KernelInterface.chardev_ctl_path}),
            else => std.log.err("Could not open {s}: {s}", .{ KernelInterface.chardev_ctl_path, @errorName(err) }),
        }
        return err;
    };
    defer {
        module.close(io);
        if (loaded_by_us) {
            if (KernelInterface.driverUnload(io)) |_| {} else |err| std.log.warn("Could not remove the kernel module ({s}); remove it manually with `sudo pside driver unload`.", .{@errorName(err)});
        }
    }

    const vma_name = resolveVmaName(parsed_options.flags.l, user_program.path);

    var future_patch_addresses = io.async(elf_section_parser.getPatchAddr, .{ user_program, parsed_options.flags.p, allocator, io });

    const patch_addresses = future_patch_addresses.await(io) catch |err| {
        const program_path = std.mem.span(user_program.path);
        switch (err) {
            error.NoPsideSection => std.log.err("'{s}' has no pside progress points; add PSIDE_THROUGHPUT_POINT(\"name\") to the source and rebuild.", .{program_path}),
            error.NoProgressPointsWithSuchName => std.log.err("No progress point named '{s}' in '{s}'.", .{ parsed_options.flags.p, program_path }),
            else => std.log.err("Could not read progress points from '{s}': {s}", .{ program_path, @errorName(err) }),
        }
        return err;
    };
    defer allocator.free(patch_addresses);

    const output_file: OutputFile = try .open(allocator, io, std.mem.span(user_program.path), owner);
    defer output_file.close(io);

    var i: usize = 0;
    while (i < parsed_options.flags.n and !stopped.load(.monotonic)) : (i += 1) {
        std.log.info("Run {}/{}", .{ i + 1, parsed_options.flags.n });

        var traced_process: TracedProcess = try .spawn(user_program, io);
        global_traced_pid.store(traced_process.pid, .release);

        errdefer {
            global_traced_pid.store(0, .release);
            traced_process.kill() catch std.log.err("Failed to kill process after error", .{});
        }

        try module.startProfilerOnPid(try .init(
            traced_process.pid,
            output_file.file.handle,
            vma_name,
            parsed_options.flags.k,
        ));

        for (patch_addresses) |address| try traced_process.patchProgressPoint(address);

        try traced_process.start();

        traced_process.wait() catch |err| {
            std.log.warn("Traced process {d} exited with error: {s}", .{ traced_process.pid, @errorName(err) });
            global_traced_pid.store(0, .release);
            return err;
        };

        global_traced_pid.store(0, .release);
        try module.stop();
    }

    if (!stopped.load(.monotonic)) {
        const program_name = std.fs.path.basename(std.mem.span(user_program.path));
        std.log.info("Done. View the report with: pside report {s}.pside", .{program_name});
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
        std.log.warn("Could not set SIGINT handler; Ctrl-C may leave the traced process running.", .{});
}

fn stop(sig: linux.SIG) callconv(.c) void {
    if (sig == .INT) {
        const pid = global_traced_pid.swap(0, .acq_rel);
        if (pid != 0) _ = linux.kill(pid, .KILL);
        stopped.store(true, .monotonic);
    }
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
