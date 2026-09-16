const std = @import("std");
const linux = std.os.linux;

const cli = @import("cli");
const communications = @import("communications");
const safety = @import("safety");
const UserIds = @import("UserIds");

const elf_section_parser = @import("elf_section_parser.zig");
const KernelControlDevice = @import("KernelControlDevice.zig");
const OutputFile = @import("OutputFile.zig");
const Program = @import("Program.zig");
const TracedProcess = @import("TracedProcess.zig");

const Flags = struct {
    c: []const u8 = "",
    p: []const u8 = "",
    l: []const u8 = "",
    prepare: []const u8 = "",
    n: u32 = 1,
    k: bool = false,
};

var interrupted: std.atomic.Value(bool) = .init(false);

pub fn record(options: cli.Options, init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const parsed_options = options.parse(Flags);
    cli.validateOptions(parsed_options.unknown_flags, "Unknown flag: ") catch std.process.exit(1);
    cli.validateOptions(parsed_options.parse_errors, "Could not parse: ") catch std.process.exit(1);

    const progress_point_name = parsed_options.flags.p;

    setSigintHandler();

    const profiled_program = Program.initFromParsedOptions(parsed_options, init.minimal.environ, allocator, io) catch |err|
        switch (err) {
            Program.InitError.ExtraPositionalArguments => std.process.fatal("Give the program either positionally or with -c, not both.", .{}),
            Program.InitError.UnspecifiedCommand => std.process.fatal("No program to profile.\n\tUsage: sudo pside record <program> [args…]", .{}),
            else => std.process.fatal("Could not resolve the program ({s})", .{@errorName(err)}),
        };
    defer profiled_program.deinit(allocator);

    const user_ids = UserIds.sudoCallerFromEnviron(init.minimal.environ) catch |err|
        std.process.fatal("Could not read the invoking user ({s})", .{@errorName(err)});

    const control_device, const module_ownership = openControlDevice(io);
    defer {
        control_device.close(io);
        if (module_ownership == .ours) unloadModule(io);
    }

    var future_patch_addresses = io.async(elf_section_parser.getPatchAddr, .{ profiled_program, progress_point_name, allocator, io });

    const vma_name = resolveVmaName(parsed_options.flags.l, profiled_program.path);
    const output_file = OutputFile.open(allocator, io, std.mem.span(profiled_program.path), vma_name, user_ids) catch |err| switch (err) {
        OutputFile.OpenError.HashDontMatch => std.process.fatal("{s}.pside was recorded from a different build of the binary; delete it to start a fresh profile.", .{profiled_program.path}),
        OutputFile.OpenError.NotAPsideFile => std.process.fatal("{s}.pside is not a pside recording; delete it to start a fresh profile.", .{profiled_program.path}),
        else => std.process.fatal("Could not open {s}.pside ({s})", .{ profiled_program.path, @errorName(err) }),
    };
    defer output_file.close(io);

    const patch_addresses = future_patch_addresses.await(io) catch |err| switch (err) {
        elf_section_parser.ParseError.NoPsideSection => std.process.fatal("'{s}' has no pside progress points; add PSIDE_THROUGHPUT_POINT(\"name\") to the source and rebuild.", .{profiled_program.path}),
        elf_section_parser.ParseError.NoProgressPointsWithSuchName => std.process.fatal("No progress point named '{s}' in '{s}'.", .{ progress_point_name, profiled_program.path }),
        else => std.process.fatal("Could not read progress points from '{s}' ({s})", .{ profiled_program.path, @errorName(err) }),
    };
    defer allocator.free(patch_addresses);

    var profiler = Profiler.init(
        control_device,
        output_file.file.handle,
        vma_name,
        parsed_options.flags.k,
    ) catch |err| std.process.fatal("Could not use VMA name '{s}' ({s})", .{ vma_name, @errorName(err) });

    const prepare: ?PrepareCommand = if (parsed_options.flags.prepare.len != 0)
        .{ .command = parsed_options.flags.prepare, .user_ids = user_ids }
    else
        null;

    executeRuns(io, parsed_options.flags.n, .{
        .prepare = prepare,
        .profiled_program = profiled_program,
        .patch_addresses = patch_addresses,
        .profiler = &profiler,
    });

    std.log.info("Done. View the report with: pside report {s}.pside", .{std.fs.path.basename(std.mem.span(profiled_program.path))});
}

fn setSigintHandler() void {
    const sa = linux.Sigaction{
        .flags = 0,
        .handler = .{ .handler = handleSigint },
        .mask = linux.sigemptyset(),
    };

    if (linux.errno(linux.sigaction(.INT, &sa, null)) != .SUCCESS)
        std.log.warn("Could not set SIGINT handler; Ctrl-C may leave the traced process running.", .{});
}

fn handleSigint(sig: linux.SIG) callconv(.c) void {
    if (sig == .INT) {
        TracedProcess.killTraced();
        interrupted.store(true, .monotonic);
    }
}

const ModuleOwnership = enum { ours, preexisting };

fn openControlDevice(io: std.Io) struct { KernelControlDevice, ModuleOwnership } {
    const device = KernelControlDevice.open(io) catch |err| {
        if (err == KernelControlDevice.OpenControlError.ModuleNotLoaded and linux.geteuid() == 0) return loadModuleAndOpen(io);

        switch (err) {
            KernelControlDevice.OpenControlError.ModuleNotLoaded => std.process.fatal("The pside module is not loaded\n\trun: sudo pside driver load", .{}),
            KernelControlDevice.OpenControlError.AccessDenied => std.process.fatal("Cannot open {s}: load the module as the same user with `sudo pside driver load`", .{communications.control_device_path}),
            else => std.process.fatal("Could not open {s} ({s})", .{ communications.control_device_path, @errorName(err) }),
        }
    };

    return .{ device, .preexisting };
}

fn loadModuleAndOpen(io: std.Io) struct { KernelControlDevice, ModuleOwnership } {
    driverCommand(io, .load) catch std.process.fatal("Could not load the kernel module", .{});

    const device = KernelControlDevice.open(io) catch |err| {
        driverCommand(io, .unload) catch {};
        std.process.fatal("Could not open {s} after loading the module ({s})", .{ communications.control_device_path, @errorName(err) });
    };

    return .{ device, .ours };
}

fn unloadModule(io: std.Io) void {
    driverCommand(io, .unload) catch |err|
        std.log.warn("Could not remove the kernel module ({s}); remove it manually with `sudo pside driver unload`.", .{@errorName(err)});
}

const DriverError = error{ CouldNotSpawn, CouldNotWait, DriverCommandFailed };

fn driverCommand(io: std.Io, verb: enum { load, unload }) DriverError!void {
    var child = std.process.spawn(io, .{
        .argv = &.{ "/proc/self/exe", "driver", @tagName(verb), "--silent" },
    }) catch return DriverError.CouldNotSpawn;

    const term = child.wait(io) catch return DriverError.CouldNotWait;

    if (!term.success()) return DriverError.DriverCommandFailed;
}

fn resolveVmaName(flag: []const u8, program_path: [*:0]const u8) []const u8 {
    if (flag.len != 0) return flag;

    return std.fs.path.basename(std.mem.span(program_path));
}

const Profiler = struct {
    const Session = enum { idle, profiling };

    device: KernelControlDevice,
    start_options: communications.StartOptions,
    state: safety.State(Session),

    pub const InitError = communications.StartOptions.InitError;

    fn init(
        device: KernelControlDevice,
        output_fd: linux.fd_t,
        vma_name: []const u8,
        attribute_kernel_samples: bool,
    ) InitError!Profiler {
        return .{
            .device = device,
            .start_options = try .init(undefined, output_fd, vma_name, attribute_kernel_samples),
            .state = .init(.idle),
        };
    }

    fn controlFd(this: Profiler) linux.fd_t {
        return this.device.ctl.handle;
    }

    fn start(this: *Profiler, pid: linux.pid_t) KernelControlDevice.ControlError!void {
        this.state.assertIs(.idle);

        var start_options = this.start_options;
        start_options.pid = pid;

        try this.device.startProfilerOnPid(start_options);

        this.state.transition(.profiling);
    }

    fn stop(this: *Profiler) KernelControlDevice.ControlError!void {
        this.state.assertIs(.profiling);

        try this.device.stop();

        this.state.transition(.idle);
    }
};

const PrepareCommand = struct {
    command: []const u8,
    user_ids: ?UserIds,

    pub const RunError = error{ CouldNotSpawn, CouldNotWait, PrepareCommandFailed };

    fn run(this: PrepareCommand, io: std.Io) RunError!void {
        const uid, const gid = if (this.user_ids) |ids| .{ ids.uid, ids.gid } else .{ null, null };

        var child = std.process.spawn(io, .{
            .argv = &.{ "/bin/sh", "-c", this.command },
            .uid = uid,
            .gid = gid,
        }) catch return RunError.CouldNotSpawn;

        const term = child.wait(io) catch return RunError.CouldNotWait;

        if (!term.success()) {
            std.log.err("Prepare command '{s}' {f}", .{ this.command, term });
            return RunError.PrepareCommandFailed;
        }
    }
};

const RunPlan = struct {
    prepare: ?PrepareCommand,
    profiled_program: Program,
    patch_addresses: []const usize,
    profiler: *Profiler,
};

fn executeRuns(io: std.Io, runs_count: u32, plan: RunPlan) void {
    var run: u32 = 0;
    while (run < runs_count and !interrupted.load(.monotonic)) : (run += 1) {
        std.log.info("Run {}/{}", .{ run + 1, runs_count });
        executeRun(io, plan);
    }
}

fn executeRun(io: std.Io, plan: RunPlan) void {
    if (plan.prepare) |prepare_command|
        prepare_command.run(io) catch |err|
            std.process.fatal("Could not run prepare command '{s}' ({s})", .{ prepare_command.command, @errorName(err) });

    var profiled_process = TracedProcess.spawn(plan.profiled_program, io) catch |err| switch (err) {
        TracedProcess.SpawnError.ChildNotTraceable => std.process.fatal("Could not ptrace the program; check /proc/sys/kernel/yama/ptrace_scope.", .{}),
        TracedProcess.SpawnError.ChildDied => if (interrupted.load(.monotonic))
            return
        else
            std.process.fatal("Could not start the program under the profiler ({s})", .{@errorName(err)}),
        else => std.process.fatal("Could not start the program under the profiler ({s})", .{@errorName(err)}),
    };

    plan.profiler.start(profiled_process.pid) catch |err| switch (err) {
        KernelControlDevice.ControlError.SessionAlreadyRunning => std.process.fatal("Another recording is already using {s}.", .{communications.control_device_path}),
        KernelControlDevice.ControlError.CouldNotAttachToProcess => std.process.fatal("The kernel could not attach to process {d}; check that perf events are available.", .{profiled_process.pid}),
        else => std.process.fatal("Could not start the profiler ({s})", .{@errorName(err)}),
    };

    for (plan.patch_addresses) |address| profiled_process.patchProgressPoint(address, plan.profiler.controlFd()) catch |err|
        std.process.fatal("Could not patch the program's progress points ({s})", .{@errorName(err)});

    profiled_process.start() catch |err|
        std.process.fatal("Could not resume the program ({s})", .{@errorName(err)});

    profiled_process.wait() catch |err|
        std.process.fatal("Could not wait on profiled process (pid: {}, err: {s})", .{ profiled_process.pid, @errorName(err) });

    plan.profiler.stop() catch |err|
        std.process.fatal("Could not stop the profiler ({s})", .{@errorName(err)});
}

test {
    _ = OutputFile;
}

test "the default vma name is the basename, extension and all" {
    const cases = [_]struct { path: [*:0]const u8, expected: []const u8 }{
        .{ .path = "a.out", .expected = "a.out" },
        .{ .path = "./a.out", .expected = "a.out" },
        .{ .path = "/usr/bin/toy", .expected = "toy" },
        .{ .path = "/usr/lib/libfoo.so.1", .expected = "libfoo.so.1" },
    };

    for (cases) |check|
        try std.testing.expectEqualStrings(check.expected, resolveVmaName("", check.path));
}

test "an explicit -l wins over the program path" {
    try std.testing.expectEqualStrings("libfoo.so.1", resolveVmaName("libfoo.so.1", "/usr/bin/toy"));
}
