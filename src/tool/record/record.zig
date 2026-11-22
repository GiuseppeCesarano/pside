const std = @import("std");
const linux = std.os.linux;
const fatal = std.process.fatal;
const Dwarf = std.debug.Dwarf;

const cli = @import("cli");
const communications = @import("communications");
const LineMap = @import("LineMap");
const safety = @import("safety");
const UserIds = @import("UserIds");

const elf_section_parser = @import("elf_section_parser.zig");
const ParseError = elf_section_parser.ParseError;
const KernelControlDevice = @import("KernelControlDevice.zig");
const ControlError = KernelControlDevice.ControlError;
const OpenControlError = KernelControlDevice.OpenControlError;
const OutputFile = @import("OutputFile.zig");
const OpenError = OutputFile.OpenError;
const Program = @import("Program.zig");
const Symbolizer = @import("Symbolizer.zig");
const TracedProcess = @import("TracedProcess.zig");
const SpawnError = TracedProcess.SpawnError;

const Flags = struct {
    c: []const u8 = "",
    p: []const u8 = "",
    prepare: []const u8 = "",
    n: u32 = 1,
};

var interrupted: std.atomic.Value(bool) = .init(false);

pub fn record(options: cli.Options, init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const parsed_options = options.parse(Flags);
    cli.validateOptions(parsed_options.unknown_flags, "Unknown flag: ") catch std.process.exit(1);
    cli.validateOptions(parsed_options.parse_errors, "Could not parse: ") catch std.process.exit(1);
    const flags = parsed_options.flags;

    setSigintHandler();

    const profiled_program = Program.initFromParsedOptions(parsed_options, init.minimal.environ, allocator, io) catch |err| switch (err) {
        Program.InitError.ExtraPositionalArguments => fatal("Give the program either positionally or with -c, not both.", .{}),
        Program.InitError.UnspecifiedCommand => fatal("No program to profile.\n\tUsage: sudo pside record <program> [args…]", .{}),
        else => fatal("Could not resolve the program ({s})", .{@errorName(err)}),
    };
    defer profiled_program.deinit(allocator);
    const program_path = std.mem.span(profiled_program.path);

    const user_ids = UserIds.sudoCallerFromEnviron(init.minimal.environ) catch |err|
        fatal("Could not read the invoking user ({s})", .{@errorName(err)});

    var future_sites = io.async(Sites.init, .{ allocator, io, program_path });
    var future_patch_addresses = io.async(elf_section_parser.getPatchAddr, .{ profiled_program, flags.p, allocator, io });
    var future_program_hash = io.async(OutputFile.computeFileHash, .{ io, program_path });

    var sites = future_sites.await(io) catch |err| switch (err) {
        Dwarf.ScanError.MissingDebugInfo => fatal("'{s}' has no DWARF debug info; rebuild it with -g.", .{program_path}),
        Symbolizer.LineMapError.NoLineTable => fatal("'{s}' has debug info but no line table for its code; rebuild it with -g.", .{program_path}),
        else => fatal("Could not read the line table of '{s}' ({s})", .{ program_path, @errorName(err) }),
    };
    defer sites.deinit(allocator);

    const patch_addresses = future_patch_addresses.await(io) catch |err| switch (err) {
        ParseError.NoPsideSection => fatal("'{s}' has no pside progress points; add PSIDE_THROUGHPUT_POINT(\"name\") to the source and rebuild.", .{program_path}),
        ParseError.NoProgressPointsWithSuchName => fatal("No progress point named '{s}' in '{s}'.", .{ flags.p, program_path }),
        else => fatal("Could not read progress points from '{s}' ({s})", .{ program_path, @errorName(err) }),
    };
    defer allocator.free(patch_addresses);

    const program_hash = future_program_hash.await(io) catch |err|
        fatal("Could not read '{s}' to hash it ({s})", .{ program_path, @errorName(err) });

    const real_path = std.Io.Dir.cwd().realPathFileAlloc(io, program_path, allocator) catch |err|
        fatal("Could not resolve the real path of '{s}' ({s})", .{ program_path, @errorName(err) });
    defer allocator.free(real_path);
    const vma_name = std.fs.path.basename(real_path);
    if (!communications.AttachOptions.vmaNameFits(vma_name)) fatal("VMA name '{s}' is longer than {d} bytes.", .{ vma_name, std.math.maxInt(u8) });

    var output_file = OutputFile.open(allocator, io, program_path, program_hash, user_ids, sites.file_names) catch |err| switch (err) {
        OpenError.HashDontMatch => fatal("{s}.pside was recorded from a different build of the binary; delete it to start a fresh profile.", .{program_path}),
        OpenError.FileTableDontMatch => fatal("{s}.pside numbers the source files differently than this pside build does; delete it to start a fresh profile.", .{program_path}),
        OpenError.NotAPsideFile => fatal("{s}.pside is not a pside recording; delete it to start a fresh profile.", .{program_path}),
        else => fatal("Could not open {s}.pside ({s})", .{ program_path, @errorName(err) }),
    };
    defer output_file.close(io);

    const control_device, const module_ownership = openControlDevice(io);
    defer {
        control_device.close(io);
        if (module_ownership == .ours) unloadModule(io);
    }

    control_device.loadLineMap(sites.source()) catch |err| {
        switch (err) {
            ControlError.MalformedLineMap => std.log.err("The kernel rejected the line map built from '{s}'.", .{program_path}),
            ControlError.OutOfMemory => std.log.err("The kernel ran out of memory while loading the line map of '{s}'.", .{program_path}),
            else => std.log.err("Could not load the line map into the kernel ({s})", .{@errorName(err)}),
        }
        return err;
    };

    var profiler = Profiler.init(control_device, output_file.file.handle, vma_name) catch |err| {
        std.log.err("Could not use VMA name '{s}' ({s})", .{ vma_name, @errorName(err) });
        return err;
    };

    const prepare: ?PrepareCommand = if (flags.prepare.len != 0) .{ .command = flags.prepare, .user_ids = user_ids } else null;

    executeRuns(io, flags.n, .{
        .prepare = prepare,
        .profiled_program = profiled_program,
        .patch_addresses = patch_addresses,
        .profiler = &profiler,
        .output_file = &output_file,
        .vma_name = vma_name,
    });

    std.log.info("Done. View the report with: pside report {s}.pside", .{std.fs.path.basename(program_path)});
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
        if (err == OpenControlError.ModuleNotLoaded and linux.geteuid() == 0) return loadModuleAndOpen(io);

        switch (err) {
            OpenControlError.ModuleNotLoaded => fatal("The pside module is not loaded\n\trun: sudo pside driver load", .{}),
            OpenControlError.AccessDenied => fatal("Cannot open {s}: load the module as the same user with `sudo pside driver load`", .{communications.control_device_path}),
            else => fatal("Could not open {s} ({s})", .{ communications.control_device_path, @errorName(err) }),
        }
    };

    return .{ device, .preexisting };
}

fn loadModuleAndOpen(io: std.Io) struct { KernelControlDevice, ModuleOwnership } {
    driverCommand(io, .load) catch fatal("Could not load the kernel module", .{});

    const device = KernelControlDevice.open(io) catch |err| {
        driverCommand(io, .unload) catch {};
        fatal("Could not open {s} after loading the module ({s})", .{ communications.control_device_path, @errorName(err) });
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

    if (!term.eql(.success)) return DriverError.DriverCommandFailed;
}

const Sites = struct {
    line_map: LineMap,
    file_names: [][]u8,

    fn init(allocator: std.mem.Allocator, io: std.Io, binary_path: []const u8) !Sites {
        var symbolizer: Symbolizer = try .init(allocator, io, binary_path);
        defer symbolizer.deinit(allocator);

        var line_map = try symbolizer.lineMap(allocator);
        errdefer line_map.deinit(allocator);

        return .{ .line_map = line_map, .file_names = try symbolizer.allocFileNames(allocator) };
    }

    fn source(this: *const Sites) communications.LineMapSource {
        const slices = this.line_map.data.slice();
        return .{
            .starts = @intFromPtr(slices.items(.start).ptr),
            .sites = @intFromPtr(slices.items(.site).ptr),
            .len = slices.len,
        };
    }

    fn deinit(this: *Sites, allocator: std.mem.Allocator) void {
        for (this.file_names) |name| allocator.free(name);
        allocator.free(this.file_names);
        this.line_map.deinit(allocator);
        this.* = undefined;
    }
};

const Profiler = struct {
    device: KernelControlDevice,
    output_fd: linux.fd_t,
    attach_options: communications.AttachOptions,
    state: safety.State(Lifecycle),

    const Lifecycle = enum { idle, attached, profiling };
    pub const InitError = communications.AttachOptions.InitError;

    fn init(
        device: KernelControlDevice,
        output_fd: linux.fd_t,
        vma_name: []const u8,
    ) InitError!Profiler {
        return .{
            .device = device,
            .output_fd = output_fd,
            .attach_options = try .init(undefined, vma_name),
            .state = .init(.idle),
        };
    }

    fn controlFd(this: Profiler) linux.fd_t {
        return this.device.ctl.handle;
    }

    fn vmaName(this: *const Profiler) []const u8 {
        return this.attach_options.vma_name[0..this.attach_options.vma_name_len];
    }

    fn attach(this: *Profiler, pid: linux.pid_t) ControlError!void {
        this.state.assertEql(.idle);

        var attach_options = this.attach_options;
        attach_options.pid = pid;

        try this.device.attachProfilerToPid(attach_options);

        this.state.transition(.attached);
    }

    fn start(this: *Profiler) ControlError!void {
        this.state.assertEql(.attached);

        try this.device.startProfiler(.{ .output_fd = this.output_fd });

        this.state.transition(.profiling);
    }

    fn stop(this: *Profiler) ControlError!void {
        this.state.assertEql(.profiling);

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

        if (!term.eql(.success)) {
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
    output_file: *OutputFile,
    vma_name: []const u8,
};

fn executeRuns(io: std.Io, runs_count: u32, plan: RunPlan) void {
    for (1..runs_count + 1) |run| {
        if (interrupted.load(.monotonic)) break;

        std.log.info("Run {}/{}", .{ run, runs_count });
        executeRun(io, plan);
    }
}

fn executeRun(io: std.Io, plan: RunPlan) void {
    const incomplete_run = "the run stopped measuring early and its samples are incomplete";

    if (plan.prepare) |prepare_command| prepare_command.run(io) catch |err|
        fatal("Could not run prepare command '{s}' ({s})", .{ prepare_command.command, @errorName(err) });

    var profiled_process = TracedProcess.spawn(plan.profiled_program, io) catch |err| switch (err) {
        SpawnError.ChildDied => if (interrupted.load(.monotonic)) return else fatal("Could not start the program under the profiler ({s})", .{@errorName(err)}),
        SpawnError.ChildNotTraceable => fatal("Could not ptrace the program; check /proc/sys/kernel/yama/ptrace_scope.", .{}),
        else => fatal("Could not start the program under the profiler ({s})", .{@errorName(err)}),
    };
    const pid = profiled_process.pid;

    plan.profiler.attach(pid) catch |err| switch (err) {
        ControlError.SessionAlreadyRunning => fatal("Another recording is already using {s}.", .{communications.control_device_path}),
        ControlError.CouldNotAttachToProcess => fatal("The kernel could not attach to process {d}; check that perf events are available.", .{pid}),
        ControlError.NoMatchingVma => fatal(
            "No executable mapping of '{s}' when the program reached its entry point; pside matches the program's real file name as it appears in /proc/<pid>/maps.",
            .{plan.profiler.vmaName()},
        ),
        ControlError.MultiThreadedTarget => fatal("Process {d} already had multiple threads at its entry point; pside can only attach while the program is single-threaded.", .{pid}),
        ControlError.TaskNotFound => fatal("Process {d} no longer exists; it exited before the kernel could attach.", .{pid}),
        ControlError.CouldNotRegisterTracepoints => fatal("The kernel could not register the scheduler tracepoints pside needs to follow process {d}.", .{pid}),
        ControlError.OutOfMemory => fatal("The kernel ran out of memory while attaching to process {d}.", .{pid}),
        else => fatal("Could not attach the profiler ({s})", .{@errorName(err)}),
    };

    plan.output_file.declareVma(io, plan.vma_name) catch |err|
        fatal("Could not declare the profiled region in the output file ({s})", .{@errorName(err)});

    plan.profiler.start() catch |err|
        fatal("Could not start the profiler ({s})", .{@errorName(err)});

    for (plan.patch_addresses) |address| profiled_process.patchProgressPoint(address, plan.profiler.controlFd()) catch |err|
        fatal("Could not patch the program's progress points ({s})", .{@errorName(err)});

    profiled_process.start() catch |err|
        fatal("Could not resume the program ({s})", .{@errorName(err)});

    profiled_process.wait() catch |err|
        fatal("Could not wait on profiled process (pid: {}, err: {s})", .{ pid, @errorName(err) });

    plan.profiler.stop() catch |err| switch (err) {
        ControlError.OutputWriteFailed => fatal("The kernel could not write this run's records to the output file; " ++ incomplete_run ++ ".", .{}),
        ControlError.ThreadTableFull => fatal("The kernel ran out of room to track the program's threads; " ++ incomplete_run ++ ".", .{}),
        ControlError.CouldNotInjectDelay => fatal("The kernel could not inject a delay into one of the program's threads; " ++ incomplete_run ++ ".", .{}),
        ControlError.OutOfMemory => fatal("The kernel ran out of memory while profiling; " ++ incomplete_run ++ ".", .{}),
        else => fatal("Could not stop the profiler ({s})", .{@errorName(err)}),
    };
}

test {
    _ = OutputFile;
}
