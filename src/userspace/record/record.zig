const std = @import("std");
const cli = @import("cli");
const PsideKernelModule = @import("PsideKernelModule.zig");
const UserProgram = @import("UserProgram.zig");
const Tracee = @import("Tracee.zig");

pub fn record(options: cli.Options, allocator: std.mem.Allocator, io: std.Io) !void {
    const parsed_options = options.parse(struct {
        c: []const u8 = "",
    });

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    var future_module = io.async(PsideKernelModule.loadFromDefaultPath, .{ allocator, io });
    defer if (future_module.cancel(io)) |module| module.unload(allocator, io) catch {
        std.log.warn("Could not remove the kernel module, please try manually with:\n\n\tsudo rmmod pside\n", .{});
    } else |_| {};

    comptime if (@import("builtin").output_mode != .Exe)
        @compileError("pside record needs environ which is setted up in zig exe start up code.");

    const user_program: UserProgram = try .initFromParsedOptions(parsed_options, @ptrCast(std.os.environ.ptr), allocator, io);
    defer user_program.deinit(allocator);

    const tracee: Tracee = try .spawn(user_program, io);

    var module = try future_module.await(io);
    try module.startProfilerOnPid(tracee.pid);

    _ = try tracee.syscall(.getpid, .{});

    try tracee.start();
    _ = tracee.wait();
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
