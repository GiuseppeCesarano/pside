const std = @import("std");
const cli = @import("cli");
const KernelModule = @import("KernelModule");

pub fn handler(_: cli.Options, allocator: std.mem.Allocator, io: std.Io) void {
    const module = KernelModule.loadFromDefaultModulePath(allocator, io, "pside") catch |err| switch (err) {
        error.NotPrivilegedOrLoadingDisabled => std.process.fatal("Loading the kernel module requires elevated privileges.", .{}),
        error.ModuleAlreadyLoaded => std.process.fatal("The kernel module is already loaded.", .{}),
        error.SymbolResolutionTimeout => std.process.fatal("Timed out while resolving kernel symbols.", .{}),
        error.AddressFault => std.process.fatal("Encountered a kernel memory access fault during load.", .{}),
        error.OutOfMemory => std.process.fatal("The system is out of memory while loading the kernel module.", .{}),
        error.FileNotReadable => std.process.fatal("Cannot read the kernel module file.", .{}),
        else => std.process.fatal("Unexpected error while loading module {s}", .{@errorName(err)}),
    };

    defer module.unload(io) catch |err| switch (err) {
        error.NotLive => std.log.warn("The kernel module was already marked for removal.", .{}),
        error.NoEntity => std.log.warn("The kernel module was not loaded.", .{}),
    };
}
