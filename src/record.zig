const std = @import("std");
const cli = @import("cli");
const KernelModule = @import("KernelModule");

pub fn handler(_: cli.Options, allocator: std.mem.Allocator, io: std.Io) void {
    const module: KernelModule = KernelModule.loadFromDefaultModulePath(allocator, io, "pside") catch @panic("TODO: handle errors\n");
    defer module.unload(io) catch @panic("TODO: handle errors\n");
}
