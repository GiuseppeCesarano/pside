const std = @import("std");
const cli = @import("cli");
const record = @import("record").record;
const report = @import("report").report;

pub fn main() !void {
    var debug_allocator_contex: std.heap.DebugAllocator(.{}) = .init;

    const allocator, const is_debug = gpa: {
        break :gpa switch (@import("builtin").mode) {
            .Debug, .ReleaseSafe => .{ debug_allocator_contex.allocator(), true },
            .ReleaseFast, .ReleaseSmall => .{ std.heap.smp_allocator, false },
        };
    };

    defer if (is_debug) {
        _ = debug_allocator_contex.deinit();
    };

    var threaded_io_context = std.Io.Threaded.init(allocator, .{});
    const io = threaded_io_context.io();
    defer threaded_io_context.deinit();

    var args = std.process.args();
    _ = args.skip(); // Skip program name

    try cli.execute(args, printHelp, .{
        record,
        report,
    }, .{ allocator, io });
}

fn printHelp(_: cli.Options, _: std.mem.Allocator, _: std.Io) void {
    std.log.debug("printHelp", .{});
}
