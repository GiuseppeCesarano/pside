const std = @import("std");
const cli = @import("cli");

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

    var threaded_io_context = std.Io.Threaded.init(allocator);
    const io = threaded_io_context.io();
    defer threaded_io_context.deinit();

    var args = std.process.args();
    _ = args.skip(); // Skip program name

    cli.execute(args, &printHelp, &.{
        .{ .name = "record", .handler = &record },
        .{ .name = "report", .handler = &report },
    }, .{ allocator, io });
}

fn record(options: cli.Options, _: std.mem.Allocator, _: std.Io) void {
    std.log.debug("record", .{});
}

fn report(_: cli.Options, _: std.mem.Allocator, _: std.Io) void {
    std.log.debug("report", .{});
}

fn printHelp(_: cli.Options, _: std.mem.Allocator, _: std.Io) void {
    std.log.debug("printHelp", .{});
}
