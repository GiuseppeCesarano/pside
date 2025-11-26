const std = @import("std");
const cli = @import("cli");

pub fn report(_: cli.Options, _: std.mem.Allocator, _: std.Io) void {
    std.log.debug("report", .{});
}
