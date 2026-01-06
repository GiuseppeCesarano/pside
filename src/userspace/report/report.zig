const std = @import("std");
const cli = @import("cli");

pub fn report(_: cli.Options, _: std.process.Init) void {
    std.log.debug("report", .{});
}
