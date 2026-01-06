const std = @import("std");
const cli = @import("cli");
const record = @import("record").record;
const report = @import("report").report;

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.skip();

    try cli.execute(args, printHelp, .{
        record,
        report,
    }, .{init});
}

fn printHelp(_: cli.Options, _: std.process.Init) void {
    std.log.debug("printHelp", .{});
}
