const std = @import("std");
const kernel = @import("kernel.zig");

export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName("pside").logFn,
};

fn count(_: ?*kernel.probe.K, _: ?*kernel.probe.PtRegs) callconv(.c) c_int {
    _ = c.fetchAdd(1, .monotonic);
    return 0;
}

var c: std.atomic.Value(u32) = .init(0);
var probe: kernel.probe.K = .init("__x64_sys_getpid", .{ .pre_handler = &count });

export fn init_module() linksection(".init.text") c_int {
    const zig = kernel.allocator.alloc(u8, 3) catch return -1;
    defer kernel.allocator.free(zig);
    @memcpy(zig, "Zig");

    const start = kernel.time.now.us();
    kernel.time.delay.us(5);

    std.log.info("Hello from {s}, pid: {}, tid: {} waited: {}us\n", .{
        zig,
        kernel.current_task.pid(),
        kernel.current_task.tid(),
        kernel.time.now.us() - start,
    });

    std.log.info("Starting probe...\n", .{});
    _ = probe.register();

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    probe.unregister();
    std.log.info("Stopping probe, getpid called: {} times\n", .{c.load(.unordered)});
}
