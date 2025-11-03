const std = @import("std");
const kernel = @import("kernel.zig");

export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName("pside").logFn,
};

export fn init_module() linksection(".init.text") c_int {
    const zig = kernel.allocator.alloc(u8, 3) catch return -1;
    defer kernel.allocator.free(zig);
    @memcpy(zig, "Zig");

    const start = kernel.time.get.us();
    kernel.time.delay.us(5);

    std.log.warn("Hello from {s}, pid:{}, tid:{} waited: {}us\n", .{
        zig,
        kernel.current_task.pid(),
        kernel.current_task.tid(),
        kernel.time.get.us() - start,
    });

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    std.log.err("Goodbye kernel\n", .{});
}
