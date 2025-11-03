const std = @import("std");
const kernel = @import("kernel.zig");

export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName("pside").logFn,
};

export fn init_module() linksection(".init.text") c_int {
    const start = kernel.time.get.us();
    kernel.time.delay.us(5);
    std.log.warn("Hello from {s}, we waited: {}us\n", .{ "Zig", kernel.time.get.us() - start - 1 });
    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    std.log.err("Goodbye kernel\n", .{});
}
