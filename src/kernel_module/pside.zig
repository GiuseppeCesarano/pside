const std = @import("std");
const kernel = @import("kernel.zig");

export const license linksection(".modinfo") = "license=MIT".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName("pside").logFn,
};

export fn init_module() linksection(".init.text") c_int {
    std.log.warn("Hi kernel from {s}\n", .{"Zig"});
    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    std.log.err("Goodbye kernel\n", .{});
}
