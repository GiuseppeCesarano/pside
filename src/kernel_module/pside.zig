const std = @import("std");
const kernel = @import("kernel.zig");

export const license linksection(".modinfo") = "license=MIT".*;
extern fn value() callconv(.c) c_int;

export fn init_module() linksection(".init.text") c_int {
    kernel.print("Hi kernel from {s}\n", .{"Zig"});
    return 0;
}
export fn cleanup_module() linksection(".exit.text") void {
    kernel.print("Goodbye kernel\n", .{});
}
