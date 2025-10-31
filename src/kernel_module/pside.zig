const std = @import("std");
const kernel = @import("kernel.zig");

export const license linksection(".modinfo") = "license=MIT".*;

extern fn vprintk(fmt: [*:0]const u8) callconv(.c) void;

export fn init_module() linksection(".init.text") c_int {
    const a = kernel.allocator.alloc(i8, 2) catch return -1;
    a[0] = -1;
    a[1] = 0;
    var b: i8 = -1;
    if (a[1] != a[0]) {
        b = 0;
    }
    kernel.allocator.free(a);
    return b;
}
export fn cleanup_module() linksection(".exit.text") void {
    vprintk("Goodby from Zig!\n");
}
