const std = @import("std");

export const license linksection(".modinfo") = "license=MIT".*;

extern fn vprintk(fmt: [*:0]const u8) callconv(.c) void;

export fn init_module() linksection(".init.text") c_int {
    vprintk("Hello Kernel from Zig!\n");
    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    vprintk("Goodby from Zig!\n");
}
