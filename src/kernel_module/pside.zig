const std = @import("std");

export const __UNIQUE_ID_license linksection(".modinfo") = [_]u8{ 'l', 'i', 'c', 'e', 'n', 's', 'e', '=', 'M', 'I', 'T', 0 };

extern fn vprintk(fmt: [*:0]const u8) callconv(.c) void;

export fn init_module() linksection(".init.text") c_int {
    vprintk("Hello Kernel from Zig!\n");
    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    vprintk("Goodby from Zig!\n");
}
