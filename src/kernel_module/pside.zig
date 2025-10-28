const std = @import("std");

extern fn vprintk(fmt: [*:0]const u8) callconv(.c) void;

export fn init() c_int {
    vprintk("Hello Kernel from Zig!\n");
    return 0;
}

export fn deinit() void {
    vprintk("Goodby from Zig!\n");
}
