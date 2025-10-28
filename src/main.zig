const std = @import("std");

pub fn main() void {
    var kernel_module = std.fs.cwd().openFile("pside.ko", .{}) catch @panic("cannot open module");
    defer kernel_module.close();

    const load_res = std.os.linux.syscall3(
        .finit_module,
        @intCast(kernel_module.handle),
        @intFromPtr(""),
        0,
    );
    std.debug.print("Run: {} errno {}\n", .{ load_res, std.posix.errno(load_res) });

    const remove_res = std.os.linux.syscall2(
        .delete_module,
        @intFromPtr("pside"),
        0,
    );
    std.debug.print("Remove: {} errno {}\n", .{ remove_res, std.posix.errno(remove_res) });
}
