const std = @import("std");
const communications = @import("communications");
const kernel = @import("bindings/kernel.zig");
const causal = @import("causal.zig");

const name = "pside";
const native_endian = @import("builtin").target.cpu.arch.endian();
const allocator = kernel.heap.allocator;
const linux = std.os.linux;

export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName(name).logFn,
};

var chardev: kernel.CharDevice = undefined;

export fn init_module() linksection(".init.text") c_int {
    chardev.create(name, ioctlHandler) catch return 1;
    std.log.debug("chardev created at: /dev/" ++ name, .{});
    causal.engine.init() catch return 1;

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    chardev.remove();
    causal.engine.deinit();
}

fn ioctlHandler(_: *anyopaque, command: c_uint, arg: c_ulong) callconv(.c) c_long {
    const in: *const communications.Data = @ptrFromInt(arg);
    var data: communications.Data = undefined;
    const copied = kernel.mem.copyBytesFromUser(std.mem.asBytes(&data), std.mem.asBytes(in));
    if (copied.len != @sizeOf(communications.Data)) return code(.FAULT);

    const cmd = @as(communications.Commands, @enumFromInt(command));

    switch (cmd) {
        .start_profiler_on_pid => causal.engine.profilePid(data.pid),
        else => return code(.INVAL),
    }

    return code(.SUCCESS);
}

fn code(return_code: linux.E) c_long {
    return -@as(c_long, @intCast(@intFromEnum(return_code)));
}
