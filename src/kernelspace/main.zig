const std = @import("std");
const communications = @import("communications");
const kernel = @import("kernel");
const CausalInfereceEngine = @import("causal/InferenceEngine.zig");

const name = "pside";

export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName(name).logFn,
};

var chardev: kernel.CharDevice = undefined;
var engine: CausalInfereceEngine = undefined;

export fn init_module() linksection(".init.text") c_int {
    chardev.create(name, ioctlHandler) catch return 1;
    std.log.debug("chardev created at: /dev/" ++ name, .{});

    const throughput_ptr: *std.atomic.Value(usize) = @ptrCast(@alignCast(chardev.shared_buffer()));
    throughput_ptr.* = .init(0);
    engine = CausalInfereceEngine.init(throughput_ptr) catch return 1;

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    engine.deinit();
    chardev.remove();
}

fn ioctlHandler(_: *anyopaque, command: c_uint, arg: c_ulong) callconv(.c) c_long {
    const in: *const communications.Data = @ptrFromInt(arg);
    var data: communications.Data = undefined;
    const copied = kernel.mem.copyBytesFromUser(std.mem.asBytes(&data), std.mem.asBytes(in));
    if (copied.len != @sizeOf(communications.Data)) return code(.FAULT);

    switch (@as(communications.Commands, @enumFromInt(command))) {
        .start_profiler => engine.profilePid(data.pid) catch return code(.IO), //TODO: change to a error list
        else => return code(.INVAL),
    }

    return code(.SUCCESS);
}

fn code(return_code: std.os.linux.E) c_long {
    return -@as(c_long, @intCast(@intFromEnum(return_code)));
}
