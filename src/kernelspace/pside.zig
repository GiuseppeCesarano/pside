const std = @import("std");
const kernel = @import("kernel.zig");

export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName("pside").logFn,
};

var c: std.atomic.Value(u32) = .init(0);
var probe: kernel.probe.U = undefined;
var chardev: kernel.CharDevice = undefined;
var pid = std.atomic.Value(std.os.linux.pid_t).init(0);

fn filter(_: ?*kernel.probe.U, _: *anyopaque) bool {
    return kernel.current_task.pid() == pid.load(.unordered);
}

fn count(_: ?*kernel.probe.U, _: ?*kernel.probe.PtRegs, _: *u64) callconv(.c) c_int {
    if (kernel.current_task.pid() == pid.load(.unordered))
        _ = c.fetchAdd(1, .monotonic);
    return 0;
}

fn write(_: *anyopaque, buff: [*]const u8, size: usize, offset: *i64) callconv(.c) isize {
    if (kernel.mem.userBytesToValue(std.os.linux.pid_t, buff[0..size])) |readed_pid| {
        pid.store(readed_pid, .unordered);
    } else |_| {
        std.log.warn("Sent data doesn't match command size, ignoring...", .{});
    }

    offset.* += @intCast(size);
    return @intCast(size);
}

export fn init_module() linksection(".init.text") c_int {
    // TODO: the offset is for pthraed_mutex_lock,
    // ofc this will need to be passed by the userspace util.
    probe = .init("/usr/lib/libc.so.6", .{ .pre_handler = &count, .filter = null }, 0x99f20);
    probe.register() catch return -1;

    std.log.info("Creating chardev...", .{});
    chardev.create("pside", null, &write);

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    probe.unregister();
    chardev.remove();
    std.log.info("probe stopped\n pthread_mutex_lock called: {} times", .{c.load(.unordered)});
    std.log.info("chardev removed", .{});
}
