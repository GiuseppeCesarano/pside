const std = @import("std");
const kernel = @import("kernel.zig");

export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName("pside").logFn,
};

fn count(_: ?*kernel.probe.K, _: ?*kernel.probe.PtRegs) callconv(.c) c_int {
    _ = c.fetchAdd(1, .monotonic);
    return 0;
}

fn read(_: *anyopaque, buff: [*]u8, _: usize, offset: *i64) callconv(.c) isize {
    const s = "Hello from chardev!!\n";
    const uoffset: usize = @intCast(offset.*);

    const to_copy = s.len -| uoffset;
    const end = @min(uoffset + to_copy, s.len);
    const not_copied = kernel.mem.copyBytesToUser(buff, s[uoffset..end]);

    offset.* += @intCast(to_copy - not_copied);
    return @intCast(to_copy - not_copied);
}

var c: std.atomic.Value(u32) = .init(0);
var probe: kernel.probe.K = .init("__x64_sys_getpid", .{ .pre_handler = &count });
var chardev: kernel.Chardev = undefined;

export fn init_module() linksection(".init.text") c_int {
    const allocator = kernel.heap.allocator;

    const zig = allocator.alloc(u8, 3) catch return -1;
    defer allocator.free(zig);
    @memcpy(zig, "Zig");

    const start = kernel.time.now.us();
    kernel.time.delay.us(5);

    std.log.info("Hello from {s}, pid: {}, tid: {} waited: {}us\n", .{
        zig,
        kernel.current_task.pid(),
        kernel.current_task.tid(),
        kernel.time.now.us() - start,
    });

    std.log.info("Starting probe...\n", .{});
    _ = probe.register();

    std.log.info("Creating chardev...\n", .{});
    chardev.register("pside", &read, null);

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    probe.unregister();
    chardev.unregister();
    std.log.info("kprobe stopped, getpid called: {} times\n", .{c.load(.unordered)});
    std.log.info("chardev removed\n", .{});
}
