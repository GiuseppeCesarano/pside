const std = @import("std");
const communications = @import("communications");
const kernel = @import("bindings/kernel.zig");
const causal_logic = @import("causal_logic.zig");

const name = "pside";
const native_endian = @import("builtin").target.cpu.arch.endian();
const allocator = kernel.heap.allocator;

export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName(name).logFn,
};

var chardev: kernel.CharDevice = undefined;
var uprobe: kernel.probe.U = undefined;

fn cb(_: *kernel.probe.U.Callbacks, _: *kernel.probe.PtRegs, _: *u64) callconv(.c) c_int {
    causal_logic.increment();
    return 0;
}

export fn init_module() linksection(".init.text") c_int {
    chardev.create(name, null, &writeCallBack);
    uprobe = kernel.probe.U.init("/home/giuseppe/Documents/pside/a.out", .{ .pre_handler = &cb }, 0x1280) catch return -1;
    uprobe.register() catch return -1;
    std.log.debug("chardev created at: /dev/" ++ name, .{});
    causal_logic.init() catch return 1;

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    uprobe.unregister();
    uprobe.deinit();
    chardev.remove();
    causal_logic.deinit();
}

fn writeCallBack(_: *anyopaque, userspace_buffer: [*]const u8, userspace_buffer_len: usize, offset: *i64) callconv(.c) isize {
    defer offset.* +|= @intCast(userspace_buffer_len); // Always read everything from the user.

    var we_allocated = false;
    var kernelspace_buffer: [std.atomic.cache_line * 2]u8 = undefined;
    var kernelspace_slice: []u8 = &kernelspace_buffer;

    if (kernelspace_buffer.len < userspace_buffer_len) {
        kernelspace_slice = allocator.alloc(u8, userspace_buffer_len) catch {
            std.log.warn("Could not allocate enough data to read userspace message. Ignoring written data...", .{});
            return @intCast(userspace_buffer_len);
        };
        we_allocated = true;
    }
    defer if (we_allocated) allocator.free(kernelspace_slice);

    var reader: std.Io.Reader = .fixed(kernel.mem.copyBytesFromUser(kernelspace_slice, userspace_buffer[0..userspace_buffer_len]));

    const recived_command = reader.takeEnum(communications.Commands, native_endian) catch |err| {
        std.log.warn("Reading command went wrong: {s}", .{@errorName(err)});
        return @intCast(userspace_buffer_len);
    };

    std.log.debug("recived: {s}\tbytes: {}", .{ @tagName(recived_command), userspace_buffer_len });

    switch (recived_command) {
        .set_pid_for_filter => setPidForFilter(&reader) catch |err| std.log.warn("Reading pid went wrong: {s}", .{@errorName(err)}),
        else => std.log.err("unsupported command: {s}.", .{@tagName(recived_command)}),
    }

    return @intCast(userspace_buffer_len);
}

fn setPidForFilter(reader: *std.Io.Reader) !void {
    const s = struct {
        var l: usize = 0;
    };
    const pid = try reader.takeInt(std.os.linux.pid_t, native_endian);
    causal_logic.wait_lenght.store(s.l, .monotonic);
    causal_logic.start(pid);
    s.l += 50;
}
