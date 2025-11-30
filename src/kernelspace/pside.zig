const std = @import("std");
const kernel = @import("kernel.zig");
const command = @import("command");

const name = "pside";
export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName(name).logFn,
};

const allocator = kernel.heap.allocator;

var call_count: std.atomic.Value(u32) = .init(0);
var filter_pid = std.atomic.Value(std.os.linux.pid_t).init(0);
var uprobes: std.ArrayList(kernel.probe.U) = undefined;
var kprobes: std.ArrayList(kernel.probe.K) = undefined;
var chardev: kernel.CharDevice = undefined;

export fn init_module() linksection(".init.text") c_int {
    chardev.create(name, null, &writeCallBack);
    std.log.debug("chardev created at: /dev/" ++ name, .{});

    uprobes = std.ArrayList(kernel.probe.U).initCapacity(allocator, 10) catch return 1;
    kprobes = std.ArrayList(kernel.probe.K).initCapacity(allocator, 10) catch return 1;

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    for (uprobes.items) |*probe| {
        probe.unregister();
        probe.deinit();
    }
    uprobes.deinit(allocator);

    for (kprobes.items) |*probe| {
        probe.unregister();
    }
    kprobes.deinit(allocator);

    chardev.remove();
    std.log.debug("pthread_mutex_lock called: {} times", .{call_count.load(.unordered)});
    std.log.debug("chardev removed", .{});
}

fn writeCallBack(_: *anyopaque, buff: [*]const u8, size: usize, offset: *i64) callconv(.c) isize {
    defer offset.* +|= @intCast(size); // Always read everything from the user.
    _ = buff;

    //     const input = buff[0..size];
    //     const data_size = @sizeOf(command.Data);

    //     if (size < data_size) {
    //         std.log.warn("Sent data doesn't match command size, ignoring...", .{});
    //         return @intCast(size);
    //     }

    //     // TODO: remove unreachable
    //     const recived_command = kernel.mem.userBytesToValue(command.Data, input) catch unreachable;
    //     var path_buff: [100]u8 = @splat(0); // TODO: maybe handle with allocator
    //     const path = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(kernel.mem.copyBytesFromUser(&path_buff, input[data_size..]).ptr)), 0);

    //     switch (recived_command) {
    //         .set_pid_for_filter => filter_pid.store(recived_command.set_pid_for_filter, .unordered),

    //         .load_benchmark_probe => loadBenchmarkProbe(path, recived_command.load_benchmark_probe),

    //         // .load_mutex_probe => loadMutexProbe(kernel.mem.copyBytesFromUser(&path, input[data_size..]), recived_command.load_benchmark_probe),
    //         // .load_function_probe => loadFunctionProbe(kernel.mem.copyBytesFromUser(&path, input[data_size..]), recived_command.load_benchmark_probe),

    //         else => std.log.err("unsupported command: {any}.", .{recived_command}),
    //     }

    return @intCast(size);
}

fn loadBenchmarkProbe(path: [:0]const u8, offset: usize) void {
    uprobes.append(allocator, .init(path, .{ .filter = &doesPidMatch, .pre_handler = &count }, offset)) catch {};
}

fn loadMutexProbe(path: [:0]const u8, offset: usize) void {
    uprobes.append(allocator, .init(path, .{ .filter = &doesPidMatch, .pre_handler = &count }, offset)) catch {};
}

fn loadFunctionProbe(path: [:0]const u8, offset: usize) void {
    uprobes.append(allocator, .init(path, .{ .filter = &doesPidMatch, .pre_handler = &count }, offset)) catch {};
}

fn doesPidMatch(_: ?*kernel.probe.U, _: *anyopaque) bool {
    return kernel.current_task.pid() == filter_pid.load(.unordered);
}

fn count(_: ?*kernel.probe.U, _: ?*kernel.probe.PtRegs, _: *u64) callconv(.c) c_int {
    _ = call_count.fetchAdd(1, .monotonic);
    return 0;
}
