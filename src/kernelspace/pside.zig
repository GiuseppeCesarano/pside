const std = @import("std");
const kernel = @import("kernel.zig");
const command = @import("command");
const native_endian = @import("builtin").target.cpu.arch.endian();
const allocator = kernel.heap.allocator;

const name = "pside";
export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.LogWithName(name).logFn,
};

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
    std.log.debug("chardev removed", .{});

    std.log.info("pthread_mutex_lock called: {} times", .{call_count.load(.unordered)});
}

fn writeCallBack(_: *anyopaque, userspace_buffer: [*]const u8, userspace_buffer_len: usize, offset: *i64) callconv(.c) isize {
    defer offset.* +|= @intCast(userspace_buffer_len); // Always read everything from the user.

    var we_allocated = false;
    var kernelspace_buffer: [std.atomic.cache_line * 2]u8 = undefined;
    var kernelspace_slice: []u8 = &kernelspace_buffer;

    std.log.debug("Userspace sent {} bytes", .{userspace_buffer_len});

    if (kernelspace_buffer.len < userspace_buffer_len) {
        kernelspace_slice = allocator.alloc(u8, userspace_buffer_len) catch {
            std.log.warn("Could not allocate enough data to read userspace message. Ignoring written data...", .{});
            return @intCast(userspace_buffer_len);
        };
        we_allocated = true;
    }
    defer if (we_allocated) allocator.free(kernelspace_slice);

    var reader: std.Io.Reader = .fixed(kernel.mem.copyBytesFromUser(kernelspace_slice, userspace_buffer[0..userspace_buffer_len]));

    const recived_command = reader.takeEnum(command.Tag, native_endian) catch |err| {
        std.log.warn("Reading pid went wrong: {s}", .{@errorName(err)});
        return @intCast(userspace_buffer_len);
    };

    switch (recived_command) {
        .set_pid_for_filter => {
            const pid = reader.takeInt(std.os.linux.pid_t, native_endian) catch |err| {
                std.log.warn("Reading pid went wrong: {s}", .{@errorName(err)});
            };
            filter_pid.store(pid, .unordered);
        },

        .load_benchmark_probe => loadBenchmarkProbe(&reader) catch |err| std.log.warn("Loading benchmark probe went wrong: {s} ", .{@errorName(err)}),

        else => std.log.err("unsupported command: {s}.", .{@tagName(recived_command)}),
    }

    return @intCast(userspace_buffer_len);
}

fn loadBenchmarkProbe(reader: *std.Io.Reader) !void {
    const probe_offset = try reader.takeInt(usize, native_endian);
    const probe_path: [:0]const u8 = try reader.takeSentinel(0);

    const new = try uprobes.addOne(allocator);
    new.* = try .init(probe_path, .{ .filter = &doesPidMatch, .pre_handler = &count }, probe_offset);
    try new.register();
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
