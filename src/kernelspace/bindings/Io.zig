const std = @import("std");

const kernel = @import("kernel.zig");

pub const io: std.Io = .{ .userdata = null, .vtable = &vtable };

const vtable: std.Io.VTable = vtable: {
    var v = std.Io.failing.vtable.*;
    v.swapCancelProtection = swapCancelProtection;
    v.lockStderr = lockStderr;
    v.tryLockStderr = tryLockStderr;
    v.unlockStderr = unlockStderr;
    v.operate = operate;
    v.futexWaitUncancelable = futexWaitUncancelable;
    v.futexWake = futexWake;
    break :vtable v;
};

fn swapCancelProtection(_: ?*anyopaque, _: std.Io.CancelProtection) std.Io.CancelProtection {
    return .blocked;
}

const spins_before_backoff = 8;
const backoff_sleep_us = 10;

fn futexWaitUncancelable(_: ?*anyopaque, ptr: *const u32, expected: u32) void {
    const word: *const std.atomic.Value(u32) = @ptrCast(ptr);

    var spins: u8 = 0;
    while (word.load(.monotonic) == expected) : (spins += 1) {
        if (spins != spins_before_backoff) {
            std.atomic.spinLoopHint();
            continue;
        }

        spins = 0;
        if (kernel.execution.canSleep())
            kernel.time.sleep.us(backoff_sleep_us)
        else
            std.atomic.spinLoopHint();
    }
}

fn futexWake(_: ?*anyopaque, _: *const u32, _: u32) void {}

const stderr_file: std.Io.File = .{ .handle = 2, .flags = .{ .nonblocking = false } };

var stderr_writer: std.Io.File.Writer = .initStreaming(stderr_file, io, &.{});
var stderr_buffer: [kernel.PrintkWriter.line_capacity]u8 = undefined;
var stderr_printk: kernel.PrintkWriter = .init(.err, &stderr_buffer);
var stderr_owner: std.atomic.Value(?*kernel.Task) = .init(null);
var stderr_depth: u32 = 0;

fn lockStderr(_: ?*anyopaque, terminal_mode: ?std.Io.Terminal.Mode) std.Io.Cancelable!std.Io.LockedStderr {
    kernel.preempt.disable();

    const task = kernel.Task.current();
    if (stderr_owner.load(.monotonic) != task) {
        while (stderr_owner.load(.monotonic) != null or
            stderr_owner.cmpxchgWeak(null, task, .acquire, .monotonic) != null)
            std.atomic.spinLoopHint();
    }

    return lockedStderr(terminal_mode);
}

fn tryLockStderr(_: ?*anyopaque, terminal_mode: ?std.Io.Terminal.Mode) std.Io.Cancelable!?std.Io.LockedStderr {
    kernel.preempt.disable();

    const task = kernel.Task.current();
    if (stderr_owner.load(.monotonic) != task and
        stderr_owner.cmpxchgStrong(null, task, .acquire, .monotonic) != null)
    {
        kernel.preempt.enable();
        return null;
    }

    return lockedStderr(terminal_mode);
}

fn lockedStderr(terminal_mode: ?std.Io.Terminal.Mode) std.Io.LockedStderr {
    stderr_depth += 1;

    return .{
        .file_writer = &stderr_writer,
        .terminal_mode = terminal_mode orelse .no_color,
    };
}

fn unlockStderr(_: ?*anyopaque) void {
    stderr_writer.interface.flush() catch {};
    stderr_writer.err = null;
    stderr_writer.interface.end = 0;
    stderr_writer.interface.buffer = &.{};

    stderr_depth -= 1;
    if (stderr_depth == 0) {
        stderr_printk.interface.flush() catch {};
        stderr_owner.store(null, .release);
    }

    kernel.preempt.enable();
}

fn operate(userdata: ?*anyopaque, operation: std.Io.Operation) std.Io.Cancelable!std.Io.Operation.Result {
    switch (operation) {
        .file_write_streaming => |w| if (w.file.handle == stderr_file.handle) {
            const printk = &stderr_printk.interface;
            printk.writeAll(w.header) catch {};
            for (w.data[0 .. w.data.len - 1]) |bytes| printk.writeAll(bytes) catch {};
            printk.splatBytesAll(w.data[w.data.len - 1], w.splat) catch {};

            return .{ .file_write_streaming = w.header.len + std.Io.Writer.countSplat(w.data, w.splat) };
        },
        else => {},
    }

    return std.Io.failing.vtable.operate(userdata, operation);
}
