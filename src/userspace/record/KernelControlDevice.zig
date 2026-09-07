const std = @import("std");
const linux = std.os.linux;

const communications = @import("communications");

pub const path: [:0]const u8 = "/dev/" ++ communications.name;

ctl: std.Io.File,

pub const ControlError = error{
    SessionAlreadyRunning,
    CouldNotAttachToProcess,
    UnknownCommand,
    CommandNotReadable,
    OutOfMemory,
    Unexpected,
};

fn controlError(e: linux.E) ControlError {
    return switch (e) {
        .BUSY => ControlError.SessionAlreadyRunning,
        .IO => ControlError.CouldNotAttachToProcess,
        .INVAL => ControlError.UnknownCommand,
        .FAULT => ControlError.CommandNotReadable,
        .NOMEM => ControlError.OutOfMemory,
        else => ControlError.Unexpected,
    };
}

pub const OpenControlError = error{
    ModuleNotLoaded,
    AccessDenied,
    CouldNotClearCloexec,
    Unexpected,
};

pub fn open(io: std.Io) OpenControlError!@This() {
    const ctl = std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_write }) catch |err| return switch (err) {
        error.FileNotFound => OpenControlError.ModuleNotLoaded,
        error.AccessDenied => OpenControlError.AccessDenied,
        else => OpenControlError.Unexpected,
    };

    // The traced child inherits this fd across fork+exec and mmaps it to reach
    // its per-session progress page, so it must survive exec (clear CLOEXEC).
    if (linux.errno(linux.fcntl(ctl.handle, linux.F.SETFD, 0)) != .SUCCESS) {
        ctl.close(io);
        return OpenControlError.CouldNotClearCloexec;
    }

    return .{ .ctl = ctl };
}

pub fn close(this: @This(), io: std.Io) void {
    this.ctl.close(io);
}

pub fn startProfilerOnPid(this: @This(), start: communications.StartOptions) ControlError!void {
    const data: communications.Data = .{ .start = start };
    const rc = linux.ioctl(
        this.ctl.handle,
        @backingInt(communications.Commands.start_profiler),
        @intFromPtr(&data),
    );

    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |e| controlError(e),
    };
}

pub fn stop(this: @This()) ControlError!void {
    const data: communications.Data = .{ .empty = {} };

    const rc = linux.ioctl(
        this.ctl.handle,
        @backingInt(communications.Commands.stop_profiler),
        @intFromPtr(&data),
    );

    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |e| controlError(e),
    };
}
