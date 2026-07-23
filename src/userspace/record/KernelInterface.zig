const std = @import("std");
const linux = std.os.linux;

const communications = @import("communications");

pub const name = "pside";
pub const chardev_ctl_path: [:0]const u8 = "/dev/" ++ name;

pub const FInitModuleError = error{
    SignatureMisformatted,
    SymbolResolutionTimeout,
    AddressFault,
    SignatureInvalidOrNoKey,
    OutOfMemory,
    NotPrivilegedOrLoadingDisabled,
    ModuleAlreadyLoaded,
    InvalidParamsOrInconsistentELF,
    InvalidELFOrWrongArchitecture,
    FileNotReadable,
    FileTooLarge,
    CompressedModuleNotSupported,
    FileOpenedReadWrite,
    Unknown,
};

pub const DeleteModuleError = error{
    FdOpen,
    NotLive,
    NoEntity,
    Unknown,
};

ctl: std.Io.File,

pub fn driverLoad(owner: [2]u32, allocator: std.mem.Allocator, io: std.Io) !void {
    const path = try resolveModulePath(allocator, io);
    defer allocator.free(path);

    const module = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer module.close(io);

    fInitModule(module.handle) catch |err| {
        switch (err) {
            FInitModuleError.ModuleAlreadyLoaded => std.log.err("The pside module is already loaded\n\trun: sudo pside driver unload", .{}),
            FInitModuleError.NotPrivilegedOrLoadingDisabled => std.log.err("Loading the kernel module requires root, run with sudo", .{}),
            else => std.log.err("Loading kernel module returned: {s}", .{@errorName(err)}),
        }

        return err;
    };
    errdefer deleteModule() catch |err| std.log.err("Could not unload kernel module: {s}", .{@errorName(err)});

    try handDeviceToOwner(chardev_ctl_path, owner, io);
}

fn handDeviceToOwner(path: [:0]const u8, owner: [2]u32, io: std.Io) !void {
    const dev = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_write });
    defer dev.close(io);
    try dev.setOwner(io, owner[0], owner[1]);
    try dev.setPermissions(io, .fromMode(0o600));
}

pub fn openControlDevice(io: std.Io) !@This() {
    const ctl = try std.Io.Dir.openFileAbsolute(io, chardev_ctl_path, .{ .mode = .read_write });

    // The traced child inherits this fd across fork+exec and mmaps it to reach
    // its per-session progress page, so it must survive exec (clear CLOEXEC).
    if (linux.errno(linux.fcntl(ctl.handle, linux.F.SETFD, 0)) != .SUCCESS) {
        ctl.close(io);
        return error.CouldNotClearCloexec;
    }

    return .{ .ctl = ctl };
}

pub fn close(this: @This(), io: std.Io) void {
    this.ctl.close(io);
}

fn resolveModulePath(allocator: std.mem.Allocator, io: std.Io) ![]const u8 {
    const bin_path = try std.process.executableDirPathAlloc(io, allocator);
    defer allocator.free(bin_path);

    const base_path = std.fs.path.dirname(bin_path) orelse "";
    var uts: std.os.linux.utsname = undefined;
    _ = std.os.linux.uname(&uts);
    const release = uts.release;
    const release_end = std.mem.findScalar(u8, &release, 0) orelse release.len;

    return try std.mem.concat(allocator, u8, &.{ base_path, "/lib/modules/", release[0..release_end], "/extra/" ++ name ++ ".ko" });
}

fn fInitModule(handle: linux.fd_t) !void {
    const load_res = linux.syscall3(
        .finit_module,
        @intCast(handle),
        @intFromPtr(""),
        0,
    );

    return switch (linux.errno(load_res)) {
        .SUCCESS => {},
        .BADMSG => FInitModuleError.SignatureMisformatted,
        .BUSY => FInitModuleError.SymbolResolutionTimeout,
        .FAULT => FInitModuleError.AddressFault,
        .NOKEY => FInitModuleError.SignatureInvalidOrNoKey,
        .NOMEM => FInitModuleError.OutOfMemory,
        .PERM => FInitModuleError.NotPrivilegedOrLoadingDisabled,
        .EXIST => FInitModuleError.ModuleAlreadyLoaded,
        .INVAL => FInitModuleError.InvalidParamsOrInconsistentELF,
        .NOEXEC => FInitModuleError.InvalidELFOrWrongArchitecture,
        .BADF => FInitModuleError.FileNotReadable,
        .FBIG => FInitModuleError.FileTooLarge,
        .OPNOTSUPP => FInitModuleError.CompressedModuleNotSupported,
        .TXTBSY => FInitModuleError.FileOpenedReadWrite,
        else => FInitModuleError.Unknown,
    };
}

fn deleteModule() DeleteModuleError!void {
    const rc = linux.syscall2(
        .delete_module,
        @intFromPtr(name.ptr),
        0,
    );

    return switch (linux.errno(rc)) {
        .SUCCESS => {},

        .AGAIN => DeleteModuleError.FdOpen,
        .BUSY => DeleteModuleError.NotLive,
        .NOENT => DeleteModuleError.NoEntity,

        // delete_module could also return PERM, FAULT
        // but each of those errors shouldn't be appliacable in our
        // case
        else => DeleteModuleError.Unknown,
    };
}

pub fn driverUnload(io: std.Io) !bool {
    // If a record process was killed but its fds aren't closed yet this
    // returns FdOpen; in that case we just wait for the os to clean up the
    // child fds/mmaps.
    for (0..50) |_| {
        deleteModule() catch |err| {
            switch (err) {
                DeleteModuleError.NoEntity => return false,
                DeleteModuleError.FdOpen => {
                    try io.sleep(.fromMilliseconds(10), .real);
                    continue;
                },
                else => return err,
            }
        };
        return true;
    }
    return DeleteModuleError.FdOpen;
}

pub fn startProfilerOnPid(this: *@This(), start: communications.StartOptions) !void {
    const data: communications.Data = .{ .start = start };
    const rc = linux.ioctl(
        this.ctl.handle,
        @intFromEnum(communications.Commands.start_profiler),
        @intFromPtr(&data),
    );

    const e = linux.errno(rc);
    switch (e) {
        .SUCCESS => {},
        else => {
            std.log.err("Sending data to chardev returned: {s}", .{@tagName(e)});
            return error.ChardevWrite;
        },
    }
}

pub fn stop(this: *@This()) !void {
    const data: communications.Data = .{ .empty = {} };

    const rc = linux.ioctl(
        this.ctl.handle,
        @intFromEnum(communications.Commands.stop_profiler),
        @intFromPtr(&data),
    );

    const e = linux.errno(rc);
    switch (e) {
        .SUCCESS => {},
        else => {
            std.log.err("Stopping profiler returned: {s}", .{@tagName(e)});
            return error.ChardevWrite;
        },
    }
}
