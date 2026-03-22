const std = @import("std");
const linux = std.os.linux;

const communications = @import("communications");

const native_endianess = @import("builtin").target.cpu.arch.endian();
pub const name = "pside";
pub const chardev_ctl_path: [:0]const u8 = "/dev/" ++ name;
pub const chardev_progress_path: [:0]const u8 = chardev_ctl_path ++ "_progress";

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

module: std.Io.File,
ctl: std.Io.File,

pub fn loadModuleFromDefaultPath(chardev_owner: ?[2]u32, allocator: std.mem.Allocator, io: std.Io) !@This() {
    const path = try resolveModulePath(allocator, io);
    defer allocator.free(path);

    var rt: @This() = .{
        .module = try std.Io.Dir.cwd().openFile(io, path, .{}),
        .ctl = undefined,
    };

    try fInitModule(rt.module.handle);
    errdefer deleteModule() catch |err| std.log.err("Could not unload kernel module: {s}", .{@errorName(err)});

    rt.ctl = try std.Io.Dir.openFileAbsolute(io, chardev_ctl_path, .{ .mode = .read_write });

    if (chardev_owner) |owner| {
        const progress = try std.Io.Dir.openFileAbsolute(io, chardev_progress_path, .{ .mode = .read_write });
        try progress.setOwner(io, owner[0], owner[1]);
        try progress.setPermissions(io, .fromMode(0o644));
        progress.close(io);
    }

    return rt;
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

pub fn unload(this: @This(), io: std.Io) !void {
    this.ctl.close(io);
    this.module.close(io);

    // If child gets killed but it's fds aren't closed yet this function
    // will return an error, in such case we just need to wait for the
    // os to clean up the child fds/mmaps.
    for (0..50) |_| {
        deleteModule() catch |err| {
            switch (err) {
                DeleteModuleError.NoEntity => return,
                DeleteModuleError.FdOpen => try io.sleep(.fromMilliseconds(10), .real),
                else => return err,
            }
        };
    } else return DeleteModuleError.FdOpen;
}

pub fn startProfilerOnPid(this: *@This(), pid: linux.pid_t, fd: linux.fd_t, vma_name: []const u8) !void {
    var data: communications.Data = .{ .start = .{
        .pid = pid,
        .output_fd = fd,
        .vma_name = undefined,
        .vma_name_len = @intCast(vma_name.len),
    } };
    @memcpy(data.start.vma_name[0..vma_name.len], vma_name);
    data.start.vma_name[vma_name.len] = 0;

    const rc = linux.ioctl(
        this.ctl.handle,
        @intFromEnum(communications.Commands.start_profiler),
        @intFromPtr(&data),
    );

    const e = linux.errno(rc);
    switch (e) {
        .SUCCESS => {},
        else => std.log.err("{s}", .{@tagName(e)}),
    }
}
