const std = @import("std");
const native_endianess = @import("builtin").target.cpu.arch.endian();
const communications = @import("communications");
const linux = std.os.linux;

pub const name = "pside";
pub const chardev_path: [:0]const u8 = "/dev/" ++ name;

pub const ChardevOwner = struct { uid: u32, gid: u32 };

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

file: std.Io.File,
chardev: std.Io.File,

pub fn loadModuleFromDefaultPath(chardev_owner: ?ChardevOwner, allocator: std.mem.Allocator, io: std.Io) !@This() {
    const path = try resolveModulePath(allocator, io);
    defer allocator.free(path);

    var rt: @This() = .{
        .file = try std.Io.Dir.cwd().openFile(io, path, .{}),
        .chardev = undefined,
    };

    try fInitModule(rt.file.handle);
    errdefer deleteModule() catch |err| std.log.err("Could not unload kernel module: {s}", .{@errorName(err)});

    rt.chardev = try std.Io.Dir.openFileAbsolute(io, chardev_path, .{ .mode = .read_write });
    if (chardev_owner) |owner| {
        try rt.chardev.setOwner(io, owner.uid, owner.gid);
        try rt.chardev.setPermissions(io, .fromMode(0o644));
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
    this.chardev.close(io);
    this.file.close(io);

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

pub fn startProfilerOnPid(this: *@This(), pid: linux.pid_t) !void {
    const data = communications.Data{ .pid = pid };

    const rc = linux.ioctl(
        this.chardev.handle,
        @intFromEnum(communications.Commands.start_profiler),
        @intFromPtr(&data),
    );
    const e = linux.errno(rc);
    switch (e) {
        .SUCCESS => {},
        else => std.log.err("{s}", .{@tagName(e)}),
    }
}
