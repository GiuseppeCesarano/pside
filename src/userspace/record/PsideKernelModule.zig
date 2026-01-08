const std = @import("std");
const native_endianess = @import("builtin").target.cpu.arch.endian();
const communications = @import("communications");

const name = "pside";

pub const CharDevOwner = struct { uid: u32, gid: u32 };

file: std.Io.File,
chardev: std.Io.File,

pub fn loadFromDefaultPath(chardev_owner: ?CharDevOwner, allocator: std.mem.Allocator, io: std.Io) !@This() {
    const path = try resolveModulePath(allocator, io);
    defer allocator.free(path);

    var rt: @This() = .{
        .file = try std.Io.Dir.cwd().openFile(io, path, .{}),
        .chardev = undefined,
    };

    const load_res = std.os.linux.syscall3(
        .finit_module,
        @intCast(rt.file.handle),
        @intFromPtr(""),
        0,
    );

    rt.chardev = try std.Io.Dir.openFileAbsolute(io, "/dev/" ++ name, .{ .mode = .read_write });
    if (chardev_owner) |owner| {
        try rt.chardev.setOwner(io, owner.uid, owner.gid);
        try rt.chardev.setPermissions(io, .fromMode(0o644));
    }

    return switch (std.posix.errno(load_res)) {
        .SUCCESS => rt,

        .BADMSG => error.SignatureMisformatted,
        .BUSY => error.SymbolResolutionTimeout,
        .FAULT => error.AddressFault,
        .NOKEY => error.SignatureInvalidOrNoKey,
        .NOMEM => error.OutOfMemory,
        .PERM => error.NotPrivilegedOrLoadingDisabled,
        .EXIST => error.ModuleAlreadyLoaded,
        .INVAL => error.InvalidParamsOrInconsistentELF,
        .NOEXEC => error.InvalidELFOrWrongArchitecture,
        .BADF => error.FileNotReadable,
        .FBIG => error.FileTooLarge,
        .OPNOTSUPP => error.CompressedModuleNotSupported,
        .TXTBSY => error.FileOpenedReadWrite,
        else => error.Unknown,
    };
}

fn resolveModulePath(allocator: std.mem.Allocator, io: std.Io) ![]const u8 {
    const bin_path = try std.process.executableDirPathAlloc(io, allocator);
    defer allocator.free(bin_path);

    const base_path = std.fs.path.dirname(bin_path) orelse "";
    const release = std.posix.uname().release;
    const release_end = std.mem.findScalar(u8, &release, 0) orelse release.len;

    return try std.mem.concat(allocator, u8, &.{ base_path, "/lib/modules/", release[0..release_end], "/extra/" ++ name ++ ".ko" });
}

pub fn unload(this: @This(), io: std.Io) !void {
    this.chardev.close(io);
    defer this.file.close(io);

    const remove_res = std.os.linux.syscall2(
        .delete_module,
        @intFromPtr(name.ptr),
        0,
    );

    return switch (std.posix.errno(remove_res)) {
        .SUCCESS => {},

        .AGAIN => error.FdOpen,
        .BUSY => error.NotLive,
        .NOENT => error.NoEntity,

        // delete_module could also return PERM, FAULT
        // but each of those errors shouldn't be appliacable in our
        // case
        else => error.Unknown,
    };
}

pub fn startProfilerOnPid(this: *@This(), pid: std.os.linux.pid_t) !void {
    const data = communications.Data{ .pid = pid };

    const rc = std.os.linux.ioctl(
        this.chardev.handle,
        @intFromEnum(communications.Commands.start_profiler_on_pid),
        @intFromPtr(&data),
    );
    const e = std.posix.errno(rc);
    switch (e) {
        .SUCCESS => {},
        else => std.log.err("{s}", .{@tagName(e)}),
    }
}
