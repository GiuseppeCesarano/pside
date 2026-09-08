const std = @import("std");
const linux = std.os.linux;

const communications = @import("communications");
const UserIds = @import("UserIds");

const name = communications.name;

pub const LoadError = FInitModuleError || error{
    ModuleFileUnreadable,
    CouldNotHandOverDevice,
    Unexpected,
};

pub fn load(owner: UserIds, allocator: std.mem.Allocator, io: std.Io) LoadError!void {
    const path = resolveModulePath(allocator, io) catch |err| return switch (err) {
        error.OutOfMemory => LoadError.OutOfMemory,
        else => LoadError.Unexpected,
    };
    defer allocator.free(path);

    const module = std.Io.Dir.cwd().openFile(io, path, .{}) catch return LoadError.ModuleFileUnreadable;
    defer module.close(io);

    try fInitModule(module.handle);
    errdefer deleteModule() catch |err| std.log.warn("Could not unload kernel module: {s}", .{@errorName(err)});

    handDeviceToOwner(communications.control_device_path, owner, io) catch return LoadError.CouldNotHandOverDevice;
}

fn resolveModulePath(allocator: std.mem.Allocator, io: std.Io) ![]const u8 {
    const bin_path = try std.process.executableDirPathAlloc(io, allocator);
    defer allocator.free(bin_path);

    const base_path = std.fs.path.dirname(bin_path) orelse "";
    var uts: std.os.linux.utsname = undefined;
    _ = std.os.linux.uname(&uts);
    const release = uts.release;
    const release_end = std.mem.findScalar(u8, &release, 0) orelse release.len;

    return std.mem.concat(allocator, u8, &.{ base_path, "/lib/modules/", release[0..release_end], "/extra/" ++ name ++ ".ko" });
}

fn handDeviceToOwner(path: [:0]const u8, owner: UserIds, io: std.Io) !void {
    const dev = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_write });
    defer dev.close(io);
    try dev.setOwner(io, owner.uid, owner.gid);
    try dev.setPermissions(io, .fromMode(0o600));
}

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

fn fInitModule(handle: linux.fd_t) FInitModuleError!void {
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

pub const DeleteModuleError = error{
    FdOpen,
    NotLive,
    NoEntity,
    Unknown,
};

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

pub fn unload(io: std.Io) DeleteModuleError!bool {
    // If a record process was killed but its fds aren't closed yet this
    // returns FdOpen; in that case we just wait for the os to clean up the
    // child fds/mmaps.
    for (0..50) |_| {
        deleteModule() catch |err| {
            switch (err) {
                DeleteModuleError.NoEntity => return false,
                DeleteModuleError.FdOpen => {
                    io.sleep(.fromMilliseconds(10), .real) catch {};
                    continue;
                },
                else => return err,
            }
        };
        return true;
    }

    return DeleteModuleError.FdOpen;
}
