const std = @import("std");

name: []const u8,
file: std.Io.File,
allocator: std.mem.Allocator,

pub fn loadFromDefaultModulePath(allocator: std.mem.Allocator, io: std.Io, name: [:0]const u8) !@This() {
    const path = try resolveModulePath(name, allocator);
    defer allocator.free(path);

    const rt: @This() = .{
        .name = name,
        .file = try std.Io.Dir.cwd().openFile(io, path, .{}),
        .allocator = allocator,
    };

    const load_res = std.os.linux.syscall3(
        .finit_module,
        @intCast(rt.file.handle),
        @intFromPtr(""),
        0,
    );

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
        else => unreachable,
    };
}

pub fn resolveModulePath(name: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    const bin_path = try std.fs.selfExeDirPathAlloc(allocator);
    defer allocator.free(bin_path);

    const base_path = std.fs.path.dirname(bin_path) orelse "";
    const release = std.posix.uname().release;
    const release_end = std.mem.findScalar(u8, &release, 0) orelse release.len;

    return try std.mem.concat(allocator, u8, &.{ base_path, "/lib/modules/", release[0..release_end], "/extra/", name, ".ko" });
}

pub fn unload(this: @This(), io: std.Io) !void {
    defer this.file.close(io);

    const remove_res = std.os.linux.syscall2(
        .delete_module,
        @intFromPtr(this.name.ptr),
        0,
    );

    return switch (std.posix.errno(remove_res)) {
        .SUCCESS => {},

        else => {}, //TODO: add erros
    };
}
