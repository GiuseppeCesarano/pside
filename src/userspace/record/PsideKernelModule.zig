const std = @import("std");
const native_endianess = @import("builtin").target.cpu.arch.endian();
const command = @import("command");

const name = "pside";

file: std.Io.File,
chardev: std.Io.File,
chardev_writer: std.fs.File.Writer, // TODO: when implemented switch to std.Io.Writer
chardev_reader: std.Io.File.Reader,
buffer: []u8,

pub fn loadFromDefaultPath(allocator: std.mem.Allocator, io: std.Io) !@This() {
    const path = try resolveModulePath(allocator);
    defer allocator.free(path);

    const buffer = try allocator.alloc(u8, std.fs.max_path_bytes + @sizeOf(command.Data));
    errdefer allocator.free(buffer);

    var rt: @This() = .{
        .file = try std.Io.Dir.cwd().openFile(io, path, .{}),
        .chardev = undefined,
        .chardev_writer = undefined,
        .chardev_reader = undefined,
        .buffer = buffer,
    };

    const load_res = std.os.linux.syscall3(
        .finit_module,
        @intCast(rt.file.handle),
        @intFromPtr(""),
        0,
    );

    rt.chardev = try std.Io.File.openAbsolute(io, "/dev/" ++ name, .{ .mode = .read_write });
    rt.chardev_writer = std.fs.File.adaptFromNewApi(rt.chardev).writerStreaming(&.{}); // switch to new api
    rt.chardev_reader = rt.chardev.reader(io, &.{});

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

fn resolveModulePath(allocator: std.mem.Allocator) ![]const u8 {
    const bin_path = try std.fs.selfExeDirPathAlloc(allocator);
    defer allocator.free(bin_path);

    const base_path = std.fs.path.dirname(bin_path) orelse "";
    const release = std.posix.uname().release;
    const release_end = std.mem.findScalar(u8, &release, 0) orelse release.len;

    return try std.mem.concat(allocator, u8, &.{ base_path, "/lib/modules/", release[0..release_end], "/extra/" ++ name ++ ".ko" });
}

pub fn unload(this: @This(), allocator: std.mem.Allocator, io: std.Io) !void {
    allocator.free(this.buffer);

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
        else => unreachable,
    };
}

pub fn setPidForFilter(this: *@This(), pid: std.os.linux.pid_t) !void {
    const c: command.Data = .{ .set_pid_for_filter = pid };

    _ = try this.chardev_writer.interface.write(std.mem.asBytes(&c));
}

pub fn loadProbe(this: *@This(), comptime kind: command.Tag, path: []const u8, offset: usize) !void {
    const c = @unionInit(command.Data, @tagName(kind), offset);

    var buffer_writer: std.Io.Writer = .fixed(this.buffer);
    // TODO: Check if we wrote all
    _ = try buffer_writer.write(std.mem.asBytes(&c));
    _ = try buffer_writer.write(path);

    _ = try this.chardev_writer.interface.write(this.buffer[0 .. @sizeOf(command.Data) + path.len]);
}
