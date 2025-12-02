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

    // Allocate enough buffer for the reader to allow
    // sending all possible commands with a single syscall.
    const buffer = try allocator.alloc(u8, std.fs.max_path_bytes + @sizeOf(command.Tag) + @sizeOf(usize));
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
    rt.chardev_writer = std.fs.File.adaptFromNewApi(rt.chardev).writerStreaming(rt.buffer); // switch to new api
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
        else => error.Unknown,
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
        else => error.Unknown,
    };
}

pub fn setPidForFilter(this: *@This(), pid: std.os.linux.pid_t) !void {
    _ = try this.chardev_writer.interface.writeInt(u8, @intFromEnum(command.Tag.set_pid_for_filter), native_endianess);
    _ = try this.chardev_writer.interface.writeInt(std.os.linux.pid_t, pid, native_endianess);
    try this.chardev_writer.interface.flush();
}

pub fn sendProbe(this: *@This(), comptime kind: command.Tag, path: []const u8, offset: usize) !void {
    switch (kind) {
        .send_benchmark_probe, .send_function_probe, .send_mutex_probe => {},
        else => @compileError("Please provide a command which loads an uprobe."),
    }

    // This would excede the buffer and couse the writer to call
    // the syscall two times which would result in the kenel
    // module to treat those as two separated commands.
    if (path.len >= std.fs.max_path_bytes) return error.pathTooLong;

    _ = try this.chardev_writer.interface.writeInt(u8, @intFromEnum(kind), native_endianess);
    _ = try this.chardev_writer.interface.writeInt(usize, offset, native_endianess);
    _ = try this.chardev_writer.interface.write(path);
    _ = try this.chardev_writer.interface.writeInt(u8, 0, native_endianess);

    try this.chardev_writer.interface.flush();
}

pub fn registerProbes(this: *@This()) !void {
    try this.chardev_writer.interface.writeInt(u8, @intFromEnum(command.Tag.register_probes), native_endianess);

    try this.chardev_writer.interface.flush();
}
