const std = @import("std");

const serialization = @import("serialization");
const payload = serialization.payload;
const UserIds = @import("UserIds");

const OutputFile = @This();

file: std.Io.File,

pub const WriteError = error{CouldNotWrite};

pub const OpenError = error{
    HashDontMatch,
    NotAPsideFile,
    ProgramUnreadable,
    CouldNotCreate,
    OutOfMemory,
    Unexpected,
};

pub fn open(allocator: std.mem.Allocator, io: std.Io, program_path: []const u8, vma_name: []const u8, owner: ?UserIds) OpenError!OutputFile {
    const file_name = std.fs.path.basename(program_path);

    const out_name = try std.mem.concat(allocator, u8, &.{ file_name, ".pside" });
    defer allocator.free(out_name);

    const full_path = std.Io.Dir.cwd().realPathFileAlloc(io, program_path, allocator) catch |err| return switch (err) {
        error.OutOfMemory => OpenError.OutOfMemory,
        else => OpenError.ProgramUnreadable,
    };
    defer allocator.free(full_path);

    const program_hash = computeFileHash(allocator, io, program_path) catch |err| return switch (err) {
        error.OutOfMemory => OpenError.OutOfMemory,
        else => OpenError.ProgramUnreadable,
    };

    if (std.Io.Dir.cwd().openFile(io, out_name, .{ .mode = .read_write })) |f| {
        errdefer f.close(io);
        try validate(f, io, program_hash);
        std.log.info("Aggregating runs into existing {s}", .{out_name});
        return .{ .file = f };
    } else |_| {
        std.log.info("Recording to new {s}", .{out_name});
        const f = create(io, out_name, owner, full_path, vma_name, program_hash) catch return OpenError.CouldNotCreate;
        return .{ .file = f };
    }
}

pub fn close(this: OutputFile, io: std.Io) void {
    this.file.close(io);
}

fn computeFileHash(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![32]u8 {
    //TODO: We shall also support hashing of the library the main exe loads.
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var reader = file.reader(io, &.{});
    const bytes = try reader.interface.allocRemaining(allocator, .unlimited);
    defer allocator.free(bytes);

    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    return out;
}

fn validate(file: std.Io.File, io: std.Io, program_hash: [32]u8) OpenError!void {
    var buf: [4096]u8 = undefined;
    var reader = file.reader(io, &buf);
    const header = serialization.Header.read(&reader.interface) catch return OpenError.NotAPsideFile;

    if (!std.mem.eql(u8, &program_hash, &header.binary_hash)) return OpenError.HashDontMatch;
}

fn create(
    io: std.Io,
    out_name: []const u8,
    owner: ?UserIds,
    program_path: []const u8,
    vma_name: []const u8,
    program_hash: [32]u8,
) !std.Io.File {
    const f = try std.Io.Dir.cwd().createFile(io, out_name, .{});
    errdefer f.close(io);

    if (owner) |o| try f.setOwner(io, o.uid, o.gid);

    var buf: [4096]u8 = undefined;
    var writer = f.writer(io, &buf);
    const w = &writer.interface;

    const header: serialization.Header = .init(program_hash);
    const binary_path: payload.Frame = .{ .tag = .binary_path, .body = program_path };
    const vma: payload.Vma = .{ .id = 0, .name = vma_name }; // TODO: id should not be always 0.

    try header.write(w);
    try binary_path.write(w);
    try vma.write(w);
    try writer.flush();

    return f;
}
