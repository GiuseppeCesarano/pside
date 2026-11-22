const std = @import("std");

const serialization = @import("serialization");
const payload = serialization.payload;
const UserIds = @import("UserIds");

const OutputFile = @This();

file: std.Io.File,
vma_declared: bool,

pub const WriteError = error{CouldNotWrite};

pub const OpenError = error{
    HashDontMatch,
    FileTableDontMatch,
    NotAPsideFile,
    ProgramUnreadable,
    CouldNotCreate,
    OutOfMemory,
    Unexpected,
};

pub fn open(
    allocator: std.mem.Allocator,
    io: std.Io,
    program_path: []const u8,
    program_hash: serialization.Header.Hash,
    owner: ?UserIds,
    file_names: []const []const u8,
) OpenError!OutputFile {
    const file_name = std.fs.path.basename(program_path);

    const out_name = try std.mem.concat(allocator, u8, &.{ file_name, ".pside" });
    defer allocator.free(out_name);

    const full_path = std.Io.Dir.cwd().realPathFileAlloc(io, program_path, allocator) catch |err| return switch (err) {
        error.OutOfMemory => OpenError.OutOfMemory,
        else => OpenError.ProgramUnreadable,
    };
    defer allocator.free(full_path);

    if (std.Io.Dir.cwd().openFile(io, out_name, .{ .mode = .read_write })) |f| {
        errdefer f.close(io);
        try validate(f, io, program_hash, file_names);
        std.log.info("Aggregating runs into existing {s}", .{out_name});
        return .{ .file = f, .vma_declared = false };
    } else |_| {
        std.log.info("Recording to new {s}", .{out_name});
        const f = create(io, out_name, owner, full_path, program_hash, file_names) catch return OpenError.CouldNotCreate;
        return .{ .file = f, .vma_declared = false };
    }
}

pub fn close(this: OutputFile, io: std.Io) void {
    this.file.close(io);
}

pub fn computeFileHash(io: std.Io, path: []const u8) !serialization.Header.Hash {
    //TODO: We shall also support hashing of the library the main exe loads.
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var hasher: std.crypto.hash.sha2.Sha256 = .init(.{});
    var chunk: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &.{});

    while (true) {
        const len = try reader.interface.readSliceShort(&chunk);
        if (len == 0) break;
        hasher.update(chunk[0..len]);
    }

    return hasher.finalResult();
}

fn validate(file: std.Io.File, io: std.Io, program_hash: serialization.Header.Hash, file_names: []const []const u8) OpenError!void {
    var buf: [8192]u8 = undefined;
    var reader = file.reader(io, &buf);
    const header = serialization.Header.read(&reader.interface) catch return OpenError.NotAPsideFile;

    if (!std.mem.eql(u8, &program_hash, &header.binary_hash)) return OpenError.HashDontMatch;

    var frames: payload.Frame.Iterator = .init(&reader.interface);
    var declared_count: usize = 0;
    while (frames.next()) |frame| switch (frame.tag) {
        .binary_path => {},
        .file => {
            const declared = payload.File.decode(frame.body) orelse return OpenError.NotAPsideFile;
            if (declared.id != declared_count or declared_count >= file_names.len) return OpenError.FileTableDontMatch;
            if (!std.mem.eql(u8, declared.name, file_names[declared_count])) return OpenError.FileTableDontMatch;
            declared_count += 1;
        },
        else => break,
    };

    if (declared_count != file_names.len) return OpenError.FileTableDontMatch;
}

pub fn declareVma(this: *OutputFile, io: std.Io, vma_name: []const u8) WriteError!void {
    if (this.vma_declared) return;

    const end = this.file.length(io) catch return WriteError.CouldNotWrite;

    var buf: [4096]u8 = undefined;
    var writer = this.file.writer(io, &buf);
    writer.seekTo(end) catch return WriteError.CouldNotWrite;

    const vma: payload.Vma = .{ .id = payload.default_vma_id, .name = vma_name };
    vma.write(&writer.interface) catch return WriteError.CouldNotWrite;
    writer.flush() catch return WriteError.CouldNotWrite;

    this.vma_declared = true;
}

fn create(
    io: std.Io,
    out_name: []const u8,
    owner: ?UserIds,
    program_path: []const u8,
    program_hash: serialization.Header.Hash,
    file_names: []const []const u8,
) !std.Io.File {
    const f = try std.Io.Dir.cwd().createFile(io, out_name, .{});
    errdefer f.close(io);

    if (owner) |o| try f.setOwner(io, o.uid, o.gid);

    var buf: [4096]u8 = undefined;
    var writer = f.writer(io, &buf);
    const w = &writer.interface;

    const header: serialization.Header = .init(program_hash);
    const binary_path: payload.Frame = .{ .tag = .binary_path, .body = program_path };

    try header.write(w);
    try binary_path.write(w);

    for (file_names, 0..) |name, id| {
        const file: payload.File = .{ .id = @intCast(id), .name = name };
        try file.write(w);
    }

    try writer.flush();

    return f;
}
