const std = @import("std");

const serialization = @import("serialization");

const OutputFile = @This();

file: std.Io.File,

pub fn open(allocator: std.mem.Allocator, io: std.Io, program_path: []const u8, owner: ?[2]u32) !OutputFile {
    const file_name = std.fs.path.basename(program_path);

    const out_name = try std.mem.concat(allocator, u8, &.{ file_name, ".pside" });
    defer allocator.free(out_name);

    const full_path = try std.Io.Dir.cwd().realPathFileAlloc(io, program_path, allocator);
    defer allocator.free(full_path);

    const program_hash: [32]u8 = @splat(0); //TODO: actually compute binary's hash

    std.log.info("{s}", .{out_name});

    return .{ .file = if (std.Io.Dir.cwd().openFile(io, out_name, .{ .mode = .read_write })) |f| blk: {
        errdefer f.close(io);
        try validate(f, io, @splat(0));
        break :blk f;
    } else |_| try create(io, out_name, owner, full_path, program_hash) };
}

pub fn close(this: OutputFile, io: std.Io) void {
    this.file.close(io);
}

fn validate(file: std.Io.File, io: std.Io, program_hash: [32]u8) !void {
    var buf: [4096]u8 = undefined;
    var reader = file.reader(io, &buf);
    const header = try reader.interface.takeStruct(serialization.Header, .native);

    if (!std.mem.eql(u8, &serialization.Header.default.magic, &header.magic)) return error.BadMagic;
    if (serialization.Header.default.version.major != header.version.major) return error.FileMajorDontMatch;

    const hash = try reader.interface.takeArray(32);

    if (!std.mem.eql(u8, &program_hash, hash)) return error.HashDontMatch;
}

fn create(
    io: std.Io,
    out_name: []const u8,
    owner: ?[2]u32,
    program_path: []const u8,
    program_hash: [32]u8,
) !std.Io.File {
    const f = try std.Io.Dir.cwd().createFile(io, out_name, .{});
    errdefer f.close(io);

    if (owner) |o| try f.setOwner(io, o[0], o[1]);
    try writeFormatHeader(io, f, program_path, program_hash);

    return f;
}

fn writeFormatHeader(io: std.Io, file: std.Io.File, program_path: []const u8, program_hash: [32]u8) !void {
    var buf: [4096]u8 = undefined;

    var writer = file.writer(io, &buf);

    try writer.interface.writeAll(std.mem.asBytes(&serialization.Header.default));
    try writer.interface.writeAll(program_hash[0..]);
    try writer.interface.writeAll(program_path);
    try writer.interface.writeByte(0);
    try writer.flush();
}
