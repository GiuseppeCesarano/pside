const std = @import("std");

const serialization = @import("serialization");

const OutputFile = @This();

file: std.Io.File,

pub fn open(allocator: std.mem.Allocator, io: std.Io, program_path: []const u8, vma_name: []const u8, owner: ?[2]u32) !OutputFile {
    const file_name = std.fs.path.basename(program_path);

    const out_name = try std.mem.concat(allocator, u8, &.{ file_name, ".pside" });
    defer allocator.free(out_name);

    const full_path = try std.Io.Dir.cwd().realPathFileAlloc(io, program_path, allocator);
    defer allocator.free(full_path);

    const program_hash = try computeFileHash(allocator, io, program_path);

    return .{ .file = if (std.Io.Dir.cwd().openFile(io, out_name, .{ .mode = .read_write })) |f| blk: {
        errdefer f.close(io);
        validate(f, io, program_hash) catch |err| {
            if (err == error.HashDontMatch)
                std.log.err("{s} was recorded from a different build of the binary; delete it to start a fresh profile.", .{out_name});
            return err;
        };
        std.log.info("Aggregating runs into existing {s}", .{out_name});
        break :blk f;
    } else |_| blk: {
        std.log.info("Recording to new {s}", .{out_name});
        break :blk try create(io, out_name, owner, full_path, vma_name, program_hash);
    } };
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

pub fn close(this: OutputFile, io: std.Io) void {
    this.file.close(io);
}

fn validate(file: std.Io.File, io: std.Io, program_hash: [32]u8) !void {
    var buf: [4096]u8 = undefined;
    var reader = file.reader(io, &buf);
    const header = try reader.interface.takeStruct(serialization.Header, .little);

    if (!header.isValid()) return error.NotAPsideFile;
    if (!std.mem.eql(u8, &program_hash, &header.binary_hash)) return error.HashDontMatch;
}

fn create(
    io: std.Io,
    out_name: []const u8,
    owner: ?[2]u32,
    program_path: []const u8,
    vma_name: []const u8,
    program_hash: [32]u8,
) !std.Io.File {
    const f = try std.Io.Dir.cwd().createFile(io, out_name, .{});
    errdefer f.close(io);

    if (owner) |o| try f.setOwner(io, o[0], o[1]);

    var buf: [4096]u8 = undefined;
    var writer = f.writer(io, &buf);
    const w = &writer.interface;

    try w.writeAll(std.mem.asBytes(&serialization.Header.init(program_hash)));
    try writeFrame(w, .binary_path, program_path);
    try writeVmaFrame(w, 0, vma_name);
    try writer.flush();

    return f;
}

fn writeFrame(w: *std.Io.Writer, tag: serialization.Tag, payload: []const u8) !void {
    const header: serialization.FrameHeader = .{ .tag = tag, .length = @intCast(payload.len) };
    try w.writeAll(std.mem.asBytes(&header));
    try w.writeAll(payload);
    try writePad(w, payload.len);
}

fn writeVmaFrame(w: *std.Io.Writer, vma_id: u32, name: []const u8) !void {
    const vma_frame: serialization.VmaFrame = .{ .vma_id = vma_id };
    const length = @sizeOf(serialization.VmaFrame) + name.len;
    const header: serialization.FrameHeader = .{ .tag = .vma, .length = @intCast(length) };
    try w.writeAll(std.mem.asBytes(&header));
    try w.writeAll(std.mem.asBytes(&vma_frame));
    try w.writeAll(name);
    try writePad(w, length);
}

fn writePad(w: *std.Io.Writer, length: usize) !void {
    const pad = serialization.pad8(length) - length;
    if (pad != 0) try w.splatByteAll(0, pad);
}
