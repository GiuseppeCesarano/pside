const std = @import("std");

buffer: [][]const u8,

pub fn initFromParsedOptions(parsed: anytype, allocator: std.mem.Allocator, io: std.Io) !@This() {
    if (!std.mem.eql(u8, parsed.flags.c, "")) {
        if (parsed.positional_arguments != null) return error.ExtraPositionalArguments;

        return try initFromString(parsed.flags.c, allocator, io);
    }

    if (parsed.positional_arguments) |args| {
        var it = args;
        if (it.count() == 1) return try initFromString(it.next().?, allocator, io);

        const buffer = try allocator.alloc([]const u8, it.count());
        errdefer allocator.free(buffer);

        buffer[0] = try expandBinaryPath(it.next().?, allocator, io);
        copyToBuffer(buffer, &it);

        return .{ .buffer = buffer };
    }

    return error.UnspecifiedCommand;
}

pub fn initFromString(string: []const u8, allocator: std.mem.Allocator, io: std.Io) !@This() {
    const buffer = try allocator.alloc([]const u8, std.mem.countScalar(u8, string, ' ') + 1);
    errdefer allocator.free(buffer);

    var it = std.mem.splitScalar(u8, string, ' ');

    buffer[0] = try expandBinaryPath(it.next().?, allocator, io);
    copyToBuffer(buffer, &it);

    return .{ .buffer = buffer };
}

fn copyToBuffer(buffer: [][]const u8, it: anytype) void {
    for (buffer[1..]) |*str| {
        str.* = it.next().?;
    }
}

fn expandBinaryPath(binary_path: []const u8, allocator: std.mem.Allocator, io: std.Io) ![]const u8 {
    if (std.mem.findScalar(u8, binary_path, '/') != null) {
        //Allocate and copy so we don't need special logic in deinit.
        const copy = try allocator.alloc(u8, binary_path.len);
        @memcpy(copy, binary_path);
        return copy;
    }

    const path_env = try std.process.getEnvVarOwned(allocator, "PATH");
    defer allocator.free(path_env);
    var path_it = std.mem.tokenizeScalar(u8, path_env, ':');

    while (path_it.next()) |current_path| {
        const dir = std.Io.Dir.cwd().openDir(io, current_path, .{}) catch continue;
        if (dir.statPath(io, binary_path, .{})) |_| {
            return std.mem.concat(allocator, u8, &.{ current_path, "/", binary_path });
        } else |_| {}
    }

    return error.notFoundInPath;
}

pub fn deinit(this: @This(), allocator: std.mem.Allocator) void {
    allocator.free(this.buffer[0]);
    allocator.free(this.buffer);
}
