const std = @import("std");

path: [*:0]const u8,
args: [*:null]const ?[*:0]const u8,
enviroment_map: [*:null]const ?[*:0]const u8,

pub fn initFromParsedOptions(parsed: anytype, environ: [*:null]const ?[*:0]const u8, allocator: std.mem.Allocator, io: std.Io) !@This() {
    if (!std.mem.eql(u8, parsed.flags.c, "")) {
        if (parsed.positional_arguments != null) return error.ExtraPositionalArguments;

        return try initFromString(parsed.flags.c, environ, allocator, io);
    }

    if (parsed.positional_arguments) |args| {
        std.debug.assert(args.count() != 0);
        if (args.count() == 1) {
            var it = args;
            return try initFromString(it.next().?, environ, allocator, io);
        }

        return initWithIterator(args, args.count() - 1, environ, allocator, io);
    }

    return error.UnspecifiedCommand;
}

pub fn initFromString(string: []const u8, environ: [*:null]const ?[*:0]const u8, allocator: std.mem.Allocator, io: std.Io) !@This() {
    return initWithIterator(std.mem.splitScalar(u8, string, ' '), std.mem.countScalar(u8, string, ' '), environ, allocator, io);
}

pub fn initWithIterator(iterator: anytype, argc: usize, environ: [*:null]const ?[*:0]const u8, allocator: std.mem.Allocator, io: std.Io) !@This() {
    var it = iterator;

    const args_slice = try allocator.allocSentinel(?[*:0]const u8, argc, null);
    errdefer allocator.free(args_slice);

    const path = try expandBinaryPath(it.next().?, allocator, io);

    for (args_slice[0..]) |*arg| {
        const new_arg = try allocator.dupeZ(u8, it.next().?);
        errdefer allocator.free(new_arg);

        arg.* = @ptrCast(new_arg);
    }

    return .{ .path = path, .args = @ptrCast(args_slice.ptr), .enviroment_map = environ };
}

fn expandBinaryPath(binary_path: []const u8, allocator: std.mem.Allocator, io: std.Io) ![*:0]const u8 {
    if (std.mem.findScalar(u8, binary_path, '/') != null) {
        const copy = try allocator.dupeZ(u8, binary_path);
        return @ptrCast(copy.ptr);
    }

    const path_env = try std.process.getEnvVarOwned(allocator, "PATH");
    defer allocator.free(path_env);
    var path_it = std.mem.tokenizeScalar(u8, path_env, ':');

    while (path_it.next()) |current_path| {
        const dir = std.Io.Dir.cwd().openDir(io, current_path, .{}) catch continue;
        if (dir.statFile(io, binary_path, .{})) |_| {
            const path = try std.mem.concatWithSentinel(allocator, u8, &.{ current_path, "/", binary_path }, 0);
            return @ptrCast(path.ptr);
        } else |_| {}
    }

    return error.notFoundInPath;
}

pub fn deinit(this: @This(), allocator: std.mem.Allocator) void {
    allocator.free(std.mem.span(this.path));
    const args_slice = std.mem.span(this.args);
    for (args_slice) |arg| {
        if (arg) |a| allocator.free(std.mem.span(a));
    }
    allocator.free(args_slice);
}
