const std = @import("std");

path: [*:0]const u8,
args: [*:null]const ?[*:0]const u8,
enviroment_map: std.process.Environ,
is_sudo: bool,

pub fn initFromParsedOptions(parsed: anytype, environ: std.process.Environ, allocator: std.mem.Allocator, io: std.Io) !@This() {
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

pub fn initFromString(string: []const u8, environ: std.process.Environ, allocator: std.mem.Allocator, io: std.Io) !@This() {
    return initWithIterator(std.mem.splitScalar(u8, string, ' '), std.mem.countScalar(u8, string, ' ') + 1, environ, allocator, io);
}

pub fn initWithIterator(iterator: anytype, argc: usize, environ: std.process.Environ, allocator: std.mem.Allocator, io: std.Io) !@This() {
    var it = iterator;

    var first_token = it.next().?;
    const is_sudo = isSudo(first_token);

    if (is_sudo) {
        first_token = it.next().?;
    }

    const path = try expandBinaryPath(first_token, environ, allocator, io);

    const path_span = std.mem.span(path);
    const name = std.fs.path.basename(path_span);

    const final_argc = if (is_sudo) argc - 1 else argc;
    const args_slice = try allocator.allocSentinel(?[*:0]const u8, final_argc, null);
    errdefer allocator.free(args_slice);

    const allocated_name = try allocator.dupeZ(u8, name);
    args_slice[0] = @ptrCast(allocated_name);

    var i: usize = 1;
    while (i < final_argc) : (i += 1) {
        if (it.next()) |next_arg| {
            const allocated_arg = try allocator.dupeZ(u8, next_arg);
            args_slice[i] = @ptrCast(allocated_arg);
        }
    }

    return .{ .path = path, .args = @ptrCast(args_slice.ptr), .enviroment_map = environ, .is_sudo = is_sudo };
}

fn isSudo(path: []const u8) bool {
    const start = if (std.mem.findScalarLast(u8, path, '/')) |last_slash| last_slash + 1 else 0;
    return std.mem.eql(u8, path[start..], "sudo");
}

fn expandBinaryPath(binary_path: []const u8, environ: std.process.Environ, allocator: std.mem.Allocator, io: std.Io) ![*:0]const u8 {
    if (std.mem.findScalar(u8, binary_path, '/') != null) {
        _ = try std.Io.Dir.cwd().statFile(io, binary_path, .{});
        const copy = try allocator.dupeZ(u8, binary_path);
        return @ptrCast(copy.ptr);
    }

    const path_env = environ.getPosix("PATH") orelse return error.NoPath;
    var path_it = std.mem.tokenizeScalar(u8, path_env, ':');

    return file: while (path_it.next()) |current_path| {
        const dir = std.Io.Dir.openDirAbsolute(io, current_path, .{}) catch continue;
        if (dir.statFile(io, binary_path, .{})) |_| {
            const path = try std.mem.concatWithSentinel(allocator, u8, &.{ current_path, "/", binary_path }, 0);
            break :file @ptrCast(path.ptr);
        } else |_| {}
    } else break :file error.notFoundInPath;
}

pub fn deinit(this: @This(), allocator: std.mem.Allocator) void {
    allocator.free(std.mem.span(this.path));
    const args_slice = std.mem.span(this.args);
    for (args_slice) |arg| {
        if (arg) |a| allocator.free(std.mem.span(a));
    }
    allocator.free(args_slice);
}
