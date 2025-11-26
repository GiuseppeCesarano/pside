const std = @import("std");
const cli = @import("cli");
const KernelModule = @import("kernel_module").KernelModule;

pub fn record(options: cli.Options, allocator: std.mem.Allocator, io: std.Io) !void {
    const parsed_options = options.parse(struct {
        c: []const u8 = "",
    });

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    var future_module = io.async(KernelModule("pside").loadFromDefaultPath, .{ allocator, io });
    defer if (future_module.cancel(io)) |module| module.unload(io) catch {} else |_| {
        std.log.warn("Could not remove the kernel module, please try manually with:\n\nsudo rmmod pside", .{});
    };

    const command: Command = try .initFromParsedOptions(parsed_options, allocator, io);
    defer command.deinit(allocator);

    // TODO: Drop permissions to userspace using SUDO_USER
    var child: std.process.Child = .init(command.buffer, allocator);
    try child.spawn();

    var module = try future_module.await(io);
    try module.chardev_writer.interface.writeInt(@TypeOf(child.id), child.id, @import("builtin").target.cpu.arch.endian());
}

fn validateOptions(optinal_errors: ?cli.Options.Iterator, comptime msg: []const u8) !void {
    if (optinal_errors) |errors| {
        @branchHint(.cold);
        var it = errors;
        while (it.next()) |flag| {
            std.log.err("{s}{s}", .{ msg, flag });
        }

        return error.InvalidOption;
    }
}

const Command = struct {
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
};

// TODO: trasform in a custom type.
pub fn loadDebugInfo(path: []const u8, allocator: std.mem.Allocator, io: std.Io) !std.debug.ElfFile {
    var file = try if (path[0] == '/') std.Io.File.openAbsolute(io, path, .{}) else std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var elf: std.debug.ElfFile = try .load(allocator, .adaptFromNewApi(file), null, &.none);
    errdefer elf.deinit(allocator);

    if (elf.dwarf == null) return error.MissingDebugInfo;
    try elf.dwarf.?.open(allocator, elf.endian);
    try elf.dwarf.?.populateRanges(allocator, elf.endian);

    return elf;
}
