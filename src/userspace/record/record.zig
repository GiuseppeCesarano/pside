const std = @import("std");
const cli = @import("cli");
const PsideKernelModule = @import("PsideKernelModule.zig");
const UserProgram = @import("UserProgram.zig");
const Tracee = @import("Tracee.zig");

pub fn record(options: cli.Options, init: std.process.Init) !void {
    const parsed_options = options.parse(struct {
        c: []const u8 = "",
    });

    const io = init.io;
    const allocator = init.gpa;

    try validateOptions(parsed_options.unknown_flags, "Unknown flag: ");
    try validateOptions(parsed_options.parse_errors, "Could not parse: ");

    const chardev_owner = blk: {
        const env = init.minimal.environ;

        const gid = try std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse break :blk null, 10);
        const uid = try std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse break :blk null, 10);

        break :blk PsideKernelModule.ChardevOwner{ .uid = uid, .gid = gid };
    };

    var future_module = io.async(PsideKernelModule.loadFromDefaultPath, .{ chardev_owner, allocator, io });
    defer if (future_module.cancel(io)) |module| module.unload(io) catch {
        std.log.warn("Could not remove the kernel module, please try manually with:\n\n\tsudo rmmod pside\n", .{});
    } else |_| {};

    const user_program: UserProgram = try .initFromParsedOptions(parsed_options, init.minimal.environ, allocator, io);
    defer user_program.deinit(allocator);

    const tracee: Tracee = try .spawn(user_program, io);

    var module = try future_module.await(io);
    try module.startProfilerOnPid(tracee.pid);

    std.log.info("Remote getpid returns: {}", .{try tracee.syscall(.getpid, .{})});
    std.log.info("Remote time returns: {}", .{try tracee.syscall(.time, .{0})});

    try tracee.patchProgressPoint(try getPatchAddr(user_program, allocator, io));

    try tracee.start();
    _ = try tracee.wait();
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

fn getPatchAddr(user_program: UserProgram, allocator: std.mem.Allocator, io: std.Io) !usize {
    const Dir = std.Io.Dir;
    const path = std.mem.span(user_program.path);
    var file = try if (std.fs.path.isAbsolute(path))
        Dir.openFileAbsolute(io, path, .{})
    else
        Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var buffer: [128]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const header = try std.elf.Header.read(&reader.interface);

    const shstrndx_offset = header.shoff + (@as(u64, header.shstrndx) * header.shentsize);
    try reader.seekTo(shstrndx_offset);

    var it = header.iterateSectionHeaders(&reader);
    var current_idx: usize = 0;
    var strtab_sh: std.elf.Elf64_Shdr = undefined;
    while (try it.next()) |sh| : (current_idx += 1) {
        if (current_idx == header.shstrndx) {
            strtab_sh = sh;
            break;
        }
    } else return error.BadElf;

    try reader.seekTo(strtab_sh.sh_offset);
    const strtab = try reader.interface.readAlloc(allocator, strtab_sh.sh_size);
    defer allocator.free(strtab);

    it = header.iterateSectionHeaders(&reader); // Reset iterator
    const section = blk: while (try it.next()) |sh| {
        // Safe way to get name: slice until null terminator
        const name = std.mem.sliceTo(strtab[sh.sh_name..], 0);
        if (std.mem.eql(u8, ".pside_throughput", name)) break :blk sh;
    } else return error.NoPsideSection;

    try reader.seekTo(section.sh_offset);
    const relative_hook_addr = try reader.interface.takeInt(u64, header.endian);

    return relative_hook_addr;
}
