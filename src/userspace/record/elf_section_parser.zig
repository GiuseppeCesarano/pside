const std = @import("std");
const Program = @import("Program.zig");
const elf = std.elf;

pub fn getPatchAddr(user_program: Program, allocator: std.mem.Allocator, io: std.Io) !usize {
    const path = std.mem.span(user_program.path);
    var file = try if (std.fs.path.isAbsolute(path))
        std.Io.Dir.openFileAbsolute(io, path, .{})
    else
        std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var buffer: [128]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const header = try std.elf.Header.read(&reader.interface);

    const strtab = try getStrtab(header, &reader, allocator);
    defer allocator.free(strtab);

    const pside_shdr = try getSectionByName(header, &reader, ".pside_throughput", strtab) orelse return error.NoPsideSection;

    try reader.seekTo(pside_shdr.sh_offset);
    const raw_target_addr = try reader.interface.takeInt(u64, header.endian);

    return raw_target_addr -% header.entry;
}

fn getStrtab(header: elf.Header, reader: *std.Io.File.Reader, allocator: std.mem.Allocator) ![]const u8 {
    const shstrndx_offset = header.shoff + (@as(u64, header.shstrndx) * header.shentsize);
    try reader.seekTo(shstrndx_offset);

    var it = header.iterateSectionHeaders(reader);
    var current_idx: usize = 0;
    var strtab_sh: std.elf.Elf64_Shdr = undefined;
    while (try it.next()) |sh| : (current_idx += 1) {
        if (current_idx == header.shstrndx) {
            strtab_sh = sh;
            break;
        }
    } else return error.BadElf;

    try reader.seekTo(strtab_sh.sh_offset);
    return try reader.interface.readAlloc(allocator, strtab_sh.sh_size);
}

fn getSectionByName(header: elf.Header, reader: *std.Io.File.Reader, target_name: []const u8, strtab: []const u8) !?std.elf.Elf64_Shdr {
    var it = header.iterateSectionHeaders(reader);
    return blk: while (try it.next()) |sh| {
        const current_name = std.mem.sliceTo(strtab[sh.sh_name..], 0);
        if (std.mem.eql(u8, target_name, current_name)) break :blk sh;
    } else null;
}
