const std = @import("std");
const elf = std.elf;

const Program = @import("Program.zig");

pub const ParseError = error{
    ProgramUnreadable,
    BadElf,
    MalformedElfSection,
    NoPsideSection,
    NoProgressPointsWithSuchName,
    OutOfMemory,
};

pub fn getPatchAddr(user_program: Program, name: []const u8, allocator: std.mem.Allocator, io: std.Io) ParseError![]const usize {
    const path = std.mem.span(user_program.path);
    var file = (if (std.fs.path.isAbsolute(path))
        std.Io.Dir.openFileAbsolute(io, path, .{})
    else
        std.Io.Dir.cwd().openFile(io, path, .{})) catch return ParseError.ProgramUnreadable;
    defer file.close(io);

    var buffer: [255]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const header = std.elf.Header.read(&reader.interface) catch return ParseError.BadElf;

    const strtab = try getStrtab(header, &reader, allocator);
    defer allocator.free(strtab);

    const pside_shdr = try getSectionByName(header, &reader, ".pside_throughput", strtab) orelse return ParseError.NoPsideSection;
    return findCorrectProgressPoint(header, pside_shdr, &reader, name, allocator);
}

fn getStrtab(header: elf.Header, reader: *std.Io.File.Reader, allocator: std.mem.Allocator) ParseError![]const u8 {
    var it = header.iterateSectionHeaders(reader);
    var current_idx: usize = 0;
    const strtab_sh = while (it.next() catch return ParseError.BadElf) |sh| : (current_idx += 1) {
        if (current_idx == header.shstrndx) break sh;
    } else return ParseError.BadElf;

    reader.seekTo(strtab_sh.sh_offset) catch return ParseError.BadElf;
    return reader.interface.readAlloc(allocator, strtab_sh.sh_size) catch |err| switch (err) {
        error.OutOfMemory => ParseError.OutOfMemory,
        else => ParseError.BadElf,
    };
}

fn getSectionByName(header: elf.Header, reader: *std.Io.File.Reader, target_name: []const u8, strtab: []const u8) ParseError!?std.elf.Elf64_Shdr {
    var it = header.iterateSectionHeaders(reader);
    return blk: while (it.next() catch return ParseError.BadElf) |sh| {
        const current_name = std.mem.sliceTo(strtab[sh.sh_name..], 0);
        if (std.mem.eql(u8, target_name, current_name)) break :blk sh;
    } else null;
}

fn findCorrectProgressPoint(header: elf.Header, shdr: std.elf.Elf64_Shdr, reader: *std.Io.File.Reader, name: []const u8, allocator: std.mem.Allocator) ParseError![]const usize {
    reader.seekTo(shdr.sh_offset) catch return ParseError.BadElf;
    const section_data = reader.interface.readAlloc(allocator, shdr.sh_size) catch |err| switch (err) {
        error.OutOfMemory => return ParseError.OutOfMemory,
        else => return ParseError.BadElf,
    };
    defer allocator.free(section_data);

    var buffer_reader: std.Io.Reader = .fixed(section_data);
    var list: std.ArrayList(usize) = try .initCapacity(allocator, 10);
    errdefer list.deinit(allocator);

    var target = name;

    while (buffer_reader.seek + @sizeOf(u64) <= buffer_reader.end) {
        const addr = buffer_reader.takeInt(u64, header.endian) catch return ParseError.MalformedElfSection;
        const read_name = buffer_reader.takeSentinel(0) catch return ParseError.MalformedElfSection;
        if (read_name.len == 0) return ParseError.MalformedElfSection;

        // If user didn't provide a name, we take the first one we find as the target
        if (target.len == 0) target = read_name;

        if (std.mem.eql(u8, read_name, target))
            try list.append(allocator, addr -% header.entry);
    }

    if (list.items.len == 0) return ParseError.NoProgressPointsWithSuchName;
    return list.toOwnedSlice(allocator);
}
