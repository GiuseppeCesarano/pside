const std = @import("std");
const Dwarf = std.debug.Dwarf;

const Symbolizer = @This();

file: std.Io.File,
mmap: std.Io.File.MemoryMap,
dwarf: Dwarf,
endian: std.builtin.Endian,
text_vaddr: u64,
cache: std.AutoHashMapUnmanaged(u64, []const u8),

pub fn init(allocator: std.mem.Allocator, io: std.Io, binary_path: []const u8) !Symbolizer {
    const file = try std.Io.Dir.openFileAbsolute(io, binary_path, .{});
    errdefer file.close(io);

    var mmap = try std.Io.File.MemoryMap.create(io, file, .{
        .len = try file.length(io),
        .protection = .{ .read = true, .write = false },
        .populate = false,
    });
    errdefer mmap.destroy(io);

    const elf_header = blk: {
        var reader: std.Io.Reader = .fixed(mmap.memory);
        break :blk try std.elf.Header.read(&reader);
    };

    var dwarf = try openDwarf(allocator, elf_header, mmap.memory);
    errdefer dwarf.deinit(allocator);

    try dwarf.populateRanges(allocator, elf_header.endian);

    return .{
        .file = file,
        .mmap = mmap,
        .dwarf = dwarf,
        .endian = elf_header.endian,
        .text_vaddr = try computeTextVaddr(elf_header, mmap.memory),
        .cache = .empty,
    };
}

pub fn deinit(this: *Symbolizer, allocator: std.mem.Allocator, io: std.Io) void {
    var located = this.cache.valueIterator();
    while (located.next()) |location| allocator.free(location.*);

    this.cache.deinit(allocator);
    this.dwarf.deinit(allocator);
    this.mmap.destroy(io);
    this.file.close(io);
}

/// This struct owns the memory, caller must not free the allocation.
pub fn locate(this: *Symbolizer, allocator: std.mem.Allocator, relative_ip: u64) ![]const u8 {
    const address = relative_ip + this.text_vaddr;
    const pair = try this.cache.getOrPut(allocator, address);

    if (!pair.found_existing)
        pair.value_ptr.* = getSrcString(allocator, &this.dwarf, this.endian, address) catch
            try std.fmt.allocPrint(allocator, "0x{x}", .{relative_ip});

    return pair.value_ptr.*;
}

fn openDwarf(allocator: std.mem.Allocator, elf_header: std.elf.Header, buff: []const u8) !Dwarf {
    var dwarf: Dwarf = .{ .sections = @splat(null) };

    var section_header_iterator = elf_header.iterateSectionHeadersBuffer(buff);
    var i: usize = 0;
    const section_header_string_table = while (try section_header_iterator.next()) |section| : (i += 1) {
        if (elf_header.shstrndx == i) break buff[section.sh_offset .. section.sh_offset + section.sh_size];
    } else return error.StringTableNotFound;

    section_header_iterator = elf_header.iterateSectionHeadersBuffer(buff);
    while (try section_header_iterator.next()) |section| {
        const name = std.mem.sliceTo(section_header_string_table[section.sh_name..], 0);
        const data = buff[section.sh_offset .. section.sh_offset + section.sh_size];

        inline for (@typeInfo(Dwarf.Section.Id).@"enum".field_names) |field_name| {
            if (std.mem.eql(u8, name, "." ++ field_name)) {
                const section_index = @backingInt(@field(Dwarf.Section.Id, field_name));
                dwarf.sections[section_index] = .{ .data = data, .owned = false };
            }
        }
    }

    if (dwarf.sections[@backingInt(Dwarf.Section.Id.debug_info)] == null) return error.NoDebugInfo;
    try dwarf.open(allocator, elf_header.endian);

    return dwarf;
}

fn getSrcString(allocator: std.mem.Allocator, dwarf: *Dwarf, endian: std.builtin.Endian, address: u64) ![]const u8 {
    const compile_unit = findCompileUnitByRange(dwarf, address) orelse return error.AddressNotFound;
    try dwarf.populateSrcLocCache(allocator, endian, compile_unit);

    const slc = &compile_unit.src_loc_cache.?;
    const line_entry = try slc.findSource(address);
    if (line_entry.isInvalid()) return error.AddressNotFound;

    const file_index = line_entry.file - @intFromBool(slc.version < 5);
    if (file_index >= slc.files.len) return error.InvalidFileIndex;

    const file_path = slc.files[file_index].path;
    return std.fmt.allocPrint(allocator, "{s}:{}", .{ file_path, line_entry.line });
}

fn computeTextVaddr(elf_header: std.elf.Header, bytes: []const u8) !u64 {
    var program_header_iterator = elf_header.iterateProgramHeadersBuffer(bytes);
    return while (try program_header_iterator.next()) |header| {
        if (header.type == .LOAD and header.flags.X) {
            const misalign = if (header.@"align" == 0) 0 else header.offset % header.@"align";
            break header.vaddr - misalign;
        }
    } else 0;
}

fn findCompileUnitByRange(dwarf: *Dwarf, address: u64) ?*Dwarf.CompileUnit {
    const scoped = struct {
        pub fn compareRange(addr: u64, range: Dwarf.Range) std.math.Order {
            if (addr < range.start) return .lt;
            if (addr >= range.end) return .gt;
            return .eq;
        }
    };

    const index = std.sort.binarySearch(Dwarf.Range, dwarf.ranges.items, address, scoped.compareRange);

    return if (index) |i|
        &dwarf.compile_unit_list.items[dwarf.ranges.items[i].compile_unit_index]
    else
        null;
}
