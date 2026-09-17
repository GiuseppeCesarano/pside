const std = @import("std");
const Dwarf = std.debug.Dwarf;

const Symbolizer = @This();

pub const OpenError = error{
    BinaryUnreadable,
    BadElf,
    StringTableNotFound,
    NoDebugInfo,
    MalformedDebugInfo,
    OutOfMemory,
};

pub const Debug = struct {
    file: std.Io.File,
    mmap: std.Io.File.MemoryMap,
    dwarf: Dwarf,
    endian: std.builtin.Endian,
    text_vaddr: u64,

    fn deinit(this: *Debug, allocator: std.mem.Allocator, io: std.Io) void {
        this.dwarf.deinit(allocator);
        this.mmap.destroy(io);
        this.file.close(io);
    }
};

debug_info: union(enum) { open: Debug, unavailable: OpenError },
cache: std.AutoHashMapUnmanaged(u64, []const u8),

pub fn init(allocator: std.mem.Allocator, io: std.Io, binary_path: []const u8) Symbolizer {
    if (openDebug(allocator, io, binary_path)) |debug| {
        return .{ .debug_info = .{ .open = debug }, .cache = .empty };
    } else |err| {
        return .{ .debug_info = .{ .unavailable = err }, .cache = .empty };
    }
}

pub fn deinit(this: *Symbolizer, allocator: std.mem.Allocator, io: std.Io) void {
    var located = this.cache.valueIterator();
    while (located.next()) |location| allocator.free(location.*);

    this.cache.deinit(allocator);

    switch (this.debug_info) {
        .open => |*debug| debug.deinit(allocator, io),
        .unavailable => {},
    }

    this.* = undefined;
}

pub fn symbolsUnavailable(this: Symbolizer) ?OpenError {
    return switch (this.debug_info) {
        .open => null,
        .unavailable => |err| err,
    };
}

pub const LocateError = error{OutOfMemory};

/// This struct owns the memory, caller must not free the allocation.
pub fn locate(this: *Symbolizer, allocator: std.mem.Allocator, relative_ip: u64) LocateError![]const u8 {
    const debug: ?*Debug = switch (this.debug_info) {
        .open => |*open| open,
        .unavailable => null,
    };

    const address = relative_ip + if (debug) |d| d.text_vaddr else 0;

    const pair = try this.cache.getOrPut(allocator, address);
    if (pair.found_existing) return pair.value_ptr.*;
    errdefer _ = this.cache.remove(address);

    const located: ?[]const u8 = if (debug) |d|
        getSrcString(allocator, &d.dwarf, d.endian, address)
    else
        null;

    pair.value_ptr.* = located orelse try std.fmt.allocPrint(allocator, "0x{x}", .{relative_ip});

    return pair.value_ptr.*;
}

fn openDebug(allocator: std.mem.Allocator, io: std.Io, binary_path: []const u8) OpenError!Debug {
    if (!std.fs.path.isAbsolute(binary_path)) return OpenError.BinaryUnreadable;

    const file = std.Io.Dir.openFileAbsolute(io, binary_path, .{}) catch return OpenError.BinaryUnreadable;
    errdefer file.close(io);

    var mmap = std.Io.File.MemoryMap.create(io, file, .{
        .len = file.length(io) catch return OpenError.BinaryUnreadable,
        .protection = .{ .read = true, .write = false },
        .populate = false,
    }) catch return OpenError.BinaryUnreadable;
    errdefer mmap.destroy(io);

    const elf_header = blk: {
        var reader: std.Io.Reader = .fixed(mmap.memory);
        break :blk std.elf.Header.read(&reader) catch return OpenError.BadElf;
    };

    var dwarf = try openDwarf(allocator, elf_header, mmap.memory);
    errdefer dwarf.deinit(allocator);

    dwarf.populateRanges(allocator, elf_header.endian) catch |err| return switch (err) {
        Dwarf.ScanError.OutOfMemory => OpenError.OutOfMemory,
        else => OpenError.MalformedDebugInfo,
    };

    return .{
        .file = file,
        .mmap = mmap,
        .dwarf = dwarf,
        .endian = elf_header.endian,
        .text_vaddr = try computeTextVaddr(elf_header, mmap.memory),
    };
}

fn openDwarf(allocator: std.mem.Allocator, elf_header: std.elf.Header, buff: []const u8) OpenError!Dwarf {
    var dwarf: Dwarf = .{ .sections = @splat(null) };
    errdefer dwarf.deinit(allocator);

    var section_header_iterator = elf_header.iterateSectionHeadersBuffer(buff);
    var i: usize = 0;
    const section_header_string_table = while (section_header_iterator.next() catch return OpenError.BadElf) |section| : (i += 1) {
        if (elf_header.shstrndx == i) break sectionData(buff, section) orelse return OpenError.BadElf;
    } else return OpenError.StringTableNotFound;

    section_header_iterator = elf_header.iterateSectionHeadersBuffer(buff);
    while (section_header_iterator.next() catch return OpenError.BadElf) |section| {
        if (section.sh_name >= section_header_string_table.len) continue;
        const name = std.mem.sliceTo(section_header_string_table[section.sh_name..], 0);
        const stem = std.mem.cutPrefix(u8, name, ".") orelse continue;
        const id = std.meta.stringToEnum(Dwarf.Section.Id, stem) orelse continue;
        const data = sectionData(buff, section) orelse continue;

        dwarf.sections[@backingInt(id)] = .{ .data = data, .owned = false };
    }

    if (dwarf.sections[@backingInt(Dwarf.Section.Id.debug_info)] == null) return OpenError.NoDebugInfo;
    dwarf.open(allocator, elf_header.endian) catch |err| return switch (err) {
        Dwarf.ScanError.OutOfMemory => OpenError.OutOfMemory,
        else => OpenError.MalformedDebugInfo,
    };

    return dwarf;
}

fn sectionData(buff: []const u8, section: std.elf.Elf64_Shdr) ?[]const u8 {
    const start = std.math.cast(usize, section.sh_offset) orelse return null;
    const size = std.math.cast(usize, section.sh_size) orelse return null;
    const end = std.math.add(usize, start, size) catch return null;

    return if (end <= buff.len) buff[start..end] else null;
}

fn getSrcString(allocator: std.mem.Allocator, dwarf: *Dwarf, endian: std.builtin.Endian, address: u64) ?[]const u8 {
    const compile_unit = findCompileUnitByRange(dwarf, address) orelse return null;
    dwarf.populateSrcLocCache(allocator, endian, compile_unit) catch return null;

    const slc = &compile_unit.src_loc_cache.?;
    const line_entry = slc.findSource(address) catch return null;
    if (line_entry.isInvalid()) return null;

    const file_index = line_entry.file - @intFromBool(slc.version < 5);
    if (file_index >= slc.files.len) return null;

    const file_path = slc.files[file_index].path;
    return std.fmt.allocPrint(allocator, "{s}:{}", .{ file_path, line_entry.line }) catch null;
}

fn computeTextVaddr(elf_header: std.elf.Header, bytes: []const u8) OpenError!u64 {
    var program_header_iterator = elf_header.iterateProgramHeadersBuffer(bytes);
    return while (program_header_iterator.next() catch return OpenError.BadElf) |header| {
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
