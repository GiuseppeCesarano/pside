const std = @import("std");

pub const Location = union(enum) {
    resolved: struct {
        function: ?[]const u8,
        file: ?[]const u8,
        line: u32,
    },
    ip: u64,

    pub fn deinit(this: Location, allocator: std.mem.Allocator) void {
        switch (this) {
            .resolved => |r| {
                if (r.function) |f| allocator.free(f);
                if (r.file) |f| allocator.free(f);
            },
            .ip => {},
        }
    }
};

const DebugInfo = @This();
dwarf: ?std.debug.Dwarf,
mmap: ?std.Io.File.MemoryMap,
text_vaddr: u64,
endian: std.builtin.Endian,

pub fn load(allocator: std.mem.Allocator, io: std.Io, binary_path: []const u8) !DebugInfo {
    const file = std.Io.Dir.cwd().openFile(io, binary_path, .{}) catch
        return .{ .dwarf = null, .mmap = null, .text_vaddr = 0, .endian = .little };
    defer file.close(io);

    var mmap = std.Io.File.MemoryMap.create(io, file, .{
        .len = @intCast(try file.length(io)),
        .protection = .{ .read = true, .write = false },
        .populate = false,
    }) catch return .{ .dwarf = null, .mmap = null, .text_vaddr = 0, .endian = .little };
    errdefer mmap.destroy(io);

    const bytes = mmap.memory;
    if (bytes.len < 64) return .{ .dwarf = null, .mmap = mmap, .text_vaddr = 0, .endian = .little };

    var reader: std.Io.Reader = .fixed(bytes);
    const hdr = std.elf.Header.read(&reader) catch
        return .{ .dwarf = null, .mmap = mmap, .text_vaddr = 0, .endian = .little };
    const endian = hdr.endian;

    var text_vaddr: u64 = 0;
    var ph_iter = hdr.iterateProgramHeadersBuffer(bytes);
    while (try ph_iter.next()) |ph| {
        if (ph.p_type == std.elf.PT_LOAD and ph.p_flags & std.elf.PF_X != 0) {
            text_vaddr = ph.p_vaddr;
            break;
        }
    }

    const shstrndx_sh = blk: {
        var it = hdr.iterateSectionHeadersBuffer(bytes);
        var i: usize = 0;
        while (try it.next()) |sh| : (i += 1)
            if (i == hdr.shstrndx) break :blk sh;
        return .{ .dwarf = null, .mmap = mmap, .text_vaddr = text_vaddr, .endian = endian };
    };
    const shstrtab = bytes[shstrndx_sh.sh_offset..][0..shstrndx_sh.sh_size];

    var dwarf: std.debug.Dwarf = .{ .sections = @splat(null) };
    var sh_iter = hdr.iterateSectionHeadersBuffer(bytes);
    while (try sh_iter.next()) |sh| {
        if (sh.sh_size == 0) continue;
        const name = std.mem.sliceTo(shstrtab[sh.sh_name..], 0);
        const data = bytes[sh.sh_offset..][0..sh.sh_size];
        const section: std.debug.Dwarf.Section = .{ .data = data, .owned = false };
        inline for (std.meta.fields(std.debug.Dwarf.Section.Id)) |field| {
            const dot_name = "." ++ field.name;
            if (std.mem.eql(u8, name, dot_name)) {
                dwarf.sections[@intFromEnum(@field(std.debug.Dwarf.Section.Id, field.name))] = section;
            }
        }
    }

    std.debug.Dwarf.open(&dwarf, allocator, endian) catch
        return .{ .dwarf = null, .mmap = mmap, .text_vaddr = text_vaddr, .endian = endian };

    return .{ .dwarf = dwarf, .mmap = mmap, .text_vaddr = text_vaddr, .endian = endian };
}

pub fn deinit(this: *DebugInfo, allocator: std.mem.Allocator) void {
    if (this.dwarf) |*d| d.deinit(allocator);
    if (this.elf_bytes.len > 0) std.posix.munmap(this.elf_bytes);
}

pub fn resolve(this: *DebugInfo, allocator: std.mem.Allocator, relative_ip: u64) !Location {
    var dwarf = &(this.dwarf orelse return .{ .ip = relative_ip });
    const addr = relative_ip + this.text_vaddr;

    const symbol = dwarf.getSymbol(allocator, this.endian, addr) catch
        return .{ .ip = relative_ip };

    const src = symbol.source_location;

    return .{
        .resolved = .{
            .function = if (symbol.name) |n| try allocator.dupe(u8, n) else null,
            .file = if (src) |s| s.file_name else null,
            .line = if (src) |s| @intCast(s.line) else 0,
        },
    };
}
