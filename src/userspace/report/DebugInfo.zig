const std = @import("std");

pub const Location = union(enum) {
    resolved: struct {
        function: ?[]const u8,
        file: ?[]const u8,
        line: u32,
    },
    ip: u64,

    pub fn deinit(self: Location, allocator: std.mem.Allocator) void {
        switch (self) {
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

const empty: DebugInfo = .{
    .dwarf = null,
    .mmap = null,
    .text_vaddr = 0,
    .endian = .little,
};

pub fn load(allocator: std.mem.Allocator, io: std.Io, binary_path: []const u8) !DebugInfo {
    const file = std.Io.Dir.cwd().openFile(io, binary_path, .{}) catch return empty;
    defer file.close(io);

    const file_len: usize = @intCast(try file.length(io));
    if (file_len < 64) return empty;

    var mmap = std.Io.File.MemoryMap.create(io, file, .{
        .len = file_len,
        .protection = .{ .read = true, .write = false },
        .populate = false,
    }) catch return empty;
    errdefer mmap.destroy(io);

    const bytes = mmap.memory;

    var reader: std.Io.Reader = .fixed(bytes);
    const hdr = std.elf.Header.read(&reader) catch return .{ .dwarf = null, .mmap = mmap, .text_vaddr = 0, .endian = .little };
    const endian = hdr.endian;

    var ph_it = hdr.iterateProgramHeadersBuffer(bytes);
    const text_vaddr = while (try ph_it.next()) |ph| {
        if (ph.p_type == std.elf.PT_LOAD and ph.p_flags & std.elf.PF_X != 0) break ph.p_vaddr;
    } else 0;

    const bail: DebugInfo = .{ .dwarf = null, .mmap = mmap, .text_vaddr = text_vaddr, .endian = endian };

    var sh_it = hdr.iterateSectionHeadersBuffer(bytes);
    var i: usize = 0;
    const shstrtab = while (try sh_it.next()) |sh| : (i += 1) {
        if (i == hdr.shstrndx) break bytes[sh.sh_offset..][0..sh.sh_size];
    } else return bail;

    var dwarf: std.debug.Dwarf = .{ .sections = @splat(null) };
    sh_it = hdr.iterateSectionHeadersBuffer(bytes);
    while (try sh_it.next()) |sh| {
        if (sh.sh_size == 0) continue;

        const name = std.mem.sliceTo(shstrtab[sh.sh_name..], 0);
        const data = bytes[sh.sh_offset..][0..sh.sh_size];

        inline for (std.meta.fields(std.debug.Dwarf.Section.Id)) |field| {
            if (std.mem.eql(u8, name, "." ++ field.name)) {
                const section = @intFromEnum(@field(std.debug.Dwarf.Section.Id, field.name));
                dwarf.sections[section] = .{ .data = data, .owned = false };
            }
        }
    }

    std.debug.Dwarf.open(&dwarf, allocator, endian) catch return bail;

    return .{ .dwarf = dwarf, .mmap = mmap, .text_vaddr = text_vaddr, .endian = endian };
}

pub fn deinit(self: *DebugInfo, allocator: std.mem.Allocator, io: std.Io) void {
    if (self.dwarf) |*d| d.deinit(allocator);
    if (self.mmap) |*m| m.destroy(io);
}

pub fn resolve(self: *DebugInfo, allocator: std.mem.Allocator, relative_ip: u64) !Location {
    const dwarf = &(self.dwarf orelse return .{ .ip = relative_ip });
    const addr = relative_ip + self.text_vaddr;

    const symbol = dwarf.getSymbol(allocator, self.endian, addr) catch
        return .{ .ip = relative_ip };

    const src = symbol.source_location;
    return .{ .resolved = .{
        .function = if (symbol.name) |n| try allocator.dupe(u8, n) else null,
        .file = if (src) |s| s.file_name else null,
        .line = if (src) |s| @intCast(s.line) else 0,
    } };
}
