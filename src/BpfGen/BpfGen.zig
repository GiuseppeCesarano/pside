const std = @import("std");
const c = @cImport({
    @cInclude("libbpf.h");
    @cInclude("libelf.h");
});

pub fn main() !void {
    var args = std.process.args();
    _ = args.skip();
    const path = args.next();

    if (path == null) {
        _ = try std.fs.File.stderr().write("Usage: BpfGen <File>\n");
        std.process.exit(1);
    }

    const bpf_obj = c.bpf_object__open_file(path.?.ptr, null);
    defer c.bpf_object__close(bpf_obj);

    const elf_file = try std.fs.cwd().openFile(path.?, .{});
    defer elf_file.close();
    const elf = c.elf_begin(elf_file.handle, c.ELF_C_READ, null) orelse return error.ElfCantOpen;
    defer _ = c.elf_end(elf);

    try GetMaps(bpf_obj.?);
    try PraseMapRelocations(elf);
}

fn GetMaps(bpf: *c.struct_bpf_object) !void {
    var m: ?*c.struct_bpf_map = null;
    while (c.bpf_object__next_map(bpf, m)) |map| : (m = map) {
        std.debug.print("name={s}, type={s}\n", .{ c.bpf_map__name(map), @tagName(@as(std.os.linux.BPF.MapType, @enumFromInt(c.bpf_map__type(map)))) });
    }
}

fn PraseMapRelocations(elf: *c.struct_Elf) !void {
    var section_header_string_table: usize = undefined;
    if (c.elf_getshdrstrndx(elf, &section_header_string_table) != 0) return error.CantGetShdrstrndx;

    var scn: ?*c.Elf_Scn = null;
    while (c.elf_nextscn(elf, scn)) |scan| : (scn = scan) {
        const section_header = c.elf64_getshdr(scan) orelse continue;
        if (section_header.*.sh_type != c.SHT_REL) continue;

        const name = std.mem.span(c.elf_strptr(elf, section_header_string_table, section_header.*.sh_name) orelse continue);
        if (!std.mem.startsWith(u8, name, ".rel")) continue;

        const target_scan = c.elf_getscn(elf, section_header.*.sh_info) orelse continue;
        const target_section_header = c.elf64_getshdr(target_scan) orelse continue;
        if ((target_section_header.*.sh_flags & c.SHF_EXECINSTR) == 0) continue;

        const data = c.elf_getdata(scan, null) orelse continue;
        const relocation_len = section_header.*.sh_size / section_header.*.sh_entsize;
        const relocations = @as([*]c.Elf64_Rel, @alignCast(@ptrCast(data.*.d_buf)))[0..relocation_len];

        const symbol_table = c.elf_getscn(elf, section_header.*.sh_link) orelse return error.MalformedElf;
        const symbol_table_section_header = c.elf64_getshdr(symbol_table) orelse return error.MalformedElf;
        std.debug.assert(symbol_table_section_header.*.sh_entsize == @sizeOf(c.Elf64_Sym));
        const symbol_len = symbol_table_section_header.*.sh_size / symbol_table_section_header.*.sh_entsize;
        const symbol_data = c.elf_getdata(symbol_table, null) orelse return error.MalformedElf;
        const symbols = @as([*]c.Elf64_Sym, @alignCast(@ptrCast(symbol_data.*.d_buf)))[0..symbol_len];

        const name_table = c.elf_getscn(elf, symbol_table_section_header.*.sh_link) orelse return error.MalformedElf;
        const name_data = c.elf_getdata(name_table, null) orelse return error.MalformedElf;
        const names = @as([*:0]const u8, @alignCast(@ptrCast(name_data.*.d_buf)))[0..name_data.*.d_size];

        for (relocations) |relocation| {
            const sym_index: usize = @intCast(c.ELF64_R_SYM(relocation.r_info));
            if (sym_index >= symbols.len) return error.MalformedElf;

            const symbol = symbols[sym_index];
            const symbol_name_offset: usize = @intCast(symbol.st_name);
            const symbol_name = if (symbol_name_offset < names.len)
                std.mem.span(@as([*:0]const u8, @ptrCast(names.ptr)) + symbol_name_offset)
            else
                "unknown";

            const idx = relocation.r_offset / @sizeOf(std.os.linux.BPF.Insn);

            std.debug.print("Relocation {s} offset=0x{x}, symbol={s}, insn {d}\n", .{ name[4..], relocation.r_offset, symbol_name, idx });
        }
    }
}
