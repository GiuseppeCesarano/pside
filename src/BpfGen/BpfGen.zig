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

    try PraseMapRelocations(elf);
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
        const target_scetion_header = c.elf64_getshdr(target_scan) orelse continue;
        if ((target_scetion_header.*.sh_flags & c.SHF_EXECINSTR) == 0) continue;

        const data = c.elf_getdata(scan, null) orelse continue;
        const relocations = @as([*]c.Elf64_Rel, @alignCast(@ptrCast(data.*.d_buf)))[0 .. section_header.*.sh_size / section_header.*.sh_entsize];

        for (relocations) |relocation| {
            const idx = relocation.r_offset / @sizeOf(std.os.linux.BPF.Insn);
            std.debug.print("Relocation {s} offset=0x{x} (insn {d})\n", .{ name, relocation.r_offset, idx });
        }
    }
}
