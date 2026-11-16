const std = @import("std");
const Coverage = std.debug.Coverage;
const Dwarf = std.debug.Dwarf;
const ElfFile = std.debug.ElfFile;

const Symbolizer = @This();

elf_file: ElfFile,
text_vaddr: u64,
coverage: Coverage,

pub fn init(allocator: std.mem.Allocator, io: std.Io, binary_path: []const u8) !Symbolizer {
    const file = try std.Io.Dir.cwd().openFile(io, binary_path, .{});
    defer file.close(io);

    const search_paths: ElfFile.DebugInfoSearchPaths = .{
        .debuginfod_client = null,
        .global_debug = &.{"/usr/lib/debug"},
        .exe_dir = std.fs.path.dirname(binary_path),
    };

    var elf_file: ElfFile = try .load(allocator, io, file, null, &search_paths);
    errdefer elf_file.deinit(allocator);

    const dwarf = if (elf_file.dwarf) |*dwarf| dwarf else return Dwarf.ScanError.MissingDebugInfo;
    try dwarf.open(allocator, elf_file.endian);
    try dwarf.populateRanges(allocator, elf_file.endian);

    return .{
        .elf_file = elf_file,
        .text_vaddr = try computeTextVaddr(elf_file.mapped_file),
        .coverage = .init,
    };
}

fn computeTextVaddr(bytes: []const u8) ElfFile.LoadError!u64 {
    var reader: std.Io.Reader = .fixed(bytes);
    const elf_header = std.elf.Header.read(&reader) catch unreachable;

    var program_header_iterator = elf_header.iterateProgramHeadersBuffer(bytes);
    return while (program_header_iterator.next() catch return ElfFile.LoadError.TruncatedElfFile) |header| {
        if (header.type == .LOAD and header.flags.X) {
            const misalign = if (header.@"align" == 0) 0 else header.offset % header.@"align";
            break header.vaddr - misalign;
        }
    } else 0;
}

pub fn deinit(this: *Symbolizer, allocator: std.mem.Allocator) void {
    this.coverage.deinit(allocator);
    this.elf_file.deinit(allocator);

    this.* = undefined;
}

pub fn toVaddrs(this: Symbolizer, relative_ips: []u64) void {
    for (relative_ips) |*ip| ip.* += this.text_vaddr;
}

pub fn resolve(this: *Symbolizer, allocator: std.mem.Allocator, io: std.Io, sorted_vaddrs: []const u64) ![]Coverage.SourceLocation {
    const resolved = try allocator.alloc(Coverage.SourceLocation, sorted_vaddrs.len);
    errdefer allocator.free(resolved);

    try this.coverage.resolveAddressesDwarf(allocator, io, this.elf_file.endian, sorted_vaddrs, resolved, &this.elf_file.dwarf.?);

    return resolved;
}

pub fn allocName(this: *Symbolizer, allocator: std.mem.Allocator, file_index: Coverage.File.Index, line: u32) std.mem.Allocator.Error![]u8 {
    const basename = this.coverage.stringAt(this.coverage.fileAt(file_index).basename);
    return std.fmt.allocPrint(allocator, "{s}:{}", .{ basename, line });
}
