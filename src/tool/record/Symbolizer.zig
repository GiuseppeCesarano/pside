const std = @import("std");
const Coverage = std.debug.Coverage;
const Dwarf = std.debug.Dwarf;
const ElfFile = std.debug.ElfFile;

const LineMap = @import("LineMap");

const Symbolizer = @This();

elf_file: ElfFile,
text_vaddr: u64,
coverage: Coverage,
compile_unit_files: []?[]Coverage.File.Index,

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

    const compile_unit_files = try allocator.alloc(?[]Coverage.File.Index, dwarf.compile_unit_list.items.len);
    @memset(compile_unit_files, null);

    return .{
        .elf_file = elf_file,
        .text_vaddr = try computeTextVaddr(elf_file.mapped_file),
        .coverage = .init,
        .compile_unit_files = compile_unit_files,
    };
}

fn computeTextVaddr(bytes: []const u8) ElfFile.LoadError!u64 {
    var reader: std.Io.Reader = .fixed(bytes);
    const elf_header = std.elf.Header.read(&reader) catch unreachable;

    var program_header_iterator = elf_header.iterateProgramHeadersBuffer(bytes);
    return while (program_header_iterator.next() catch return ElfFile.LoadError.TruncatedElfFile) |header| {
        if (header.type == .LOAD and header.flags.X) break std.mem.alignBackward(u64, header.vaddr, std.heap.pageSize());
    } else 0;
}

pub fn deinit(this: *Symbolizer, allocator: std.mem.Allocator) void {
    for (this.compile_unit_files) |files| if (files) |f| allocator.free(f);
    allocator.free(this.compile_unit_files);
    this.coverage.deinit(allocator);
    this.elf_file.deinit(allocator);

    this.* = undefined;
}

pub const LineMapError = error{NoLineTable};

pub fn lineMap(this: *Symbolizer, allocator: std.mem.Allocator) !LineMap {
    var line_map: LineMap = .empty;
    errdefer line_map.deinit(allocator);

    var iterator = this.boundaries();
    while (try iterator.next(allocator)) |boundary|
        try line_map.emit(allocator, boundary.relative_ip, .{ .file = boundary.location.file, .line = boundary.location.line });

    if (!line_map.isWellFormed()) return LineMapError.NoLineTable;
    return line_map;
}

pub const Boundary = struct {
    relative_ip: u64,
    location: Coverage.SourceLocation,
};

pub fn boundaries(this: *Symbolizer) BoundaryIterator {
    return .{ .symbolizer = this, .covered_end = this.text_vaddr };
}

pub const BoundaryIterator = struct {
    symbolizer: *Symbolizer,
    covered_end: u64,
    range_index: usize = 0,
    current: ?Current = null,

    const Current = struct {
        end: u64,
        compile_unit_index: usize,
        cache: *const Dwarf.CompileUnit.SrcLocCache,
        row: usize,
    };

    pub fn next(this: *BoundaryIterator, allocator: std.mem.Allocator) !?Boundary {
        const symbolizer = this.symbolizer;

        if (this.current) |*current| {
            const addresses = current.cache.line_table.keys();
            if (current.row < addresses.len and addresses[current.row] < current.end) {
                defer current.row += 1;
                return .{
                    .relative_ip = addresses[current.row] - symbolizer.text_vaddr,
                    .location = try symbolizer.locate(allocator, current.compile_unit_index, current.cache, current.cache.line_table.values()[current.row]),
                };
            }

            const end = current.end;
            this.current = null;
            return .{ .relative_ip = end - symbolizer.text_vaddr, .location = .invalid };
        }

        const dwarf = &symbolizer.elf_file.dwarf.?;
        const range = while (this.range_index < dwarf.ranges.items.len) {
            const range = dwarf.ranges.items[this.range_index];
            this.range_index += 1;
            if (range.start >= this.covered_end and range.end > range.start) break range;
        } else return null;
        this.covered_end = range.end;

        const compile_unit = &dwarf.compile_unit_list.items[range.compile_unit_index];
        try dwarf.populateSrcLocCache(allocator, symbolizer.elf_file.endian, compile_unit);
        const cache = &compile_unit.src_loc_cache.?;

        const row = std.sort.upperBound(u64, cache.line_table.keys(), range.start, order);
        this.current = .{ .end = range.end, .compile_unit_index = range.compile_unit_index, .cache = cache, .row = row };

        return .{
            .relative_ip = range.start - symbolizer.text_vaddr,
            .location = if (row == 0) .invalid else try symbolizer.locate(allocator, range.compile_unit_index, cache, cache.line_table.values()[row - 1]),
        };
    }

    fn order(a: u64, b: u64) std.math.Order {
        return std.math.order(a, b);
    }
};

fn locate(
    this: *Symbolizer,
    allocator: std.mem.Allocator,
    compile_unit_index: usize,
    cache: *const Dwarf.CompileUnit.SrcLocCache,
    row: Dwarf.CompileUnit.SrcLocCache.LineEntry,
) std.mem.Allocator.Error!Coverage.SourceLocation {
    const files = this.compile_unit_files[compile_unit_index] orelse files: {
        const files = try allocator.alloc(Coverage.File.Index, cache.files.len);
        @memset(files, .invalid);
        this.compile_unit_files[compile_unit_index] = files;
        break :files files;
    };

    const file_index = row.file - @intFromBool(cache.version < 5);
    const file = &files[file_index];
    if (file.* == .invalid) file.* = try this.internFile(allocator, cache, file_index);

    return .{ .file = file.*, .line = row.line, .column = row.column };
}

fn internFile(
    this: *Symbolizer,
    allocator: std.mem.Allocator,
    cache: *const Dwarf.CompileUnit.SrcLocCache,
    file_index: usize,
) std.mem.Allocator.Error!Coverage.File.Index {
    const coverage = &this.coverage;
    const file_entry = cache.files[file_index];
    const directory = cache.directories[file_entry.dir_index].path;

    try coverage.string_bytes.ensureUnusedCapacity(allocator, directory.len + file_entry.path.len + 2);

    const directory_gop = try coverage.directories.getOrPutContextAdapted(
        allocator,
        directory,
        Coverage.String.SliceAdapter{ .string_bytes = coverage.string_bytes.items },
        Coverage.String.MapContext{ .string_bytes = coverage.string_bytes.items },
    );
    if (!directory_gop.found_existing) directory_gop.key_ptr.* = coverage.addStringAssumeCapacity(directory);

    const file_gop = try coverage.files.getOrPutContextAdapted(
        allocator,
        Coverage.File.SliceAdapter.Entry{ .directory_index = @intCast(directory_gop.index), .basename = file_entry.path },
        Coverage.File.SliceAdapter{ .string_bytes = coverage.string_bytes.items },
        Coverage.File.MapContext{ .string_bytes = coverage.string_bytes.items },
    );
    if (!file_gop.found_existing) file_gop.key_ptr.* = .{
        .directory_index = @intCast(directory_gop.index),
        .basename = coverage.addStringAssumeCapacity(file_entry.path),
    };

    return @fromBackingInt(@intCast(file_gop.index));
}

pub fn allocFileNames(this: *Symbolizer, allocator: std.mem.Allocator) std.mem.Allocator.Error![][]u8 {
    const files = this.coverage.files.keys();

    const names = try allocator.alloc([]u8, files.len);
    var filled: usize = 0;
    errdefer {
        for (names[0..filled]) |name| allocator.free(name);
        allocator.free(names);
    }

    for (files, names) |file, *name| {
        name.* = try allocator.dupe(u8, this.coverage.stringAt(file.basename));
        filled += 1;
    }

    return names;
}
