const std = @import("std");

const OutputFileParseResults = @import("OutputFileParseResults");

const Collapsed = @This();

pub const Throughput = struct {
    pub const Vma = struct {
        pub const Experiments = struct {
            pub const speedups = 21;
            pub const Datapoints = [speedups]std.ArrayListUnmanaged(f32); // [0] = 0% speedup, [20] = 100% speedup

            location: []const u8,
            datapoints: Datapoints,
        };

        name: []const u8,
        experiments: []Experiments,
    };

    vmas: []Vma,
};

throughput: Throughput,
//latency: Latency, TODO

pub fn onDwarfSymbol(arena_allocator: std.mem.Allocator, io: std.Io, parse_results: OutputFileParseResults) !Collapsed {
    const file = try std.Io.Dir.openFileAbsolute(io, parse_results.path, .{});
    defer file.close(io);

    var mmap = try std.Io.File.MemoryMap.create(io, file, .{
        .len = try file.length(io),
        .protection = .{ .read = true, .write = false },
        .populate = false,
    });
    defer mmap.destroy(io);

    const elf_header = blk: {
        var reader: std.Io.Reader = .fixed(mmap.memory);
        break :blk try std.elf.Header.read(&reader);
    };

    var dwarf = try openDwarf(arena_allocator, elf_header, mmap.memory);
    defer dwarf.deinit(arena_allocator);

    const text_vaddr = try computeTextVaddr(elf_header, mmap.memory);

    return .{
        .throughput = try collapseThroughputWithDwarf(arena_allocator, parse_results.vmas.throughput, &dwarf, elf_header.endian, text_vaddr),
    };
}

fn openDwarf(arena_allocator: std.mem.Allocator, elf_header: std.elf.Header, buff: []const u8) !std.debug.Dwarf {
    var dwarf: std.debug.Dwarf = .{ .sections = @splat(null) };

    var section_header_iterator = elf_header.iterateSectionHeadersBuffer(buff);
    var i: usize = 0;
    const section_header_string_table = while (try section_header_iterator.next()) |section| : (i += 1) {
        if (elf_header.shstrndx == i) break buff[section.sh_offset .. section.sh_offset + section.sh_size];
    } else return error.StringTableNotFound;

    section_header_iterator = elf_header.iterateSectionHeadersBuffer(buff);
    while (try section_header_iterator.next()) |section| {
        const name = std.mem.sliceTo(section_header_string_table[section.sh_name..], 0);
        const data = buff[section.sh_offset .. section.sh_offset + section.sh_size];

        inline for (std.meta.fields(std.debug.Dwarf.Section.Id)) |field| {
            if (std.mem.eql(u8, name, "." ++ field.name)) {
                const section_index = @intFromEnum(@field(std.debug.Dwarf.Section.Id, field.name));
                dwarf.sections[section_index] = .{ .data = data, .owned = false };
            }
        }
    }

    if (dwarf.sections[@intFromEnum(std.debug.Dwarf.Section.Id.debug_info)] == null) return error.NoDebugInfo;
    try dwarf.open(arena_allocator, elf_header.endian);

    return dwarf;
}

fn computeTextVaddr(elf_header: std.elf.Header, bytes: []const u8) !u64 {
    var program_header_iterator = elf_header.iterateProgramHeadersBuffer(bytes);
    return while (try program_header_iterator.next()) |header| {
        if (header.p_type == std.elf.PT_LOAD and header.p_flags & std.elf.PF_X != 0)
            break header.p_vaddr - (header.p_offset % header.p_align);
    } else 0;
}

fn collapseThroughputWithDwarf(
    allocator: std.mem.Allocator,
    parsed_vmas_map: OutputFileParseResults.Vmas.VmaThroughputExperimentsMap,
    dwarf: *std.debug.Dwarf,
    endian: std.builtin.Endian,
    text_vaddr: u64,
) !Throughput {
    const vmas = try allocator.alloc(Throughput.Vma, parsed_vmas_map.size);
    var parsed_vmas_map_iterator = parsed_vmas_map.iterator();
    for (vmas) |*vma| {
        var location_map: std.StringHashMapUnmanaged(Throughput.Vma.Experiments.Datapoints) = .empty;
        defer location_map.deinit(allocator);

        const map_vma = parsed_vmas_map_iterator.next().?;
        for (map_vma.value_ptr.items) |experiment| {
            // TODO: maybe just write directly the float
            const datapoint = experiment.throughput;
            const speedup_percent = experiment.speedup_percent;

            if (speedup_percent % 5 != 0 or speedup_percent > 100) return error.BadSpeedUpPercent;
            const index = @divExact(speedup_percent, 5);

            const address = experiment.relative_ip + text_vaddr;
            const solved_name = getSrcString(allocator, dwarf, endian, address);
            const name = if (solved_name) |n| n else |_| try std.fmt.allocPrint(allocator, "0x{x}", .{experiment.relative_ip});

            const pair = try location_map.getOrPut(allocator, name);
            if (!pair.found_existing) {
                pair.key_ptr.* = name;
                for (pair.value_ptr) |*bucket|
                    bucket.* = .empty;
            } else allocator.free(name);

            try pair.value_ptr[index].append(allocator, datapoint);
        }

        const experiments = try allocator.alloc(Throughput.Vma.Experiments, location_map.size);
        var location_iterator = location_map.iterator();
        for (experiments) |*experiment| {
            const location_pair = location_iterator.next().?;
            experiment.* = .{
                .location = location_pair.key_ptr.*,
                .datapoints = location_pair.value_ptr.*,
            };
        }

        vma.* = .{
            .name = try allocator.dupe(u8, map_vma.key_ptr.*),
            .experiments = experiments,
        };
    }

    return .{ .vmas = vmas };
}

fn getSrcString(allocator: std.mem.Allocator, dwarf: *std.debug.Dwarf, endian: std.builtin.Endian, address: u64) ![]const u8 {
    const compile_unit = try dwarf.findCompileUnit(endian, address);
    try dwarf.populateSrcLocCache(allocator, endian, compile_unit);

    const slc = &compile_unit.src_loc_cache.?;
    const line_entry = try slc.findSource(address);
    if (line_entry.isInvalid()) return error.AddressNotFound;

    const file_index = line_entry.file - @intFromBool(slc.version < 5);
    if (file_index >= slc.files.len) return error.InvalidFileIndex;

    const file_name = std.fs.path.basename(slc.files[file_index].path);
    return std.fmt.allocPrint(allocator, "{s}:{}", .{ file_name, line_entry.line });
}
