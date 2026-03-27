const std = @import("std");

const serialization = @import("serialization");

const ParseResult = @This();

pub const ThroughputNoIP = extern struct {
    progress_delta: u64,
    wall: u64,
    injected_delay: u64,
    speedup_percent: u8,

    pub fn fromThroughputRecord(record: serialization.record.Throughput) ThroughputNoIP {
        return .{
            .progress_delta = record.progress_delta,
            .wall = record.wall,
            .injected_delay = record.injected_delay,
            .speedup_percent = record.speedup_percent,
        };
    }
};

pub const ThroughputIpMap = std.AutoHashMapUnmanaged(u64, std.ArrayListUnmanaged(ThroughputNoIP));
const ThroughputMap = std.StringHashMapUnmanaged(ThroughputIpMap);

const LatencyIpMap = std.AutoHashMapUnmanaged(u64, std.ArrayListUnmanaged(ThroughputNoIP));
const LatencyMap = std.StringHashMapUnmanaged(LatencyIpMap);

throughput_map: ThroughputMap,
latency_map: LatencyMap,
binary_hash: [32]u8,
binary_path: []const u8,

pub fn deinit(this: *ParseResult, allocator: std.mem.Allocator) void {
    allocator.free(this.binary_path);
    deinitMaps(&this.throughput_map, &this.latency_map, allocator);
}

pub fn parse(allocator: std.mem.Allocator, io: std.Io, path: [:0]const u8) !ParseResult {
    const MiB = 1024 * 1024;
    const page_size = std.heap.pageSize();

    var result: ParseResult = undefined;

    // Even 10yo nvme ssds can copy 2MiB in a single transfer.
    const buffer = try allocator.alignedAlloc(u8, .fromByteUnits(page_size), 2 * MiB);
    defer allocator.free(buffer);

    const file = try openFile(path);
    defer file.close(io);

    var reader = file.reader(io, buffer);

    const header = try reader.interface.takeStructPointer(serialization.Header);
    if (!std.mem.eql(u8, &header.magic, &serialization.Header.default.magic)) return error.WrongMagic;
    if (header.version.major != serialization.Header.default.version.major) return error.VersionMajorNotMatching;

    result.binary_hash = (try reader.interface.takeStructPointer(serialization.FileInfo)).hash;
    result.binary_path = try allocator.dupe(u8, (try reader.interface.takeSentinel(0))[0..]);
    errdefer allocator.free(result.binary_path);

    result.throughput_map = .empty;
    result.latency_map = .empty;
    errdefer deinitMaps(&result.throughput_map, &result.latency_map, allocator);

    while (reader.interface.takeStructPointer(serialization.SectionHeader)) |next_section| {
        const vma = try reader.interface.takeSentinel(0);
        const vma_dupe = try allocator.dupe(u8, vma[0..]);

        switch (next_section.kind) {
            .throughput => {
                const pair = try result.throughput_map.getOrPut(allocator, vma_dupe);
                if (pair.found_existing) allocator.free(vma_dupe) else pair.value_ptr.* = .empty;

                result.throughput_map.lockPointers();
                defer result.throughput_map.unlockPointers();

                try appendThroughputSection(allocator, &reader, pair.value_ptr);
            },
            .latency => {
                allocator.free(vma_dupe);
                return error.UnsupportedSectionKind; // TODO
            },
        }
    } else |err| return if (err == std.Io.Reader.Error.EndOfStream) result else err;
}

fn openFile(path: [:0]const u8) !std.Io.File {
    const rc = std.os.linux.open(path.ptr, .{ .DIRECT = true }, 0);

    return switch (std.os.linux.errno(rc)) {
        .SUCCESS => std.Io.File{ .handle = @intCast(rc), .flags = .{ .nonblocking = false } },
        else => |e| {
            switch (e) {
                .INVAL => return error.BadPathName,
                .ACCES => return error.AccessDenied,
                .FBIG => return error.FileTooBig,
                .OVERFLOW => return error.FileTooBig,
                .ISDIR => return error.IsDir,
                .LOOP => return error.SymLinkLoop,
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NAMETOOLONG => return error.NameTooLong,
                .NFILE => return error.SystemFdQuotaExceeded,
                .NODEV => return error.NoDevice,
                .NOENT => return error.FileNotFound,
                .SRCH => return error.FileNotFound,
                .NOMEM => return error.SystemResources,
                .NOSPC => return error.NoSpaceLeft,
                .NOTDIR => return error.NotDir,
                .PERM => return error.PermissionDenied,
                .EXIST => return error.PathAlreadyExists,
                .BUSY => return error.DeviceBusy,
                .OPNOTSUPP => return error.FileLocksUnsupported,
                .AGAIN => return error.WouldBlock,
                .TXTBSY => return error.FileBusy,
                .NXIO => return error.NoDevice,
                .ILSEQ => return error.BadPathName,
                else => |err| return std.posix.unexpectedErrno(err),
            }
        },
    };
}

fn deinitMaps(throughput_map: *ThroughputMap, latency_map: *LatencyMap, allocator: std.mem.Allocator) void {
    var tp_it = throughput_map.iterator();
    while (tp_it.next()) |ip_map_pair| {
        allocator.free(ip_map_pair.key_ptr.*);
        var ip_it = ip_map_pair.value_ptr.iterator();
        while (ip_it.next()) |record_list| record_list.value_ptr.deinit(allocator);
        ip_map_pair.value_ptr.deinit(allocator);
    }
    throughput_map.deinit(allocator);

    var lat_it = latency_map.iterator();
    while (lat_it.next()) |ip_map_pair| {
        allocator.free(ip_map_pair.key_ptr.*);
        var ip_it = ip_map_pair.value_ptr.iterator();
        while (ip_it.next()) |record_list| record_list.value_ptr.deinit(allocator);
        ip_map_pair.value_ptr.deinit(allocator);
    }
    latency_map.deinit(allocator);
}

fn appendThroughputSection(
    allocator: std.mem.Allocator,
    reader: *std.Io.File.Reader,
    section: *ThroughputIpMap,
) !void {
    var next_record = try reader.interface.takeStructPointer(serialization.record.Throughput);
    while (!next_record.isEmpty()) : (next_record = try reader.interface.takeStructPointer(serialization.record.Throughput)) {
        const slot = try section.getOrPut(allocator, next_record.relative_ip);
        if (!slot.found_existing) slot.value_ptr.* = try .initCapacity(allocator, 10);

        section.lockPointers();
        defer section.unlockPointers();

        try slot.value_ptr.append(allocator, .fromThroughputRecord(next_record.*));
    }
}
