// # pside binary format
//
// All multi-byte integers are little-endian.
// The default unit for time fields is microseconds (us) unless the field name says otherwise.
// Strings are null-terminated and not included in any fixed-size struct.
//
// ## Layout
//
// [Header]                    -- magic "pside" + version
// [FileInfo]                  -- SHA-256 hash of the profiled binary
// <binary_path>\0             -- null-terminated path string
//
// Repeated until EOF:
//   [SectionHeader]              -- measurement kind
//   <vma_target>\0               -- null-terminated VMA region name
//   [record.Throughput] ...      -- if kind == .throughput, terminated by record.Throughput.empty
//   [record.Latency]    ...      -- if kind == .latency,    terminated by record.Latency.empty
//
// A sentinel (all-zero record) marks the end of each section's record list.
// Parsers stop reading records upon encountering it and expect either another
// SectionHeader or EOF immediately after.
//
// Versioning
//
// version.major bumps on breaking format changes (field removed, reordered, resized).
// version.minor bumps on additive changes (new MeasurementKind, new field appended to a record).
// Parsers should reject files where major != their own known major.
// TODO: handle endianness

const std = @import("std");

pub const Header = extern struct {
    pub const Version = extern struct {
        major: u8,
        minor: u8,
        _: u8 = 0,
    };

    magic: [5]u8,
    version: Version,

    pub const default: Header = .{
        .magic = "pside".*,
        .version = .{ .major = 0, .minor = 0 },
    };
};

pub const FileInfo = extern struct {
    hash: [32]u8,
    // binary_path: [:0]u8
};

pub const SectionHeader = extern struct {
    pub const MeasurementKind = enum(u8) {
        throughput = 0,
        latency = 1,
    };

    kind: MeasurementKind,
    // vma_name: [:0]u8
};

pub const record = struct {
    pub const Throughput = extern struct {
        relative_ip: u64,
        progress_delta: u64,
        wall: u64,
        injected_delay: u64,
        delay_per_tick: u16,
        _: [6]u8 = .{0} ** 6,

        pub const empty = std.mem.zeroes(Throughput);
    };

    pub const Latency = extern struct {
        // Later
    };
};
