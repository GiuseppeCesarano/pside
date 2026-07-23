// # pside binary format
//
// A .pside file is a fixed Header followed by a flat sequence of self-describing
// frames, read left-to-right until EOF. Every frame carries its own length, so a
// parser can skip any frame — or any record kind — it does not understand; this
// is what lets new measurement kinds be added without breaking old readers.
//
// All multi-byte integers are little-endian. Time fields are microseconds (us)
// unless the field name says otherwise. There are no NUL-terminated strings:
// every string is delimited by its frame length.
//
// ## Header (48 bytes, at offset 0)
//
//   magic        [8]u8   "pside\0\0\0"
//   version      { major:u8, minor:u8 }   reject the file if major differs
//   flags        u16     bit 0 = big-endian payloads (currently always 0)
//   _            u32     reserved, zero
//   binary_hash  [32]u8  SHA-256 of the profiled binary
//
// ## Frames
//
// Everything after the Header is a sequence of frames. Each frame is:
//
//   FrameHeader (8 bytes):
//     tag      u16   frame type (see below)
//     flags    u16   reserved, zero
//     length   u32   payload size in bytes (excludes this header and padding)
//   payload    [length]u8
//   padding    zero bytes up to the next multiple of 8
//
// To walk the file: read a FrameHeader, consume `length` payload bytes, then skip
// pad8(length) - length padding bytes to reach the next FrameHeader, where
// pad8(n) = (n + 7) & ~7. Stop at EOF. A frame whose header or payload is cut
// short by EOF is a truncated tail (e.g. a recorder that was killed mid-write)
// and should be dropped, not treated as an error.
//
// An unknown `tag` is skipped via `length`; keep going.
//
// ### tag = 0  binary_path
//   payload is the absolute path of the profiled binary (no trailing NUL).
//
// ### tag = 1  vma
//   Declares a name for a vma id, so records can reference it compactly.
//     vma_id   u32
//     name     [length - 4]u8   region name (no trailing NUL)
//   The same id may be declared more than once (aggregating runs re-emit it);
//   the mapping is idempotent.
//
// ### tag = 2  records
//   A batch of fixed-size measurement records for one (kind, vma).
//     kind         u16   measurement kind: 0 = throughput, 1 = latency
//     record_size  u16   size in bytes of each record in this frame
//     vma_id       u32   which vma these records belong to (see tag = 1)
//     records      (length - 8) bytes = count records, count = (length - 8) / record_size
//   Records stream in batches: one recording emits many `records` frames for the
//   same (kind, vma) over its lifetime, and aggregating runs append still more.
//
//   record_size keeps records forward-compatible: read the fields you know and
//   skip the remaining (record_size - sizeof(your_struct)) bytes of each record.
//   A reader that does not understand `kind` skips the whole frame via `length`.
//
// #### kind = 0  throughput record (record_size = 16)
//     relative_ip      u64    sample instruction pointer minus the vma base
//     throughput       f32    progress / virtual-time for this experiment
//     speedup_percent  u8     virtual speedup applied (0..100, step 5)
//     _                [3]u8  padding, zero
//
// ## Versioning
//
// version.major bumps on any change a parser could misread: the header, the frame
// framing, or the meaning of an existing field — reject a file whose major does
// not match. version.minor bumps on additive changes (a new frame tag, a new
// MeasurementKind, or fields appended to a record with a larger record_size);
// existing parsers skip what they do not know, so the minor is informational.

const std = @import("std");

pub fn flatten(value: anytype, comptime cb: anytype, args: anytype) !void {
    const type_info = @typeInfo(@TypeOf(value));
    if (type_info == .@"struct" and type_info.@"struct".is_tuple) {
        inline for (value) |field| try flatten(field, cb, args);
        return;
    }

    const bytes = if (@TypeOf(value) == []const u8) value else std.mem.asBytes(&value);
    try @call(.auto, cb, args ++ .{bytes});
}

pub fn pad8(n: usize) usize {
    return (n + 7) & ~@as(usize, 7);
}

pub const Hash = [32]u8;

pub const Header = extern struct {
    pub const magic_value: [8]u8 = "pside\x00\x00\x00".*;

    pub const Version = extern struct {
        major: u8,
        minor: u8,
    };

    pub const current_version: Version = .{ .major = 0, .minor = 1 };

    pub const Flags = packed struct(u16) {
        big_endian: bool = false,
        _: u15 = 0,
    };

    magic: [8]u8,
    version: Version,
    flags: Flags,
    _: u32 = 0,
    binary_hash: Hash,

    pub fn init(binary_hash: Hash) Header {
        return .{
            .magic = magic_value,
            .version = current_version,
            .flags = .{},
            .binary_hash = binary_hash,
        };
    }

    pub fn isValid(this: Header) bool {
        return std.mem.eql(u8, &this.magic, &magic_value) and this.version.major == current_version.major;
    }
};

pub const Tag = enum(u16) {
    binary_path = 0,
    vma = 1,
    records = 2,
    _,
};

pub const FrameHeader = extern struct {
    tag: Tag,
    flags: u16 = 0,
    length: u32,
};

pub const VmaFrame = extern struct {
    vma_id: u32,
};

pub const MeasurementKind = enum(u16) {
    throughput = 0,
    latency = 1,
    _,
};

pub const RecordsFrame = extern struct {
    kind: MeasurementKind,
    record_size: u16,
    vma_id: u32,
};

pub const record = struct {
    pub const Throughput = extern struct {
        relative_ip: u64,
        throughput: f32,
        speedup_percent: u8,
        _: [3]u8 = @splat(0),
    };

    pub const Latency = extern struct {};
};
