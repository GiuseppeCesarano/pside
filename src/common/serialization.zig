// TODO: maybe include binary path field in header
// # pside binary format
//
// A .pside file is a fixed Header followed by a flat sequence of self-describing
// frames, read left-to-right until EOF. Every frame carries its own length, so a
// parser can skip any frame — or any record kind — it does not understand.
//
// All multi-byte integers are little-endian. Time fields are microseconds (us)
// unless the field name says otherwise. There are no NUL-terminated strings:
// every string is delimited by its frame length.
//
// ## Header (48 bytes, at offset 0)
//
//   magic        [8]u8   "pside\0\0\0"
//   version      { major:u8, minor:u8 }   reject the file if major differs
//   flags        u16     reserved, zero
//   _            u32     reserved, zero
//   binary_hash  [32]u8  SHA-256 of the profiled binary
//
// ## Payload
//
// Everything after the Header is a sequence of frames. Each frame is:
//
//   payload.Header (8 bytes):
//     tag      u16   frame type (see below)
//     flags    u16   reserved, zero
//     len      u32   payload size in bytes (excludes this header and padding)
//   payload    [len]u8
//   padding    zero bytes up to the next multiple of 8
//
// To walk the file: read a payload.Header, consume `len` payload bytes, then skip
// pad8(len) - len padding bytes to reach the next payload.Header, where
// pad8(n) = (n + 7) & ~7. Stop at EOF. A frame whose header or payload is cut
// short by EOF is a truncated tail (e.g. a recorder that was killed mid-write)
// and should be dropped, not treated as an error.
//
// ### tag = 0  binary_path
//   payload is the absolute path of the profiled binary (no trailing NUL).
//
// ### tag = 1  vma
//   Declares a name for a vma id, so records can reference it compactly.
//     id       u32           payload.VmaId
//     name     [len - 4]u8   region name (no trailing NUL)
//   The same id may be declared more than once (aggregating runs re-emit it);
//   the mapping is idempotent.
//
// ### tag = 2  records
//   A batch of fixed-size measurement records for one (kind, vma).
//
//   payload.records.Header (8 bytes):
//     kind         u16   measurement kind: 0 = throughput, 1 = latency
//     record_size  u16   size in bytes of each record in this frame
//     vma_id       u32   which vma these records belong to (see tag = 1)
//   records      (len - 8) bytes = count records, count = (len - 8) / record_size
//   Records stream in batches: one recording emits many `records` frames for the
//   same (kind, vma) over its lifetime, and aggregating runs append still more.
//
//   record_size keeps records forward-compatible: read the fields you know and
//   skip the remaining (record_size - sizeof(your_struct)) bytes of each record.
//   A reader that does not understand `kind` skips the whole frame via `len`.
//
// #### kind = 0  throughput record (payload.records.Throughput, record_size = 16)
//     relative_ip      u64    sample instruction pointer minus the vma base
//     throughput       f32    progress / virtual-time for this experiment
//     speedup_percent  u8     virtual speedup applied (0..100, step 5)
//     _                [3]u8  padding, zero
//
// ## Versioning
//
// version.major bumps on any change a parser could misread: the header, the frame
// framing, or the meaning of an existing field, reject a file whose major does
// not match. version.minor bumps on additive changes (a new frame tag, a new
// records.Header.Kind, or fields appended to a record with a larger record_size);
// existing parsers skip what they do not know, so the minor is informational.

const std = @import("std");

pub fn pad8(n: usize) usize {
    return std.mem.alignForward(usize, n, 8);
}

pub const speedup_levels_len = 21;
pub const speedup_step_per_level = 5; // 5 * 20 = 100%;

pub const Header = extern struct {
    pub const Version = extern struct {
        major: u8,
        minor: u8,
    };

    pub const Flags = packed struct(u16) {
        _: u16 = 0,
    };

    pub const Hash = [32]u8;

    pub const ReadError = error{NotAPsideFile};

    pub const magic_value: [8]u8 = "pside\x00\x00\x00".*;
    pub const current_version: Version = .{ .major = 0, .minor = 2 };

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

    pub fn matchesCurrent(this: Header) bool {
        return std.mem.eql(u8, &this.magic, &magic_value) and
            this.version.major == current_version.major;
    }

    pub fn read(reader: *std.Io.Reader) ReadError!Header {
        const header = reader.takeStructPointer(Header) catch return ReadError.NotAPsideFile;
        if (!header.matchesCurrent()) return ReadError.NotAPsideFile;

        return header.*;
    }

    pub fn write(this: Header, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(std.mem.asBytes(&this));
    }
};

pub const payload = struct {
    pub const Header = extern struct {
        pub const Tag = enum(u16) {
            binary_path = 0,
            vma = 1,
            records = 2,
            _,
        };

        tag: Tag,
        flags: u16 = 0,
        len: u32,

        fn write(this: payload.Header, w: *std.Io.Writer) std.Io.Writer.Error!void {
            try w.writeAll(std.mem.asBytes(&this));
        }
    };

    pub const VmaId = u32;

    pub const Frame = struct {
        pub const Iterator = struct {
            reader: *std.Io.Reader,

            pub fn init(reader: *std.Io.Reader) Iterator {
                return .{ .reader = reader };
            }

            pub fn next(this: *Iterator) ?Frame {
                const header = this.reader.takeStructPointer(payload.Header) catch return null;
                const tag = header.tag;
                const len = header.len;

                const body = this.reader.take(len) catch return null;
                this.reader.discardAll(pad8(len) - len) catch {};

                return .{ .tag = tag, .body = body };
            }
        };

        tag: payload.Header.Tag,
        body: []const u8,

        pub fn write(this: Frame, w: *std.Io.Writer) std.Io.Writer.Error!void {
            const header: payload.Header = .{ .tag = this.tag, .len = @intCast(this.body.len) };

            try header.write(w);
            try w.writeAll(this.body);
            try writePad(w, this.body.len);
        }
    };

    pub const Vma = struct {
        id: VmaId,
        name: []const u8,

        pub fn decode(body: []const u8) ?Vma {
            if (body.len < @sizeOf(VmaId)) return null;

            return .{
                .id = std.mem.readInt(VmaId, body[0..@sizeOf(VmaId)], .little),
                .name = body[@sizeOf(VmaId)..],
            };
        }

        pub fn write(this: Vma, w: *std.Io.Writer) std.Io.Writer.Error!void {
            const len = @sizeOf(VmaId) + this.name.len;
            const header: payload.Header = .{ .tag = .vma, .len = @intCast(len) };

            try header.write(w);
            try w.writeInt(VmaId, this.id, .little);
            try w.writeAll(this.name);
            try writePad(w, len);
        }
    };

    pub const records = struct {
        pub const Header = extern struct {
            pub const Kind = enum(u16) {
                throughput = 0,
                latency = 1,
                _,
            };

            kind: Kind,
            record_size: u16,
            vma_id: u32,
        };

        pub const Throughput = extern struct {
            relative_ip: u64,
            throughput: f32,
            speedup_percent: u8,
            _: [3]u8 = @splat(0),
        };

        pub const Latency = extern struct {};

        pub const Batch = struct {
            header: records.Header,
            body: []const u8,

            pub fn decode(frame_body: []const u8) ?Batch {
                if (frame_body.len < @sizeOf(records.Header)) return null;

                return .{
                    .header = std.mem.bytesToValue(records.Header, frame_body[0..@sizeOf(records.Header)]),
                    .body = frame_body[@sizeOf(records.Header)..],
                };
            }

            pub fn Iterator(comptime T: type) type {
                return struct {
                    body: []const u8,
                    record_size: u16,
                    offset: usize = 0,

                    pub fn next(this: *@This()) ?T {
                        if (this.offset + this.record_size > this.body.len) return null;
                        defer this.offset += this.record_size;

                        return std.mem.bytesToValue(T, this.body[this.offset..][0..@sizeOf(T)]);
                    }
                };
            }

            pub fn iterate(this: Batch, comptime T: type) ?Iterator(T) {
                if (this.header.record_size < @sizeOf(T)) return null;

                return .{ .body = this.body, .record_size = this.header.record_size };
            }
        };
    };

    fn writePad(w: *std.Io.Writer, len: usize) std.Io.Writer.Error!void {
        const pad = pad8(len) - len;
        if (pad != 0) try w.splatByteAll(0, pad);
    }
};
