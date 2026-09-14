// TODO: maybe include binary path field in header
// # pside binary format
//
// A .pside file is a fixed Header followed by a flat sequence of self-describing
// frames, read left-to-right until EOF. Every frame carries its own length, so a
// parser can skip any frame, or any record kind, it does not understand.
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
    pub const default_vma_id: VmaId = 0;

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
            vma_id: VmaId,
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

fn writeBatch(w: *std.Io.Writer, header: payload.records.Header, body: []const u8) std.Io.Writer.Error!void {
    const frame_header: payload.Header = .{
        .tag = .records,
        .len = @intCast(@sizeOf(payload.records.Header) + body.len),
    };

    try frame_header.write(w);
    try w.writeAll(std.mem.asBytes(&header));
    try w.writeAll(body);
    try payload.writePad(w, frame_header.len);
}

test "pad8 rounds a length up to the next multiple of eight" {
    const cases = [_]struct { len: usize, padded: usize }{
        .{ .len = 0, .padded = 0 },
        .{ .len = 1, .padded = 8 },
        .{ .len = 7, .padded = 8 },
        .{ .len = 8, .padded = 8 },
        .{ .len = 9, .padded = 16 },
        .{ .len = 16, .padded = 16 },
    };

    for (cases) |check| try std.testing.expectEqual(check.padded, pad8(check.len));
}

test "a file header round trips and nothing else is accepted as one" {
    var buffer: [@sizeOf(Header)]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const hash: Header.Hash = @splat(0xab);
    const header: Header = .init(hash);
    try header.write(&writer);

    try std.testing.expectEqual(@as(usize, 48), writer.buffered().len);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const read = try Header.read(&reader);

    try std.testing.expectEqualSlices(u8, &hash, &read.binary_hash);
    try std.testing.expectEqual(Header.current_version.major, read.version.major);
    try std.testing.expectEqual(Header.current_version.minor, read.version.minor);

    var wrong_magic = buffer;
    wrong_magic[0] = 'P';
    var magic_reader: std.Io.Reader = .fixed(&wrong_magic);
    try std.testing.expectError(Header.ReadError.NotAPsideFile, Header.read(&magic_reader));

    var wrong_major = buffer;
    wrong_major[8] +%= 1;
    var major_reader: std.Io.Reader = .fixed(&wrong_major);
    try std.testing.expectError(Header.ReadError.NotAPsideFile, Header.read(&major_reader));

    var truncated: std.Io.Reader = .fixed(buffer[0 .. @sizeOf(Header) - 1]);
    try std.testing.expectError(Header.ReadError.NotAPsideFile, Header.read(&truncated));
}

test "binary_path and vma frames round trip through the iterator" {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const binary_path: payload.Frame = .{ .tag = .binary_path, .body = "/usr/bin/toy" };
    const vma: payload.Vma = .{ .id = 7, .name = "libfoo.so.1" };

    try binary_path.write(&writer);
    try vma.write(&writer);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    var frames: payload.Frame.Iterator = .init(&reader);

    const first = frames.next().?;
    try std.testing.expectEqual(payload.Header.Tag.binary_path, first.tag);
    try std.testing.expectEqualStrings("/usr/bin/toy", first.body);

    const second = frames.next().?;
    try std.testing.expectEqual(payload.Header.Tag.vma, second.tag);

    const decoded = payload.Vma.decode(second.body).?;
    try std.testing.expectEqual(@as(payload.VmaId, 7), decoded.id);
    try std.testing.expectEqualStrings("libfoo.so.1", decoded.name);

    try std.testing.expect(frames.next() == null);
    try std.testing.expect(payload.Vma.decode(second.body[0..3]) == null);
}

test "an odd length body is padded with zeros and the walk steps over them" {
    var buffer: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const odd: payload.Frame = .{ .tag = .binary_path, .body = "odd" };
    const next: payload.Frame = .{ .tag = .binary_path, .body = "after" };

    try odd.write(&writer);
    try next.write(&writer);

    const written = writer.buffered();
    const header_len = @sizeOf(payload.Header);

    try std.testing.expectEqual(2 * (header_len + pad8(3)), written.len);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0 }, written[header_len + 3 .. header_len + pad8(3)]);

    var reader: std.Io.Reader = .fixed(written);
    var frames: payload.Frame.Iterator = .init(&reader);

    try std.testing.expectEqualStrings("odd", frames.next().?.body);
    try std.testing.expectEqualStrings("after", frames.next().?.body);
    try std.testing.expect(frames.next() == null);
}

test "a throughput batch round trips with its kind and vma" {
    const samples = [_]payload.records.Throughput{
        .{ .relative_ip = 0x6b8, .throughput = 0.5, .speedup_percent = 0 },
        .{ .relative_ip = 0x6b4, .throughput = 0.25, .speedup_percent = 45 },
    };

    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writeBatch(&writer, .{ .kind = .throughput, .record_size = @sizeOf(payload.records.Throughput), .vma_id = 3 }, std.mem.sliceAsBytes(samples[0..]));

    var reader: std.Io.Reader = .fixed(writer.buffered());
    var frames: payload.Frame.Iterator = .init(&reader);

    const frame = frames.next().?;
    try std.testing.expectEqual(payload.Header.Tag.records, frame.tag);

    const batch = payload.records.Batch.decode(frame.body).?;
    try std.testing.expectEqual(payload.records.Header.Kind.throughput, batch.header.kind);
    try std.testing.expectEqual(@as(payload.VmaId, 3), batch.header.vma_id);

    var read_samples = batch.iterate(payload.records.Throughput).?;
    for (samples) |expected| {
        const actual = read_samples.next().?;

        try std.testing.expectEqual(expected.relative_ip, actual.relative_ip);
        try std.testing.expectEqual(expected.throughput, actual.throughput);
        try std.testing.expectEqual(expected.speedup_percent, actual.speedup_percent);
    }

    try std.testing.expect(read_samples.next() == null);
    try std.testing.expect(payload.records.Batch.decode(frame.body[0..4]) == null);
}

test "a record grown by a later writer is still readable, a shrunk one is refused" {
    const Wide = extern struct {
        base: payload.records.Throughput,
        added: u64,
    };

    const wide = [_]Wide{
        .{ .base = .{ .relative_ip = 0x10, .throughput = 1.0, .speedup_percent = 5 }, .added = 0xfeed },
        .{ .base = .{ .relative_ip = 0x20, .throughput = 2.0, .speedup_percent = 10 }, .added = 0xbeef },
    };

    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writeBatch(&writer, .{ .kind = .throughput, .record_size = @sizeOf(Wide), .vma_id = 0 }, std.mem.sliceAsBytes(wide[0..]));

    var reader: std.Io.Reader = .fixed(writer.buffered());
    var frames: payload.Frame.Iterator = .init(&reader);
    const batch = payload.records.Batch.decode(frames.next().?.body).?;

    var read_samples = batch.iterate(payload.records.Throughput).?;
    for (wide) |expected| {
        const actual = read_samples.next().?;

        try std.testing.expectEqual(expected.base.relative_ip, actual.relative_ip);
        try std.testing.expectEqual(expected.base.speedup_percent, actual.speedup_percent);
    }
    try std.testing.expect(read_samples.next() == null);

    const shrunk: payload.records.Batch = .{
        .header = .{ .kind = .throughput, .record_size = @sizeOf(payload.records.Throughput) - 1, .vma_id = 0 },
        .body = batch.body,
    };
    try std.testing.expect(shrunk.iterate(payload.records.Throughput) == null);
}

test "a frame cut short by EOF ends the walk instead of erroring" {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const whole: payload.Frame = .{ .tag = .binary_path, .body = "/usr/bin/toy" };
    const cut: payload.Frame = .{ .tag = .vma, .body = "this one never finished" };

    try whole.write(&writer);
    const whole_len = writer.buffered().len;
    try cut.write(&writer);

    for ([_]usize{ 0, 1, @sizeOf(payload.Header), @sizeOf(payload.Header) + 4 }) |kept| {
        var reader: std.Io.Reader = .fixed(writer.buffered()[0 .. whole_len + kept]);
        var frames: payload.Frame.Iterator = .init(&reader);

        try std.testing.expectEqualStrings("/usr/bin/toy", frames.next().?.body);
        try std.testing.expect(frames.next() == null);
    }
}
