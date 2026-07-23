const std = @import("std");

const kernel = @import("kernel");
const allocator = kernel.heap.allocator;
const serialization = @import("serialization");

const DiskWriter = @This();

thread: ?*kernel.Thread,

file: ?*kernel.File,
file_offset: i64,

buffer: []u8,
buffer_begin: std.atomic.Value(usize),
buffer_end: std.atomic.Value(usize),

completion: kernel.Completion,

records_frame: serialization.RecordsFrame,
healthy: bool,

pub const empty: DiskWriter = .{
    .buffer = &.{},
    .buffer_begin = .init(0),
    .buffer_end = .init(0),
    .file_offset = 0,
    .thread = null,
    .file = null,
    .completion = undefined,
    .records_frame = undefined,
    .healthy = true,
};

pub fn deinit(this: *DiskWriter) void {
    if (this.thread == null) return;
    this.completion.signal();
    _ = this.thread.?.stop();
    this.file.?.put();
    allocator.free(this.buffer);
}

pub fn start(
    this: *DiskWriter,
    fd: std.os.linux.fd_t,
    kind: serialization.MeasurementKind,
    record_size: u16,
    vma_id: u32,
) !void {
    if (this.file != null) return;

    const file = kernel.File.get(fd) orelse return error.InvalidFd;
    errdefer file.put();

    this.buffer = try allocator.alloc(u8, std.heap.page_size_min * 6);
    errdefer allocator.free(this.buffer);

    this.completion.init(); // init before thread spawns
    this.file = file;
    this.file_offset = file.size();
    this.records_frame = .{ .kind = kind, .record_size = record_size, .vma_id = vma_id };
    this.healthy = true;
    errdefer this.file = null;

    this.thread = try kernel.Thread.run(writerFn, this, "pside_disk_writer");
}

pub fn push(this: *DiskWriter, record: anytype) !void {
    var total: usize = 0;
    try serialization.flatten(record, sumLen, .{&total});

    const len = this.buffer.len;
    const end = this.buffer_end.load(.monotonic);
    const begin = this.buffer_begin.load(.monotonic);

    const free = if (end >= begin)
        len - (end - begin) - 1
    else
        begin - end - 1;

    if (free < total) return error.Full;

    try serialization.flatten(record, pushBytesUnchecked, .{this});

    if (free - total <= len / 2) this.completion.signal();
}

fn sumLen(total: *usize, bytes: []const u8) !void {
    total.* += bytes.len;
}

fn pushBytesUnchecked(this: *DiskWriter, bytes: []const u8) !void {
    const len = this.buffer.len;
    const end = this.buffer_end.load(.monotonic);

    const tail_space = len - end;
    if (bytes.len <= tail_space) {
        @memcpy(this.buffer[end .. end + bytes.len], bytes);
    } else {
        @memcpy(this.buffer[end..], bytes[0..tail_space]);
        @memcpy(this.buffer[0 .. bytes.len - tail_space], bytes[tail_space..]);
    }

    this.buffer_end.store((end + bytes.len) % len, .release);
}

fn writerFn(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *DiskWriter = @ptrCast(@alignCast(ctx.?));

    while (!kernel.Thread.shouldStop()) {
        this.completion.wait();
        defer this.completion.reinit();

        this.flush();
    }

    return 0;
}

fn writeFull(file: *kernel.File, bytes: []const u8, offset: *i64) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try file.write(bytes[written..], offset);
        if (n == 0) return error.WriteFailed;
        written += n;
    }
}

pub fn flush(this: *DiskWriter) void {
    if (!this.healthy) return;

    const begin = this.buffer_begin.load(.monotonic);
    const end = this.buffer_end.load(.acquire);
    if (begin == end) return;

    const len = this.buffer.len;
    const available = if (end > begin) end - begin else len - begin + end;

    const frame_header: serialization.FrameHeader = .{
        .tag = .records,
        .length = @intCast(@sizeOf(serialization.RecordsFrame) + available),
    };

    this.writeRecordsFrame(frame_header, begin, end, len) catch |err| {
        std.log.err("disk write failed: {s}", .{@errorName(err)});
        this.healthy = false;
        return;
    };

    this.buffer_begin.store(end, .monotonic);
}

fn writeRecordsFrame(this: *DiskWriter, frame_header: serialization.FrameHeader, begin: usize, end: usize, len: usize) !void {
    const file = this.file.?;

    try writeFull(file, std.mem.asBytes(&frame_header), &this.file_offset);
    try writeFull(file, std.mem.asBytes(&this.records_frame), &this.file_offset);

    if (end > begin) {
        try writeFull(file, this.buffer[begin..end], &this.file_offset);
    } else {
        try writeFull(file, this.buffer[begin..len], &this.file_offset);
        try writeFull(file, this.buffer[0..end], &this.file_offset);
    }
}
