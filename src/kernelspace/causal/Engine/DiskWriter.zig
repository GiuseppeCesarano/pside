const std = @import("std");

const kernel = @import("kernel");
const allocator = kernel.heap.allocator;
const serialization = @import("serialization");
const payload = serialization.payload;

const DiskWriter = @This();

thread: ?*kernel.Thread,

file: ?*kernel.File,
file_offset: i64,

buffer: []u8,
buffer_begin: std.atomic.Value(usize),
buffer_end: std.atomic.Value(usize),

completion: kernel.Completion,

records_header: payload.records.Header,
healthy: bool,

pub const empty: DiskWriter = .{
    .buffer = &.{},
    .buffer_begin = .init(0),
    .buffer_end = .init(0),
    .file_offset = 0,
    .thread = null,
    .file = null,
    .completion = undefined,
    .records_header = undefined,
    .healthy = true,
};

pub fn start(
    this: *DiskWriter,
    fd: std.os.linux.fd_t,
    kind: payload.records.Header.Kind,
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
    this.records_header = .{ .kind = kind, .record_size = record_size, .vma_id = vma_id };
    this.healthy = true;
    errdefer this.file = null;

    this.thread = try kernel.Thread.run(writerFn, this, "pside_disk_writer");
}

pub fn deinit(this: *DiskWriter) void {
    if (this.thread == null) return;
    this.completion.signal();
    _ = this.thread.?.stop();
    this.file.?.put();
    allocator.free(this.buffer);
}

pub fn push(this: *DiskWriter, record: anytype) !void {
    const bytes = std.mem.asBytes(&record);

    const len = this.buffer.len;
    const end = this.buffer_end.load(.monotonic);
    const begin = this.buffer_begin.load(.monotonic);

    const free = if (end >= begin)
        len - (end - begin) - 1
    else
        begin - end - 1;

    if (free < bytes.len) return error.Full;

    this.pushBytesUnchecked(bytes);

    if (free - bytes.len <= len / 2) this.completion.signal();
}

fn pushBytesUnchecked(this: *DiskWriter, bytes: []const u8) void {
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
        _ = this.completion.timedWait(100);
        this.completion.reinit();

        this.flush();
    }

    this.flush();
    return 0;
}

pub fn flush(this: *DiskWriter) void {
    if (!this.healthy) return;

    const begin = this.buffer_begin.load(.monotonic);
    const end = this.buffer_end.load(.acquire);
    if (begin == end) return;

    const len = this.buffer.len;
    const available = if (end > begin) end - begin else len - begin + end;

    const payload_header: payload.Header = .{
        .tag = .records,
        .len = @intCast(@sizeOf(payload.records.Header) + available),
    };

    this.writeRecordsFrame(payload_header, begin, end, len) catch |err| {
        std.log.err("disk write failed: {s}", .{@errorName(err)});
        this.healthy = false;
        return;
    };

    this.buffer_begin.store(end, .monotonic);
}

fn writeRecordsFrame(this: *DiskWriter, payload_header: payload.Header, begin: usize, end: usize, len: usize) !void {
    const file = this.file.?;

    try file.writeAll(std.mem.asBytes(&payload_header), &this.file_offset);
    try file.writeAll(std.mem.asBytes(&this.records_header), &this.file_offset);

    if (end > begin) {
        try file.writeAll(this.buffer[begin..end], &this.file_offset);
    } else {
        try file.writeAll(this.buffer[begin..len], &this.file_offset);
        try file.writeAll(this.buffer[0..end], &this.file_offset);
    }

    const padding: [8]u8 = @splat(0);
    const pad = serialization.pad8(payload_header.len) - payload_header.len;
    if (pad != 0) try file.writeAll(padding[0..pad], &this.file_offset);
}
