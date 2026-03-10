const std = @import("std");
const kernel = @import("kernel");
const allocator = kernel.heap.allocator;

const DiskWriter = @This();

thread: ?*kernel.Thread,

file: ?*kernel.File,
file_offset: i64,

buffer: []u8,
buffer_begin: std.atomic.Value(usize),
buffer_end: std.atomic.Value(usize),

completion: kernel.Completion,

pub fn init() !DiskWriter {
    const buffer = try allocator.alloc(u8, std.heap.page_size_min * 6);
    errdefer allocator.free(buffer);

    return .{
        .buffer = buffer,
        .buffer_begin = .init(0),
        .buffer_end = .init(0),
        .file_offset = 0,
        .thread = null,
        .file = null,
        .completion = undefined,
    };
}

pub fn deinit(this: *DiskWriter) void {
    if (this.thread == null) return;
    this.completion.signal();
    this.thread.?.stop();
    this.file.?.put();
    allocator.free(this.buffer);
}

pub fn start(this: *DiskWriter, fd: std.os.linux.fd_t) void {
    if (this.file != null) return;

    this.completion.init(); // init before thread spawns
    this.file = .get(fd);
    this.file_offset = this.file.?.size();
    this.thread = .run(writerFn, this, "pside_disk_writer");
}

pub fn push(this: *DiskWriter, record: anytype) !void {
    const bytes = std.mem.asBytes(&record);
    const len = this.buffer.len;
    const end = this.buffer_end.load(.monotonic);
    const begin = this.buffer_begin.load(.acquire);

    const free = if (end >= begin)
        len - (end - begin) - 1
    else
        begin - end - 1;

    if (free < bytes.len) return error.Full;

    const tail_space = len - end;
    if (bytes.len <= tail_space) {
        @memcpy(this.buffer[end .. end + bytes.len], bytes);
    } else {
        @memcpy(this.buffer[end..], bytes[0..tail_space]);
        @memcpy(this.buffer[0 .. bytes.len - tail_space], bytes[tail_space..]);
    }

    this.buffer_end.store((end + bytes.len) % len, .release);

    if (free <= len / 2) this.completion.signal();
}

fn writerFn(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *DiskWriter = @ptrCast(@alignCast(ctx.?));

    while (!kernel.Thread.shouldThisStop()) {
        this.completion.wait();
        defer this.completion.reinit();

        this.flush();
    }

    return 0;
}

pub fn flush(this: *DiskWriter) void {
    const begin = this.buffer_begin.load(.monotonic);
    const end = this.buffer_end.load(.acquire);
    if (begin == end) return;

    const len = this.buffer.len;

    if (end > begin) {
        _ = this.file.?.write(this.buffer[begin..end], &this.file_offset);
    } else {
        const tail = this.buffer[begin..len];
        const head = this.buffer[0..end];

        _ = this.file.?.write(tail, &this.file_offset);
        _ = this.file.?.write(head, &this.file_offset);
    }

    this.buffer_begin.store(end, .monotonic);
}
