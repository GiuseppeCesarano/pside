const std = @import("std");

const safety = @import("safety");
const serialization = @import("serialization");
const payload = serialization.payload;
const Throughput = payload.records.Throughput;

const Sink = @This();

file_writer: std.Io.File.Writer,
queue: std.Io.Queue(Throughput),
queue_buffer: [records_per_frame]Throughput,
batch: [records_per_frame]Throughput,
writer: ?std.Io.Future(WriteError!void),
address: safety.Pinned,

pub const StartError = std.Io.File.LengthError || std.Io.File.SeekError || std.Io.ConcurrentError;
pub const Error = std.Io.QueueClosedError || std.Io.Cancelable;
const WriteError = std.Io.Writer.Error;

const records_per_frame = 64;
const records_header: payload.records.Header = .{
    .kind = .throughput,
    .record_size = @sizeOf(Throughput),
    .vma_id = payload.default_vma_id,
};

pub const empty: Sink = .{
    .file_writer = undefined,
    .queue = undefined,
    .queue_buffer = undefined,
    .batch = undefined,
    .writer = null,
    .address = .unbound,
};

pub fn deinit(this: *Sink, io: std.Io) void {
    this.stop(io);
    this.* = undefined;
}

pub fn stop(this: *Sink, io: std.Io) void {
    this.address.assertCurrentIfBound();

    const writer = if (this.writer) |*w| w else return;

    this.queue.close(io);
    writer.await(io) catch |err| std.log.err("Writing records failed: {s}", .{@errorName(err)});
    this.file_writer.file.close(io);

    this.writer = null;
}

pub fn start(this: *Sink, io: std.Io, file: std.Io.File) StartError!void {
    errdefer file.close(io);
    std.debug.assert(this.writer == null);
    this.address.bind();

    this.file_writer = .init(file, io, &.{});
    try this.file_writer.seekToUnbuffered(try file.length(io));

    this.queue = .init(&this.queue_buffer);
    this.writer = try io.concurrent(writeLoop, .{ this, io });
}

pub fn recordThroughput(
    this: *Sink,
    io: std.Io,
    relative_ip: usize,
    progress_delta: u64,
    time_delta: std.Io.Duration,
    injected_us: u32,
    speedup_percent: u8,
) Error!void {
    this.address.assertCurrent();

    try this.queue.putOne(io, .{
        .relative_ip = relative_ip,
        .progress_delta = progress_delta,
        .time_delta_us = @intCast(time_delta.toMicroseconds()),
        .injected_us = injected_us,
        .speedup_percent = speedup_percent,
    });
}

fn writeLoop(this: *Sink, io: std.Io) WriteError!void {
    while (this.queue.getUncancelable(io, &this.batch, this.batch.len)) |len| {
        try serialization.writeBatch(&this.file_writer.interface, records_header, std.mem.sliceAsBytes(this.batch[0..len]));
    } else |_| {}
}
