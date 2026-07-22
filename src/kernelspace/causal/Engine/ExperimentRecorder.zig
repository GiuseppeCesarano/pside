const std = @import("std");

const kernel = @import("kernel");
const serialization = @import("serialization");

const DiskWriter = @import("DiskWriter.zig");

const ExperimentRecorder = @This();

const flush_retry_count = 3;
const flush_retry_delay_us = 50;

pub const Reading = struct {
    progress: usize,
    vclock: u64,
    time_us: u64,
};

disk_writer: DiskWriter,

pub const empty: ExperimentRecorder = .{ .disk_writer = .empty };

pub fn deinit(this: *ExperimentRecorder) void {
    this.disk_writer.deinit();
}

pub fn start(this: *ExperimentRecorder, fd: std.os.linux.fd_t, vma_name: [:0]const u8) !void {
    try this.disk_writer.start(fd);
    try this.disk_writer.push(.{
        serialization.SectionHeader{ .kind = .throughput },
        vma_name[0 .. vma_name.len + 1],
    });
}

pub fn recordThroughput(
    this: *ExperimentRecorder,
    base: Reading,
    end: Reading,
    delay_per_tick: u16,
    relative_ip: usize,
    speedup_percent: u16,
) !void {
    const wall = end.time_us - base.time_us;
    const injected_delay = (end.vclock - base.vclock) * delay_per_tick;

    const progress_delta: f32 = @floatFromInt(end.progress -% base.progress);
    const virtual_time: f32 = @floatFromInt(wall - injected_delay);

    try this.disk_writer.push(serialization.record.Throughput{
        .relative_ip = relative_ip,
        .throughput = progress_delta / virtual_time,
        .speedup_percent = @truncate(speedup_percent),
    });
}

pub fn finish(this: *ExperimentRecorder) !void {
    for (0..flush_retry_count) |_| {
        this.disk_writer.push(serialization.record.Throughput.empty) catch {
            kernel.time.sleep.us(flush_retry_delay_us);
            continue;
        };
        return;
    }
    // Last attempt: let the error surface so the engine can flag the file.
    try this.disk_writer.push(serialization.record.Throughput.empty);
}
