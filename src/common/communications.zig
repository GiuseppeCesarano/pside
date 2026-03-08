const std = @import("std");

const iow = std.os.linux.IOCTL.IOW;

pub const Commands = enum(c_uint) {
    pub const Tag = @typeInfo(Commands).@"enum".tag_type;
    start_profiler = iow('k', 0, Data),
    _,
};

pub const Data = union {
    start: struct {
        pid: std.os.linux.pid_t,
        output_fd: std.os.linux.fd_t,
    },
};

pub const ThroughputRecord = extern struct {
    ip: u64,
    prog_delta: u64,
    wall: u64,
    total_delay: u64,
    delay_per_tick: u16,
    _pad: [6]u8 = .{0} ** 6,
};
