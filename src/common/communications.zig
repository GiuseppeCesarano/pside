const std = @import("std");

const iow = std.os.linux.IOCTL.IOW;

pub const Commands = enum(c_uint) {
    pub const Tag = @typeInfo(@This()).@"enum".tag_type;

    start_profiler = iow('k', 0, Data),
    _,
};

pub const Data = union {
    pid: std.os.linux.pid_t,
};
