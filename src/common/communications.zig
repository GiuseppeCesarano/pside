const std = @import("std");
const iow = std.os.linux.IOCTL.IOW;

pub const Commands = enum(c_uint) {
    pub const Tag = @typeInfo(Commands).@"enum".tag_type;
    start_profiler = iow('k', 0, Data),
    _,
};

pub const vma_name_max_len = 256;

pub const Data = union {
    start: struct {
        pid: std.os.linux.pid_t,
        output_fd: std.os.linux.fd_t,
        vma_name: [vma_name_max_len + 1]u8 = @splat(0),
        vma_name_len: u8,
    },
};
