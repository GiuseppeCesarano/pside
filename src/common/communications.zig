const std = @import("std");
const iow = std.os.linux.IOCTL.IOW;

pub const Commands = enum(c_uint) {
    pub const Tag = @typeInfo(Commands).@"enum".tag_type;
    start_profiler = iow('k', 0, Data),
    stop_profiler = iow('k', 1, Data),
    _,
};

pub const vma_name_max_len = std.math.maxInt(u8);

pub const StartOptions = extern struct {
    pid: std.os.linux.pid_t,
    output_fd: std.os.linux.fd_t,
    vma_name: [vma_name_max_len + 1]u8,
    vma_name_len: u8,
    attribute_kernel_samples: bool,

    pub fn init(pid: std.os.linux.pid_t, output_fd: std.os.linux.fd_t, vma_name: []const u8, attribute_kernel_samples: bool) !StartOptions {
        if (vma_name.len > std.math.maxInt(u8)) return error.VmaNameTooLong;

        var start_options: StartOptions = .{
            .pid = pid,
            .output_fd = output_fd,
            .vma_name = undefined,
            .vma_name_len = @intCast(vma_name.len),
            .attribute_kernel_samples = attribute_kernel_samples,
        };
        @memcpy(start_options.vma_name[0..vma_name.len], vma_name);

        return start_options;
    }
};

pub const Data = union {
    start: StartOptions,
    empty: void,
};
