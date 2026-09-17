const std = @import("std");
const iow = std.os.linux.IOCTL.IOW;

pub const name = "pside";
pub const control_device_path: [:0]const u8 = "/dev/" ++ name;

pub const Commands = enum(c_uint) {
    pub const Tag = @typeInfo(Commands).@"enum".tag_type;
    attach_profiler = iow('k', 0, Data),
    start_profiler = iow('k', 1, Data),
    stop_profiler = iow('k', 2, Data),
    _,
};

pub const vma_name_max_len = std.math.maxInt(u8) + 1;

pub const AttachOptions = extern struct {
    pid: std.os.linux.pid_t,
    vma_name: [vma_name_max_len]u8,
    vma_name_len: u8,
    attribute_kernel_samples: bool,

    pub const InitError = error{
        VmaNameTooLong,
    };

    pub fn vmaNameFits(vma_name: []const u8) bool {
        return vma_name.len <= std.math.maxInt(u8);
    }

    pub fn init(pid: std.os.linux.pid_t, vma_name: []const u8, attribute_kernel_samples: bool) InitError!AttachOptions {
        if (!vmaNameFits(vma_name)) return InitError.VmaNameTooLong;

        var attach_options: AttachOptions = .{
            .pid = pid,
            .vma_name = undefined,
            .vma_name_len = @intCast(vma_name.len),
            .attribute_kernel_samples = attribute_kernel_samples,
        };
        @memcpy(attach_options.vma_name[0..vma_name.len], vma_name);

        return attach_options;
    }
};

pub const StartOptions = extern struct {
    output_fd: std.os.linux.fd_t,
};

pub const Data = union {
    attach: AttachOptions,
    start: StartOptions,
    empty: void,
};
