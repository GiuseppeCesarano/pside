const std = @import("std");

pub const Commands = enum(u8) {
    pub const Tag = @typeInfo(@This()).@"enum".tag_type;

    start_profiler_on_pid, // followed by std.os.linux.pid_t
    _,
};

pub const Responses = error{
    Ok,
};
pub const ResponsesAsInt = std.meta.Int(.unsigned, @bitSizeOf(Responses));
