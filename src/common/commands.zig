const std = @import("std");

// This is the list of the supported commands by the kernel
// module. To send a command, the cli tool needs to write in the
// chardev the enum followed by the rest of the necessary info.
//
// Moreover, the command with all it's parts must be sent by a
// single systemcall write since the kernel module always reads
// the whole buffer and treats it as a single command.

pub const Tag = enum(u8) {
    set_pid_for_filter, //   followed by std.os.linux.pid_t

    load_benchmark_probe, // followed by usize, [:0]const u8

    load_mutex_probe, //     followed by usize, [:0]const u8
    load_function_probe, //  followed by usize, [:0]const u8

    load_disk_probes,
    load_network_probes,

    unload_probes,
};
