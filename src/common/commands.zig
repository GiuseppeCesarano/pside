const std = @import("std");

// This file defines how the cli tool sends commands to the
// kernel module
//
// in general, the cli tool will send the following tagged
// union to the kernel module's chardev.
//
// The cli tool may also send additional data afther the
// union for example strings. 

pub const Tag = enum {
    set_pid_for_filter,

    load_benchmark_probe,

    load_mutex_probe,
    load_function_probe,

    load_disk_probes,
    load_network_probes,

    unload_probes,
};

pub const Data = union(Tag) {
    set_pid_for_filter: std.os.linux.pid_t,

    load_benchmark_probe: usize,

    load_mutex_probe: usize,
    load_function_probe: usize,

    load_disk_probes: void,
    load_network_probes: void,

    unload_probes: void,
};
