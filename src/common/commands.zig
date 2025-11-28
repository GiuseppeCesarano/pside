const std = @import("std");

// This file defines how the cli tool sends commands to the
// kernel module
//
// in general, the cli tool will send the following tagged
// union to the kernel module's chardev.
//
// The cli tool may also send additional data afther the
// union in case the size of the data is variable, for
// example strings. If this is the case, the union must
// contain a field that rappresents such data, this field
// must be of type usize and it must contain the length of
// the of the sent data.
//
// If more then one variable lenght field must be sent,
// the command corresponding union type must reflect that
// having one usize field per varible data sent.

pub const Tag = enum {
    set_pid_for_filter,
    load_benchmark_probe,
    load_mutex_probe,
    load_function_probe,
    load_disk_probes,
    load_network_probes,
    unload_probes,
};

pub const ProbeData = struct {
    path_len: usize,
    offset: usize,
};

pub const Data = union(Tag) {
    set_pid_for_filter: std.os.linux.pid_t,
    load_benchmark_probe: ProbeData,
    load_mutex_probe: ProbeData,
    load_function_probe: ProbeData,
    load_disk_probes: void,
    load_network_probes: void,
    unload_probes: void,
};
