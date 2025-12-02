const std = @import("std");

// TODO: consider decuppling uprobes and kprobes registration.

// This is the list of the supported commands by the kernel
// module. To send a command, the cli tool needs to write in the
// chardev the enum followed by the rest of the necessary info.
//
// Moreover, the command with all it's parts must be sent by a
// single systemcall write since the kernel module always reads
// the whole buffer and treats it as a single command.

// send_*_probe will precede specific probe data, if the probes
// are currently registered (active) the sent probe will be also
// registered.

// register_probes will register all the sent probes

// register_*_probes will register probes that are already known
// so no specific info about them is required.

// unregister_probes will unregister (deactivate) all the probes.
// This doens't clean the probe array, and thay can be registered
// again with register_probes.

// clear_probes will clear the probe array, if the probes are
// registered it will also unregister them.

pub const Tag = enum(u8) {
    set_pid_for_filter, //   followed by std.os.linux.pid_t

    send_benchmark_probe, // followed by usize, [:0]const u8

    send_mutex_probe, //     followed by usize, [:0]const u8
    send_function_probe, //  followed by usize, [:0]const u8

    register_disk_probes,
    register_network_probes,

    register_probes,
    unregister_probes,
    clear_probes,
};
