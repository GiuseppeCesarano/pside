// TODO: missing syscalls to cover:

// pthread_kill -> tgkill
//
// sigwait_wait
// sigwaitinfo
// sigtimedwait
// sigsuspend
//
// TODO: remove the thread_wait_count_map .? since they can actually be null
// TODO: create error handling with push queue
const std = @import("std");
const kernel = @import("bindings/kernel.zig");
const thread_safe = @import("thread_safe.zig");

const FProbe = kernel.probe.F;
const FtraceRegs = kernel.probe.FtraceRegs;
const Pid = std.os.linux.pid_t;
const Tid = Pid;
const FutexHandle = usize;
const WaitCounter = usize;

const WaitProbeData = struct {
    wait_debit: WaitCounter,
    futex_hande: FutexHandle,
};

const allocator = kernel.heap.atomic_allocator;

var histrumented_pid: std.atomic.Value(Pid) = .init(0);
var wait_counter: std.atomic.Value(WaitCounter) = .init(0);
var wait_lenght: std.atomic.Value(usize) = .init(0);

var threads_wait_count: thread_safe.SegmentedSparseVector(WaitCounter, std.math.maxInt(WaitCounter)) = .init;
var futex_wakers_wait_count: thread_safe.AddressMap(WaitCounter, std.math.maxInt(WaitCounter)) = .init;

var experiment_has_error: std.atomic.Value(bool) = .init(true);

const filters = [_][:0]const u8{ "kernel_clone", "futex_wait", "futex_wake", "do_exit" };
var probes = [filters.len]FProbe{
    .{ .callbacks = .{ .post_handler = &clone } },
    .{ .callbacks = .{ .pre_handler = &futexWaitStart, .post_handler = &futexWaitEnd }, .entry_data_size = @sizeOf(WaitProbeData) },
    .{ .callbacks = .{ .pre_handler = &futexWake } },
    .{ .callbacks = .{ .pre_handler = &exit } },
};

pub fn init() !void {
    try futex_wakers_wait_count.grow(allocator);
    for (probes[0..], filters) |*probe, filter| {
        probe.register(filter, null) catch {};
    }
}

pub fn start(pid: Pid) void {
    threads_wait_count.put(allocator, @intCast(pid), 0) catch {};
    histrumented_pid.store(pid, .release);
}

pub fn deinit() void {
    threads_wait_count.deinit(allocator);
    futex_wakers_wait_count.deinit(allocator);

    for (probes[0..]) |*probe| {
        probe.unregister();
    }
}

fn profilingLoop() void {
    // while running:
    //     wait_for_points_if_needed()
    //     line = pick_line()
    //     delay = pick_delay()
    //     snapshot_all_points()

    //     experiment_active = true
    //     sleep(experiment_length)
    //     experiment_active = false

    //     compute_deltas()
    //     log_results()
    //     experiment_length = adjust_length(min_delta)
    //     cooldown()
}

fn increment() void {
    const this_thread_wait_count = threads_wait_count.getPtr(@intCast(kernel.current_task.tid()));
    this_thread_wait_count.* += 1;

    _ = wait_counter.cmpxchgStrong(this_thread_wait_count.* - 1, this_thread_wait_count.*, .monotonic, .monotonic);
}

fn not_histrumented() bool {
    return kernel.current_task.pid() != histrumented_pid.load(.monotonic);
}

fn clone(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) void {
    if (not_histrumented()) return;

    const parent_wait_count = threads_wait_count.get(@intCast(kernel.current_task.tid())).?;
    threads_wait_count.put(allocator, @intCast(regs.getReturnValue()), parent_wait_count) catch {};
}

fn futexWaitStart(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1; // returning 1 will cancel futexWaitEnd call

    const data: *WaitProbeData = @ptrCast(@alignCast(data_opaque.?));

    data.wait_debit = wait_counter.load(.monotonic) - threads_wait_count.get(@intCast(kernel.current_task.tid())).?;
    data.futex_hande = regs.getArgument(0); // We save the handle since it gets clobbered

    return 0;
}

fn futexWaitEnd(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) void {
    if (regs.getReturnValue() != 0) return; // Not woke by other threads.

    const data: *WaitProbeData = @ptrCast(@alignCast(data_opaque.?));

    kernel.time.delay.us(data.wait_debit * wait_lenght.load(.monotonic));

    const waker_wait_counter = futex_wakers_wait_count.get(data.futex_hande) orelse {
        @branchHint(.cold);
        experiment_has_error.store(true, .monotonic);
        std.log.err("futexWaitEnd found waker_wait_count empty", .{});
        return;
    };

    threads_wait_count.put(allocator, @intCast(kernel.current_task.tid()), waker_wait_counter) catch {};
}

fn futexWake(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1;

    const tid: usize = @intCast(kernel.current_task.tid());
    const wait_len = wait_lenght.load(.monotonic);

    var credit: WaitCounter = 0;
    var thread_wait_count: ?WaitCounter = threads_wait_count.get(tid);
    while (thread_wait_count == null and credit <= 10) {
        // We may win the race condition against the thread
        // creation in that case let's wait a bit and retry
        // Since we wait, we create some wait credit that we
        // can subtract later.
        @branchHint(.cold);
        kernel.time.delay.us(wait_len);
        credit += 1;
        thread_wait_count = threads_wait_count.get(tid);
    }

    const this_thread_wait_counter = if (thread_wait_count) |twc| twc else {
        @branchHint(.cold);
        experiment_has_error.store(true, .monotonic);
        // TODO: maybe we sould't print from the probe and should use a print error function
        std.log.err("futexWake we could't not recover from race condition, maybe never assigned?", .{});
        return 1;
    };

    futex_wakers_wait_count.put(allocator, regs.getArgument(0), this_thread_wait_counter) catch return 1; //TODO: should signal error;

    const wait_debit = wait_counter.load(.monotonic) - this_thread_wait_counter;
    kernel.time.delay.us(wait_debit * wait_lenght.load(.monotonic));

    return 0;
}

fn exit(_: *FProbe, _: c_ulong, _: c_ulong, _: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1;
    const this_thread_wait_count = threads_wait_count.get(@intCast(kernel.current_task.tid())).?;

    const wait_debit = wait_counter.load(.monotonic) - this_thread_wait_count;
    kernel.time.delay.us(wait_debit * wait_lenght.load(.monotonic));

    return 0;
}
