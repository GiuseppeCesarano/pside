// TODO: missing syscalls to cover:
// pthread_kill -> tgkill
//
// sigwait_wait
// sigwaitinfo
// sigtimedwait
// sigsuspend
//
// TODO: remove the thread_wait_count_map .? since they can actually be null
// TODO: Check if the normal kernel.heap.allocator is fine to be used in the probes (may return in_atomic() == true)
const std = @import("std");
const kernel = @import("bindings/kernel.zig");
const ThreadSafeMap = @import("thread_safe_map.zig").ThreadSafeMap;

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

const allocator = kernel.heap.allocator;

var histrumented_pid: std.atomic.Value(Pid) = .init(0);
var wait_counter: std.atomic.Value(WaitCounter) = .init(0);
var wait_lenght: std.atomic.Value(usize) = .init(0);

var threads_wait_count: ThreadSafeMap(Tid, WaitCounter) = undefined;
var futex_wakers_wait_count: ThreadSafeMap(FutexHandle, WaitCounter) = undefined;

const filters = [_][:0]const u8{ "kernel_clone", "futex_wait", "futex_wake", "do_exit" };
var probes = [filters.len]FProbe{
    .{ .callbacks = .{ .post_handler = &addThread } },
    .{ .callbacks = .{ .pre_handler = &futexWaitStart, .post_handler = &futexWaitEnd }, .entry_data_size = @sizeOf(WaitProbeData) },
    .{ .callbacks = .{ .pre_handler = &futexWake } },
    .{ .callbacks = .{ .pre_handler = &exit } },
};

pub fn init() !void {
    threads_wait_count = try .init(allocator, 128);
    futex_wakers_wait_count = try .init(allocator, 128);

    for (probes[0..], filters) |*probe, filter| {
        try probe.register(filter, null);
    }
}

pub fn start(pid: Pid) void {
    futex_wakers_wait_count.clear();

    threads_wait_count.clear();
    threads_wait_count.putAssumeCapacity(pid, 0);

    // TODO: maybe clear the WaitCounter?

    histrumented_pid.store(pid, .release);
}

pub fn deinit() void {
    threads_wait_count.deinit(allocator);
    futex_wakers_wait_count.deinit(allocator);

    for (probes[0..]) |*probe| {
        probe.unregister();
    }
}

fn increment() void {
    const this_thread_wait_count = threads_wait_count.getPtr(kernel.current_task.tid()).?;
    this_thread_wait_count.* += 1;

    _ = wait_counter.cmpxchgStrong(this_thread_wait_count.* - 1, this_thread_wait_count.*, .monotonic, .monotonic);
}

fn not_histrumented() bool {
    return kernel.current_task.pid() != histrumented_pid.load(.monotonic);
}

fn addThread(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) void {
    if (not_histrumented()) return;

    threads_wait_count.acquireAccess();
    defer threads_wait_count.releaseAccess();

    if (threads_wait_count.map.available == 0) threads_wait_count.growUnsafe(allocator) catch return; //TODO: should signal error

    const parent_wait_count = threads_wait_count.map.get(kernel.current_task.tid()).?;
    threads_wait_count.map.putAssumeCapacity(@intCast(regs.getReturnValue()), parent_wait_count);
}

fn futexWaitStart(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1; // returning 1 will cancel futexWaitEnd call

    const data: *WaitProbeData = @ptrCast(@alignCast(data_opaque.?));

    data.wait_debit = wait_counter.load(.monotonic) - threads_wait_count.get(kernel.current_task.tid()).?;
    data.futex_hande = regs.getArgument(0); // We save the handle since it gets clobbered

    return 0;
}

fn futexWaitEnd(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) void {
    if (regs.getReturnValue() != 0) return; // Not woke by other threads.

    const data: *WaitProbeData = @ptrCast(@alignCast(data_opaque.?));

    // TODO: in rare cases this could grow the map; same as the .? so we will need to handle that better.
    threads_wait_count.putAssumeCapacity(kernel.current_task.tid(), futex_wakers_wait_count.get(data.futex_hande).?);

    kernel.time.delay.us(data.wait_debit * wait_lenght.load(.monotonic));
}

fn futexWake(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1;

    const this_thread_wait_count = threads_wait_count.get(kernel.current_task.tid()).?;

    futex_wakers_wait_count.put(allocator, regs.getArgument(0), this_thread_wait_count) catch return 1; //TODO: should signal error;

    const wait_debit = wait_counter.load(.monotonic) - this_thread_wait_count;
    kernel.time.delay.us(wait_debit * wait_lenght.load(.monotonic));

    return 0;
}

fn exit(_: *FProbe, _: c_ulong, _: c_ulong, _: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1;
    const this_thread_wait_count = threads_wait_count.get(kernel.current_task.tid()).?;

    const wait_debit = wait_counter.load(.monotonic) - this_thread_wait_count;
    kernel.time.delay.us(wait_debit * wait_lenght.load(.monotonic));

    return 0;
}
