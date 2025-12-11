// TODO: missing syscalls to cover:
// pthread_kill -> tgkill
//
// sigwait_wait
// sigwaitinfo
// sigtimedwait
// sigsuspend
//
// TODO: remove the thread_wait_count_map .? since they can actually be null
const std = @import("std");
const kernel = @import("bindings/kernel.zig");

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

var thread_wait_count_map: std.AutoHashMapUnmanaged(Tid, WaitCounter) = .empty;
var futex_wakers_wait_count_map: std.AutoHashMapUnmanaged(FutexHandle, WaitCounter) = .empty;

const filters = [_][:0]const u8{ "kernel_clone", "futex_wait", "futex_wake", "do_exit" };
var probes = [filters.len]FProbe{
    .{ .callbacks = .{ .post_handler = &addThread } },
    .{ .callbacks = .{ .pre_handler = &futexWaitStart, .post_handler = &futexWaitEnd }, .entry_data_size = @sizeOf(WaitProbeData) },
    .{ .callbacks = .{ .pre_handler = &futexWake } },
    .{ .callbacks = .{ .pre_handler = &exit } },
};

pub fn init() !void {
    try thread_wait_count_map.ensureTotalCapacity(allocator, 300);
    try futex_wakers_wait_count_map.ensureTotalCapacity(allocator, 300);

    for (probes[0..], filters) |*probe, filter| {
        try probe.register(filter, null);
    }
}

pub fn start(pid: Pid) void {
    thread_wait_count_map.clearRetainingCapacity();
    futex_wakers_wait_count_map.clearRetainingCapacity();

    // TODO: maybe clear the WaitCounter?
    thread_wait_count_map.putAssumeCapacity(pid, 0);
    histrumented_pid.store(pid, .release);
}

pub fn deinit() void {
    thread_wait_count_map.deinit(allocator);
    futex_wakers_wait_count_map.deinit(allocator);

    for (probes[0..]) |*probe| {
        probe.unregister();
    }
}

fn increment() void {
    const this_thread_wait_count = thread_wait_count_map.getPtr(kernel.current_task.tid()).?;
    this_thread_wait_count.* += 1;

    _ = wait_counter.cmpxchgStrong(this_thread_wait_count.* - 1, this_thread_wait_count.*, .monotonic, .monotonic);
}

fn applyWaitDebit(this_thread_wait_count: *WaitCounter) void {
    const global_wait_counter = wait_counter.load(.monotonic);
    const wait_debit = global_wait_counter - this_thread_wait_count.*;

    this_thread_wait_count.* = global_wait_counter;

    kernel.time.delay.us(wait_debit * wait_lenght.load(.monotonic));
}

fn not_histrumented() bool {
    return kernel.current_task.pid() != histrumented_pid.load(.monotonic);
}

fn addThread(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) void {
    if (not_histrumented()) return;
    // TODO: handle map growth if needed

    const parent_wait_count = thread_wait_count_map.get(kernel.current_task.tid()).?;
    thread_wait_count_map.putAssumeCapacity(@intCast(regs.getReturnValue()), parent_wait_count);
}

fn futexWaitStart(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1; // returning 1 will cancel futexWaitEnd call

    const data: *WaitProbeData = @ptrCast(@alignCast(data_opaque.?));

    data.wait_debit = wait_counter.load(.monotonic) - thread_wait_count_map.get(kernel.current_task.tid()).?;
    data.futex_hande = regs.getArgument(0); // We save the handle since it gets clobbered

    return 0;
}

fn futexWaitEnd(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) void {
    if (regs.getReturnValue() != 0) return; // Not woke by other threads.

    const data: *WaitProbeData = @ptrCast(@alignCast(data_opaque.?));

    const this_thread_wait_count = thread_wait_count_map.getPtr(kernel.current_task.tid()).?;
    this_thread_wait_count.* = futex_wakers_wait_count_map.get(data.futex_hande).?;
    kernel.time.delay.us(data.wait_debit * wait_lenght.load(.monotonic));
}

fn futexWake(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1;

    const this_thread_wait_count = thread_wait_count_map.getPtr(kernel.current_task.tid()).?;
    applyWaitDebit(this_thread_wait_count);

    const futex_handle = regs.getArgument(0);
    // TODO: handle map growth if needed
    futex_wakers_wait_count_map.putAssumeCapacity(futex_handle, this_thread_wait_count.*);

    return 0;
}

fn exit(_: *FProbe, _: c_ulong, _: c_ulong, _: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1;
    applyWaitDebit(thread_wait_count_map.getPtr(kernel.current_task.tid()).?);

    return 0;
}
