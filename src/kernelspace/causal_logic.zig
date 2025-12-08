// TODO: remove the thread_wait_count_map .? since they can actually be null
const std = @import("std");
const kernel = @import("bindings/kernel.zig");

const FProbe = kernel.probe.F;
const FtraceRegs = kernel.probe.FtraceRegs;
const Pid = std.os.linux.pid_t;
const Tid = Pid;
const FutexHandle = usize;
const WaitCounter = usize;

const allocator = kernel.heap.allocator;

var histrumented_pid: std.atomic.Value(Pid) = .init(0);
var wait_counter: std.atomic.Value(WaitCounter) = .init(0);
var wait_lenght: std.atomic.Value(usize) = .init(0);

var thread_wait_count_map: std.AutoHashMapUnmanaged(Tid, WaitCounter) = .empty;
var futex_wakers_wait_count_map: std.AutoHashMapUnmanaged(FutexHandle, WaitCounter) = .empty;

const filters = [_][:0]const u8{ "kernel_clone", "futex_wait", "futex_wake" };
var probes = [filters.len]FProbe{
    .{ .callbacks = .{ .post_handler = &addThread } },
    .{ .callbacks = .{ .pre_handler = &futexWaitStart, .post_handler = &futexWaitEnd }, .entry_data_size = @sizeOf(WaitCounter) },
    .{ .callbacks = .{ .pre_handler = &futexWake } },
};

pub fn init() !void {
    try thread_wait_count_map.ensureTotalCapacity(allocator, 100);
    try futex_wakers_wait_count_map.ensureTotalCapacity(allocator, 100);

    for (probes[0..], filters) |*probe, filter| {
        try probe.register(filter, null);
    }
}

pub fn start(pid: Pid) void {
    thread_wait_count_map.clearRetainingCapacity();
    futex_wakers_wait_count_map.clearRetainingCapacity();

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

    wait_counter.cmpxchgStrong(this_thread_wait_count.* - 1, this_thread_wait_count.*, .monotonic);
}

fn not_histrumented() bool {
    return kernel.current_task.pid() != histrumented_pid.load(.unordered);
}

pub fn addThread(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) void {
    if (not_histrumented()) return;
    // TODO: handle map growth if needed

    const parent_wait_count = thread_wait_count_map.get(kernel.current_task.tid()).?;
    thread_wait_count_map.putAssumeCapacity(@intCast(regs.getReturnValue()), parent_wait_count);
}

pub fn futexWaitStart(_: *FProbe, _: c_ulong, _: c_ulong, _: *FtraceRegs, wait_debit_opa: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1; // returning 1 will cancel futexWaitEnd call

    const wait_debit: *WaitCounter = @ptrCast(@alignCast(wait_debit_opa.?));

    std.log.debug("wait tid:{}", .{kernel.current_task.tid()});
    wait_debit.* = wait_counter.load(.monotonic) - thread_wait_count_map.get(kernel.current_task.tid()).?;
    return 0;
}

pub fn futexWaitEnd(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, wait_debit_opa: ?*anyopaque) callconv(.c) void {
    if (regs.getReturnValue() != 0) return; // Not woke by other threads.
    const this_thread_wait_count = thread_wait_count_map.getPtr(kernel.current_task.tid()).?;
    const futex_handle = regs.getArgument(0);
    this_thread_wait_count.* = futex_wakers_wait_count_map.get(futex_handle).?;

    const wait_debit = @as(*WaitCounter, @ptrCast(@alignCast(wait_debit_opa.?))).*;
    if (wait_debit != 0) kernel.time.delay.us(wait_debit * wait_lenght.load(.unordered));
}

pub fn futexWake(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    if (not_histrumented()) return 1;

    const this_thread_wait_count = thread_wait_count_map.getPtr(kernel.current_task.tid()).?;
    const global_wait_counter = wait_counter.load(.monotonic);
    const wait_debit = global_wait_counter - this_thread_wait_count.*;

    this_thread_wait_count.* = global_wait_counter;

    if (wait_debit != 0) kernel.time.delay.us(wait_debit * wait_lenght.load(.unordered));

    const futex_handle = regs.getArgument(0);

    // TODO: handle map growth if needed
    futex_wakers_wait_count_map.putAssumeCapacity(futex_handle, this_thread_wait_count.*);
    return 0;
}

// TODO: check for if we covered those too:
// pthread cond broadcast
// pthread kill
// pthread exit
//
// pthread join
// sigwait wait
// sigwaitinfo
// sigtimedwait
// sigsuspend
