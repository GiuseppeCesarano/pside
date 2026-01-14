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
const kernel = @import("kernel");
const thread_safe = @import("thread_safe.zig");

const Pid = std.os.linux.pid_t;
const Tid = Pid;
const FutexHandle = usize;
const ProgressPoint = usize;

const FProbe = kernel.probe.F;
const FtraceRegs = kernel.probe.FtraceRegs;

const allocator = kernel.heap.atomic_allocator;

const ThreadProgressMap = thread_safe.SegmentedSparseVector(ProgressPoint, std.math.maxInt(ProgressPoint));
const ProgressTransferMap = thread_safe.AddressMap(ProgressPoint, std.math.maxInt(ProgressPoint));

const WaitProbeCtx = struct {
    lag_debit: ProgressPoint,
    futex_handle: FutexHandle,
};

pub const state = struct {
    var instrumented_pid = std.atomic.Value(Pid).init(0);
    var delay_per_point_us = std.atomic.Value(usize).init(0);

    var lead_progress = std.atomic.Value(ProgressPoint).init(0);
    var thread_points: ThreadProgressMap = .init;
    var transfer_map: ProgressTransferMap = .init;

    var profiler: *kernel.PerfEvent = undefined;
    var line_selector: *kernel.PerfEvent = undefined;
    var selected_line: usize = 0;
};

const ProbeDef = struct {
    filter: [:0]const u8,
    pre: ?*const fn (*FProbe, c_ulong, c_ulong, *FtraceRegs, ?*anyopaque) callconv(.c) c_int = null,
    post: ?*const fn (*FProbe, c_ulong, c_ulong, *FtraceRegs, ?*anyopaque) callconv(.c) void = null,
    data_size: usize = 0,
};

const probes_list = [_]ProbeDef{
    .{ .filter = "kernel_clone", .post = clone },
    .{ .filter = "futex_wait", .pre = futexWaitStart, .post = futexWaitEnd, .data_size = @sizeOf(WaitProbeCtx) },
    .{ .filter = "futex_wake", .pre = futexWake },
    .{ .filter = "do_exit", .pre = exit },
};

var fprobes: [probes_list.len]FProbe = undefined;

pub fn init() !void {
    try state.transfer_map.growExponential(allocator);

    inline for (probes_list, 0..) |def, i| {
        fprobes[i] = .{
            .callbacks = .{ .pre_handler = def.pre, .post_handler = def.post },
            .entry_data_size = @intCast(def.data_size),
        };
        try fprobes[i].register(def.filter, null);
    }
}

pub fn deinit() void {
    for (&fprobes) |*probe| probe.unregister();

    state.transfer_map.deinit(allocator);
    state.thread_points.deinit(allocator);

    state.line_selector.deinit();
    state.profiler.deinit();

    std.log.info("Global virtual clock at exit: {}", .{state.lead_progress.load(.monotonic)});
}

pub fn profilePid(pid: Pid) void {
    state.thread_points.put(allocator, @intCast(pid), 0) catch {};
    state.instrumented_pid.store(pid, .release);

    var attr = std.os.linux.perf_event_attr{
        .type = .SOFTWARE,
        .config = @intFromEnum(std.os.linux.PERF.COUNT.SW.TASK_CLOCK),
        .sample_period_or_freq = 200 * std.time.ns_per_us,
        .wakeup_events_or_watermark = 1,
        .flags = .{
            .disabled = true,
            .inherit = true,
            .exclude_host = true,
            .exclude_guest = true,
            .exclude_hv = true,
            .exclude_idle = true,
            .exclude_kernel = true,
        },
    };
    state.line_selector = kernel.PerfEvent.init(&attr, -1, pid, line_selector_cb, &state.selected_line) catch return;
    state.line_selector.enable();

    attr.sample_period_or_freq = 1 * std.time.ns_per_ms;
    state.profiler = kernel.PerfEvent.init(&attr, -1, pid, profiler_cb, &state.selected_line) catch return;
    state.profiler.enable();
}

fn line_selector_cb(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    state.line_selector.disable();
    const ptr: *usize = if (event.context()) |ctx| @ptrCast(@alignCast(ctx)) else return;
    ptr.* = regs.ip;
}

fn profiler_cb(event: *kernel.PerfEvent, _: *anyopaque, regs: *kernel.PtRegs) callconv(.c) void {
    const ptr: *const usize = if (event.context()) |ctx| @ptrCast(@alignCast(ctx)) else return;
    if (ptr.* == regs.ip) increment();
}

fn profileLoop() void {
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
    if (state.thread_points.increment(@intCast(kernel.current_task.tid()))) |counter| {
        _ = state.lead_progress.fetchMax(counter, .monotonic);
    }
}

fn notInstrumented() bool {
    return kernel.current_task.pid() != state.instrumented_pid.load(.monotonic);
}

fn clone(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) void {
    if (notInstrumented()) return;

    const parent_wait_count = state.thread_points.get(@intCast(kernel.current_task.tid())).?;
    state.thread_points.put(allocator, @intCast(regs.getReturnValue()), parent_wait_count) catch {};
}

fn futexWaitStart(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) c_int {
    if (notInstrumented()) return 1; // returning 1 will cancel futexWaitEnd call

    const data: *WaitProbeCtx = @ptrCast(@alignCast(data_opaque.?));

    data.lag_debit = state.lead_progress.load(.monotonic) - state.thread_points.get(@intCast(kernel.current_task.tid())).?;
    data.futex_handle = regs.getArgument(0); // We save the handle since it gets clobbered

    return 0;
}

fn futexWaitEnd(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) void {
    if (regs.getReturnValue() != 0) return; // Not woke by other threads.

    const data: *WaitProbeCtx = @ptrCast(@alignCast(data_opaque.?));

    kernel.time.delay.us(data.lag_debit * state.delay_per_point_us.load(.monotonic));

    const waker_wait_counter = state.transfer_map.get(data.futex_handle) orelse {
        @branchHint(.cold);
        //TODO: signal error
        return;
    };

    state.thread_points.put(allocator, @intCast(kernel.current_task.tid()), waker_wait_counter) catch {};
}

fn futexWake(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    if (notInstrumented()) return 1;

    const tid: usize = @intCast(kernel.current_task.tid());

    const this_thread_wait_counter = state.thread_points.get(tid).?;
    state.transfer_map.put(allocator, regs.getArgument(0), this_thread_wait_counter) catch return 1; //TODO: should signal error;

    const wait_debit = state.lead_progress.load(.monotonic) - this_thread_wait_counter;
    kernel.time.delay.us(wait_debit * state.delay_per_point_us.load(.monotonic));

    return 0;
}

fn exit(_: *FProbe, _: c_ulong, _: c_ulong, _: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
    if (notInstrumented()) return 1;
    const this_thread_wait_count = state.thread_points.get(@intCast(kernel.current_task.tid())).?;

    const wait_debit = state.lead_progress.load(.monotonic) - this_thread_wait_count;
    kernel.time.delay.us(wait_debit * state.delay_per_point_us.load(.monotonic));

    return 0;
}
