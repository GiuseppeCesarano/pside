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

pub const engine = struct {
    const allocator = kernel.heap.atomic_allocator;

    pub fn init() !void {
        try probes.init();
    }

    pub fn deinit() void {
        probes.deinit();
    }

    pub fn profilePid(pid: Pid) void {
        probes.profilePid(pid);
        profileLoop();
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

    const probes = struct {
        const ThreadWaitCounterMap = thread_safe.SegmentedSparseVector(WaitCounter, std.math.maxInt(WaitCounter));
        const FutexWakerWaitCountMap = thread_safe.AddressMap(WaitCounter, std.math.maxInt(WaitCounter));

        const WaitProbeData = struct {
            wait_debit: WaitCounter,
            futex_hande: FutexHandle,
        };

        fn ErrorQueue(Error: type) type {
            if (@typeInfo(Error) != .error_set) @compileError("ErrorQueue only supports error sets");
            return struct {
                errors: [16]Error,
                index: std.atomic.Value(u8),

                pub const init = @This(){ .errors = @splat(undefined), .index = .init(0) };

                pub fn signalError(this: *@This(), err: Error) void {
                    @branchHint(.cold);
                    const index = this.index.fetchAdd(1, .monotonic);
                    if (this.errors.len > index) this.errors[index] = err;
                }

                pub fn getOccurred(this: @This()) ?[]Error {
                    const index = @min(this.index.load(.monotonic), this.errors.len);
                    return if (index != 0) this.errors[0..index] else null;
                }

                pub fn someWhereLost(this: @This()) bool {
                    return this.index.load(.monotonic) > this.errors.len;
                }

                pub fn clear(this: *@This()) void {
                    this.index.store(0, .monotonic);
                }
            };
        }

        const Errors = error{};

        var histrumented_pid: std.atomic.Value(Pid) = .init(0);
        var wait_lenght: std.atomic.Value(usize) = .init(0);

        var global_wait_counter: std.atomic.Value(WaitCounter) = .init(0);
        var threads_wait_count: ThreadWaitCounterMap = .init;
        var futex_wakers_wait_count: FutexWakerWaitCountMap = .init;

        const filters = [_][:0]const u8{ "kernel_clone", "futex_wait", "futex_wake", "do_exit" };
        var fprobes = [filters.len]FProbe{
            .{ .callbacks = .{ .post_handler = &clone } },
            .{ .callbacks = .{ .pre_handler = &futexWaitStart, .post_handler = &futexWaitEnd }, .entry_data_size = @sizeOf(WaitProbeData) },
            .{ .callbacks = .{ .pre_handler = &futexWake } },
            .{ .callbacks = .{ .pre_handler = &exit } },
        };

        pub fn init() !void {
            try futex_wakers_wait_count.grow(allocator);
            for (fprobes[0..], filters) |*probe, filter| {
                try probe.register(filter, null);
            }
        }

        pub fn deinit() void {
            threads_wait_count.deinit(allocator);
            futex_wakers_wait_count.deinit(allocator);

            for (fprobes[0..]) |*probe| {
                probe.unregister();
            }
        }

        pub fn profilePid(pid: Pid) void {
            threads_wait_count.put(allocator, @intCast(pid), 0) catch {};
            histrumented_pid.store(pid, .release);
        }

        fn increment() void {
            const this_thread_wait_count = threads_wait_count.getPtr(@intCast(kernel.current_task.tid()));
            this_thread_wait_count.* += 1;

            _ = global_wait_counter.cmpxchgStrong(this_thread_wait_count.* - 1, this_thread_wait_count.*, .monotonic, .monotonic);
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

            data.wait_debit = global_wait_counter.load(.monotonic) - threads_wait_count.get(@intCast(kernel.current_task.tid())).?;
            data.futex_hande = regs.getArgument(0); // We save the handle since it gets clobbered

            return 0;
        }

        fn futexWaitEnd(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, data_opaque: ?*anyopaque) callconv(.c) void {
            if (regs.getReturnValue() != 0) return; // Not woke by other threads.

            const data: *WaitProbeData = @ptrCast(@alignCast(data_opaque.?));

            kernel.time.delay.us(data.wait_debit * wait_lenght.load(.monotonic));

            const waker_wait_counter = futex_wakers_wait_count.get(data.futex_hande) orelse {
                @branchHint(.cold);
                //TODO: signal error
                return;
            };

            threads_wait_count.put(allocator, @intCast(kernel.current_task.tid()), waker_wait_counter) catch {};
        }

        fn futexWake(_: *FProbe, _: c_ulong, _: c_ulong, regs: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
            if (not_histrumented()) return 1;

            const tid: usize = @intCast(kernel.current_task.tid());

            const this_thread_wait_counter = threads_wait_count.get(tid).?;
            futex_wakers_wait_count.put(allocator, regs.getArgument(0), this_thread_wait_counter) catch return 1; //TODO: should signal error;

            const wait_debit = global_wait_counter.load(.monotonic) - this_thread_wait_counter;
            kernel.time.delay.us(wait_debit * wait_lenght.load(.monotonic));

            return 0;
        }

        fn exit(_: *FProbe, _: c_ulong, _: c_ulong, _: *FtraceRegs, _: ?*anyopaque) callconv(.c) c_int {
            if (not_histrumented()) return 1;
            const this_thread_wait_count = threads_wait_count.get(@intCast(kernel.current_task.tid())).?;

            const wait_debit = global_wait_counter.load(.monotonic) - this_thread_wait_count;
            kernel.time.delay.us(wait_debit * wait_lenght.load(.monotonic));

            return 0;
        }
    };
};
