// TODO: this file should be replaced when we have full support
// for translate-c in zig

const std = @import("std");
const linux = std.os.linux;
const is_target_kernel = @import("builtin").target.os.tag == .freestanding;
const arch = @import("builtin").cpu.arch;

//TODO: keep an eye on the std lib; they may implement that.
pub const PtRegs = switch (arch) {
    .x86_64 => extern struct {
        r15: u64,
        r14: u64,
        r13: u64,
        r12: u64,
        bp: u64,
        bx: u64,

        r11: u64,
        r10: u64,
        r9: u64,
        r8: u64,
        ax: u64,
        cx: u64,
        dx: u64,
        si: u64,
        di: u64,

        orig_ax: u64,
        ip: u64,

        c: extern union {
            s: u16,
            sx: u64,
            fred_cs: packed struct(u64) {
                cs: u16,
                sl: u2,
                wfe: bool,
                padding0: u45,
            },
        },

        flags: u64,
        sp: u64,

        s: extern union {
            s: u16,
            sx: u64,
            fred_ss: packed struct(u64) {
                ss: u16,
                sti: bool,
                swevent: bool,
                nmi: bool,
                pad0: u13,
                vector: u8,
                pad1: u8,
                type: u4,
                pad2: u4,
                enclave: bool,
                lm: bool,
                nested: bool,
                pad3: u1,
                insnlen: u4,
            },
        },
    },

    else => @compileError("Unsupported arch"),
};

// We test the custom allocator replacing kernel calls with malloc and free
const c = if (!is_target_kernel) @cImport({
    @cInclude("stdlib.h");
}) else {};

pub const mem = struct {
    extern fn c_copy_to_user(*anyopaque, *const anyopaque, usize) usize;
    pub fn copyBytesToUser(to: *anyopaque, from: []const u8) usize {
        return c_copy_to_user(to, from.ptr, from.len);
    }

    extern fn c_copy_from_user(*anyopaque, *const anyopaque, usize) usize;
    pub fn copyBytesFromUser(to: []u8, from: []const u8) []const u8 {
        const len = @min(to.len, from.len);
        return to[0 .. len - c_copy_from_user(to.ptr, from.ptr, len)];
    }
};

pub const heap = struct {
    pub fn KAllocator(cmalloc: fn (c_ulong) callconv(.c) ?*anyopaque) type {
        return struct {
            extern fn c_kfree(*anyopaque) void;
            const cfree = if (is_target_kernel) c_kfree else c.free;

            const Metadata = u16;

            const vtable: std.mem.Allocator.VTable = .{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            };

            fn alloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
                std.debug.assert(len > 0);
                const alignment_bytes = alignment.toByteUnits();
                std.debug.assert(alignment_bytes < std.math.maxInt(Metadata));

                // We will overallocate for the maximum alignment padding
                // which is the alignement_bytes - 1 + @SizeOf(metadata)
                // to save how many bytes we skipped.
                //
                // The metadata will be the value preceding the returned ptr
                const unaligned_address = @intFromPtr(cmalloc(@intCast(len + alignment_bytes + @sizeOf(Metadata) - 1)) orelse return null);

                // If the address is already aligned alignForward
                // will not advance and we will not have space for
                // our metadata byte so we need to advance by one
                const aligned_address = alignment.forward(unaligned_address + @sizeOf(Metadata));

                const ptr: [*]align(1) Metadata = @ptrFromInt(aligned_address);
                (ptr - 1)[0] = @truncate(aligned_address - unaligned_address);

                return @ptrCast(ptr);
            }

            fn resize(_: *anyopaque, buf: []u8, _: std.mem.Alignment, new_len: usize, _: usize) bool {
                // We don't have any facility that forces in place resizing
                // so this operation can only succeed if the new len is less
                // than the old one.
                return new_len <= buf.len;
            }

            fn remap(context: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, return_address: usize) ?[*]u8 {
                // krealloc could potentially return an allocation that
                // doesn't respect the alginment required so is not
                // suitable to achive the remap implementation
                return if (resize(context, buf, alignment, new_len, return_address)) buf.ptr else null;
            }

            fn free(_: *anyopaque, buf: []u8, _: std.mem.Alignment, _: usize) void {
                const buf_ptr: [*]u8 = @ptrCast(buf.ptr);

                const metadata_ptr: [*]align(1) Metadata = @ptrCast(buf_ptr);
                const skipped_bytes = (metadata_ptr - 1)[0];

                cfree(@ptrCast(buf_ptr - skipped_bytes));
            }
        };
    }

    // This allocator doesn't support alignments requiroments > 255 bytes.
    extern fn c_kmalloc(c_ulong) ?*anyopaque;
    pub const allocator: std.mem.Allocator = .{
        .ptr = undefined,
        .vtable = &KAllocator(if (is_target_kernel) c_kmalloc else c.malloc).vtable,
    };

    extern fn c_kmalloc_atomic(c_ulong) ?*anyopaque;
    pub const atomic_allocator: std.mem.Allocator = .{
        .ptr = undefined,
        .vtable = &KAllocator(c_kmalloc_atomic).vtable,
    };
};

pub fn LogWithName(comptime module_name: []const u8) type {
    return struct {
        extern fn c_pr_err([*:0]const u8) void;
        extern fn c_pr_warn([*:0]const u8) void;
        extern fn c_pr_info([*:0]const u8) void;
        extern fn c_pr_debug([*:0]const u8) void;

        pub fn logFn(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime fmt: []const u8, args: anytype) void {
            var buf: [128]u8 = undefined;
            const scope_name = if (scope == .default) module_name else @tagName(scope);
            const scoped_fmt = scope_name ++ ": " ++ fmt ++ "\n";
            const string = if (@inComptime())
                std.fmt.comptimePrint(scoped_fmt, args)
            else
                std.fmt.bufPrintSentinel(&buf, scoped_fmt, args, 0) catch scope_name ++ " PRINT FAILED: No space left in formatting buffer\n";

            switch (level) {
                .err => c_pr_err(string),
                .warn => c_pr_warn(string),
                .info => c_pr_info(string),
                .debug => c_pr_debug(string),
            }
        }
    };
}

pub const time = struct {
    pub const delay = struct {
        extern fn c_ndelay(c_ulong) void;
        pub fn ns(nsec: usize) void {
            if (nsec == 0) return;

            c_ndelay(@intCast(@mod(nsec, 1000)));
            us(@divFloor(nsec, 1000));
        }

        extern fn c_udelay(c_ulong) void;
        pub fn us(usec: usize) void {
            if (usec == 0) return;

            c_udelay(@intCast(@mod(usec, 1000)));
            ms(@divFloor(usec, 1000));
        }

        extern fn c_mdelay(c_ulong) void;
        pub fn ms(msec: usize) void {
            if (msec != 0) c_mdelay(@intCast(msec));
        }
    };

    pub const now = struct {
        extern fn c_ktime_get_ns() u64;
        pub fn ns() u64 {
            return c_ktime_get_ns();
        }

        pub fn us() u64 {
            return @divTrunc(ns(), 1000);
        }

        pub fn ms() u64 {
            return @divTrunc(us(), 1000);
        }

        pub fn s() u64 {
            return @divTrunc(ms(), 1000);
        }
    };

    pub const sleep = struct {
        extern fn c_sleep(usize) void;
        pub inline fn us(usec: usize) void {
            if (usec == 0) return;
            if (usec > 5) {
                c_sleep(usec);
            } else {
                delay.us(usec);
            }
        }
    };
};

pub const Task = opaque {
    extern fn c_current_task() *Task;
    pub fn current() *Task {
        return c_current_task();
    }

    extern fn c_get_task_from_tid(linux.pid_t) *Task;
    pub fn fromTid(t: linux.pid_t) *Task {
        return c_get_task_from_tid(t);
    }

    extern fn c_task_work_add(?*Task, ?*Work, NotifyMode) c_int;
    pub fn findAddWork() WorkAddError!void {
        return switch (linux.errno(@intCast(c_task_work_add(null, null, .none)))) {
            .SUCCESS => {},
            .NOSYS => WorkAddError.KprobeLeakFaild,
            else => WorkAddError.Unknown,
        };
    }

    extern fn c_pid(*Task) linux.pid_t;
    pub fn pid(this: *Task) linux.pid_t {
        return c_pid(this);
    }

    extern fn c_tid(*Task) linux.pid_t;
    pub fn tid(this: *Task) linux.pid_t {
        return c_tid(this);
    }

    extern fn c_task_is_running(*Task) c_int;
    pub fn isRunning(this: *Task) bool {
        return c_task_is_running(this) != 0;
    }

    extern fn c_task_is_dead(*Task) c_int;
    pub fn isDead(this: *Task) bool {
        return c_task_is_dead(this) != 0;
    }

    pub const Work = extern struct {
        pub const Callback = *const fn (*Work) callconv(.c) void;
        next: ?*Work align(@alignOf(usize)),
        func: Callback,
    };

    pub const NotifyMode = enum(c_int) {
        none = 0,
        @"resume",
        signal,
        signal_no_ipi,
        nmi_current,
    };

    pub const WorkAddError = error{
        KprobeLeakFaild,
        BadConfig,
        TooLateShuttingDown,
        Unknown,
    };

    pub fn addWork(this: *Task, work: *Work, notify_mode: NotifyMode) WorkAddError!void {
        return switch (linux.errno(@intCast(c_task_work_add(this, work, notify_mode)))) {
            .SUCCESS => {},
            .NOSYS => WorkAddError.KprobeLeakFaild,
            .INVAL => WorkAddError.BadConfig,
            .SRCH => WorkAddError.TooLateShuttingDown,
            else => WorkAddError.Unknown,
        };
    }

    extern fn c_find_vma(*Task, usize) ?*Vma;
    pub fn findVma(this: *Task, addr: usize) ?*Vma {
        return c_find_vma(this, addr);
    }

    extern fn c_get_task_struct(*Task) void;
    pub fn incrementReferences(this: *Task) void {
        c_get_task_struct(this);
    }

    extern fn c_put_task_struct(*Task) void;
    pub fn decrementReferences(this: *Task) void {
        c_put_task_struct(this);
    }
};

pub const rcu = struct {
    pub const read = struct {
        extern fn c_rcu_read_lock() void;
        pub fn lock() void {
            c_rcu_read_lock();
        }

        extern fn c_rcu_read_unlock() void;
        pub fn unlock() void {
            c_rcu_read_unlock();
        }
    };
};

pub const Vma = opaque {
    extern fn c_vma_start(*Vma) usize;
    pub fn start(this: *Vma) usize {
        return c_vma_start(this);
    }

    extern fn c_vma_filename(*Vma) ?[*:0]const u8;
    pub fn filename(this: *Vma) ?[*:0]const u8 {
        return c_vma_filename(this);
    }
};

pub const CharDevice = extern struct {
    _: [512]u8 = undefined,
    pub const IoctlHandler = ?*const fn (*anyopaque, c_uint, c_ulong) callconv(.c) c_long;

    extern fn c_chardev_register(*CharDevice, [*:0]const u8, IoctlHandler) c_int;
    pub fn create(this: *CharDevice, file_name: [:0]const u8, handler: IoctlHandler) !void {
        if (c_chardev_register(this, file_name.ptr, handler) != 0) return error.CouldNotRegisterChardev;
    }

    extern fn c_chardev_unregister(*CharDevice) void;
    pub fn remove(this: *CharDevice) void {
        c_chardev_unregister(this);
    }

    extern fn c_get_shared_buffer(*CharDevice) *[std.heap.page_size_min]u8;
    pub fn shared_buffer(this: *CharDevice) *[std.heap.page_size_min]u8 {
        return c_get_shared_buffer(this);
    }
};

pub const PerfEvent = opaque {
    const PerfOverflowHandler = *const fn (*PerfEvent, *anyopaque, *PtRegs) callconv(.c) void;

    pub const InitErrors = error{
        InvalidConfiguration,
        TaskNotFound,
        CpuOffline,
        HardwareBusy,
        NotSupported,
        OutOfMemory,
        HardwareNotFound,
        InvalidAttributeSize,
        Unexpected,
    };

    extern fn c_perf_event_create_kernel_counter(*linux.perf_event_attr, c_int, linux.pid_t, PerfOverflowHandler, ?*anyopaque) usize;
    pub fn init(attr: *linux.perf_event_attr, cpu: c_int, pid: linux.pid_t, callback: PerfOverflowHandler, cntxt: ?*anyopaque) InitErrors!*PerfEvent {
        const rc = c_perf_event_create_kernel_counter(attr, cpu, pid, callback, cntxt);
        return switch (linux.errno(rc)) {
            .SUCCESS => @ptrFromInt(rc),
            .INVAL => InitErrors.InvalidConfiguration,
            .SRCH => InitErrors.TaskNotFound,
            .NODEV => InitErrors.CpuOffline,
            .BUSY => InitErrors.HardwareBusy,
            .OPNOTSUPP => InitErrors.NotSupported,
            .NOMEM => InitErrors.OutOfMemory,
            .NOENT => InitErrors.HardwareNotFound,
            .@"2BIG" => InitErrors.InvalidAttributeSize,
            else => InitErrors.Unexpected,
        };
    }

    extern fn c_perf_event_enable(*PerfEvent) void;
    pub fn enable(this: *PerfEvent) void {
        c_perf_event_enable(this);
    }

    extern fn c_perf_event_disable(*PerfEvent) void;
    pub fn disable(this: *PerfEvent) void {
        c_perf_event_disable(this);
    }

    extern fn c_perf_event_release_kernel(*PerfEvent) c_int;
    pub fn deinit(this: ?*PerfEvent) void {
        if (this) |t| _ = c_perf_event_release_kernel(t);
    }

    extern fn c_perf_event_context(*PerfEvent) ?*anyopaque;
    pub fn context(this: *PerfEvent) ?*anyopaque {
        return c_perf_event_context(this);
    }
};

pub const Thread = opaque {
    pub const Handler = *const fn (?*anyopaque) callconv(.c) c_int;
    extern fn c_kthread_run(thread_handler: Handler, data: ?*anyopaque, name: [*:0]const u8) *Thread;
    pub fn run(thread_handler: Handler, data: ?*anyopaque, name: [*:0]const u8) *Thread {
        return c_kthread_run(thread_handler, data, name);
    }

    extern fn c_kthread_stop(*Thread) c_int;
    pub fn stop(this: *Thread) void {
        _ = c_kthread_stop(this); //TODO: this should return errors
    }

    extern fn c_kthread_should_stop() bool;
    pub fn shouldThisStop() bool {
        return c_kthread_should_stop();
    }
};

pub const tracepoint = struct {
    extern fn c_tracepoint_init() void;
    extern fn c_tracepoint_sync() void;

    pub fn init() void {
        c_tracepoint_init();
    }

    pub fn sync() void {
        c_tracepoint_sync();
    }

    pub const sched = struct {
        pub const RegistrationError = error{
            Failed,
        };

        pub const fork = struct {
            pub const Callback = *const fn (data: ?*anyopaque, parent: *Task, child: *Task) callconv(.c) void;

            extern fn c_register_sched_fork(probe: Callback, data: ?*anyopaque) c_int;
            pub fn register(trace: Callback, data: ?*anyopaque) RegistrationError!void {
                if (c_register_sched_fork(trace, data) != 0) return RegistrationError.Failed;
            }

            extern fn c_unregister_sched_fork(probe: Callback, data: ?*anyopaque) void;
            pub fn unregister(trace: Callback, data: ?*anyopaque) void {
                c_unregister_sched_fork(trace, data);
            }
        };

        pub const exit = struct {
            pub const Callback = *const fn (data: ?*anyopaque, task: *Task) callconv(.c) void;

            extern fn c_register_sched_exit(probe: Callback, data: ?*anyopaque) c_int;
            pub fn register(trace: Callback, data: ?*anyopaque) RegistrationError!void {
                if (c_register_sched_exit(trace, data) != 0) return RegistrationError.Failed;
            }

            extern fn c_unregister_sched_exit(probe: Callback, data: ?*anyopaque) void;
            pub fn unregister(trace: Callback, data: ?*anyopaque) void {
                c_unregister_sched_exit(trace, data);
            }
        };

        pub const waking = struct {
            pub const Callback = *const fn (data: ?*anyopaque, task: *Task) callconv(.c) void;

            extern fn c_register_sched_waking(probe: Callback, data: ?*anyopaque) c_int;
            pub fn register(trace: Callback, data: ?*anyopaque) RegistrationError!void {
                if (c_register_sched_waking(trace, data) != 0) return RegistrationError.Failed;
            }

            extern fn c_unregister_sched_waking(probe: Callback, data: ?*anyopaque) void;
            pub fn unregister(trace: Callback, data: ?*anyopaque) void {
                c_unregister_sched_waking(trace, data);
            }
        };

        pub const @"switch" = struct {
            pub const Callback = *const fn (data: ?*anyopaque, preempt: bool, prev: *Task, next: *Task) callconv(.c) void;

            extern fn c_register_sched_switch(probe: Callback, data: ?*anyopaque) c_int;
            pub fn register(trace: Callback, data: ?*anyopaque) RegistrationError!void {
                if (c_register_sched_switch(trace, data) != 0) return RegistrationError.Failed;
            }

            extern fn c_unregister_sched_switch(probe: Callback, data: ?*anyopaque) void;
            pub fn unregister(trace: Callback, data: ?*anyopaque) void {
                c_unregister_sched_switch(trace, data);
            }
        };
    };
};

test "Allocator" {
    try std.heap.testAllocator(heap.allocator);
    try std.heap.testAllocatorAligned(heap.allocator);
    try std.heap.testAllocatorAlignedShrink(heap.allocator);
    try std.heap.testAllocatorLargeAlignment(heap.allocator);
}
