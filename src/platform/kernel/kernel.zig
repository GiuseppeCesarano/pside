// TODO: this file should be replaced when we have full support
// for translate-c in zig

const std = @import("std");
const linux = std.os.linux;
const arch = @import("builtin").cpu.arch;

pub const Io = @import("Io.zig");

const is_target_kernel = @import("builtin").code_model == .kernel;
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

extern fn c_copy_from_user(*anyopaque, usize, usize) usize;
pub fn copyFromUser(to: []u8, from: usize) []const u8 {
    return to[0 .. to.len - c_copy_from_user(to.ptr, from, to.len)];
}

pub const heap = struct {
    const Context = enum { sleepable, atomic, any };

    pub fn KAllocator(cmalloc: fn (c_ulong) callconv(.c) ?*anyopaque, allocation_context: Context) type {
        return struct {
            extern fn kfree(*anyopaque) void;
            const cfree = if (is_target_kernel) kfree else std.c.free;
            const Metadata = u16;

            const vtable: std.mem.Allocator.VTable = .{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            };

            fn alloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
                assertContext();
                std.debug.assert(len > 0);
                const alignment_bytes = alignment.toByteUnits();
                std.debug.assert(alignment_bytes < std.math.maxInt(Metadata));

                // We will overallocate for the maximum alignment padding
                // which is the alignment_bytes - 1 + @sizeOf(Metadata)
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
                // doesn't respect the alignment required so is not
                // suitable to achieve the remap implementation
                return if (resize(context, buf, alignment, new_len, return_address)) buf.ptr else null;
            }

            fn free(_: *anyopaque, buf: []u8, _: std.mem.Alignment, _: usize) void {
                const buf_ptr: [*]u8 = @ptrCast(buf.ptr);

                const metadata_ptr: [*]align(1) Metadata = @ptrCast(buf_ptr);
                const skipped_bytes = (metadata_ptr - 1)[0];

                cfree(@ptrCast(buf_ptr - skipped_bytes));
            }

            fn assertContext() void {
                if (!is_target_kernel) return;

                switch (allocation_context) {
                    .sleepable => assertSleepable(),
                    .atomic => std.debug.assert(!preemptible()),
                    .any => {},
                }
            }
        };
    }

    extern fn c_gfp_kernel() c_uint;
    extern fn c_gfp_atomic() c_uint;
    extern fn c_kmalloc(c_ulong, c_uint) ?*anyopaque;

    fn kmallocGfpKernel(size: c_ulong) callconv(.c) ?*anyopaque {
        return c_kmalloc(size, c_gfp_kernel());
    }

    fn kmallocGfpAtomic(size: c_ulong) callconv(.c) ?*anyopaque {
        return c_kmalloc(size, c_gfp_atomic());
    }

    pub const allocator: std.mem.Allocator = .{
        .ptr = undefined,
        .vtable = &KAllocator(if (is_target_kernel) kmallocGfpKernel else std.c.malloc, .sleepable).vtable,
    };

    pub const atomic_allocator: std.mem.Allocator = .{
        .ptr = undefined,
        .vtable = &KAllocator(kmallocGfpAtomic, .atomic).vtable,
    };

    const any_context_allocator: std.mem.Allocator = .{
        .ptr = undefined,
        .vtable = &KAllocator(kmallocGfpAtomic, .any).vtable,
    };
};

//TODO: redo
const PrintkWriter = struct {
    pub const line_capacity = 1024;

    level: std.log.Level,
    interface: std.Io.Writer,

    extern fn c_printk(c_int, [*]const u8, usize) void;

    pub fn init(level: std.log.Level, buffer: []u8) PrintkWriter {
        return .{
            .level = level,
            .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
        };
    }

    fn emit(this: *const PrintkWriter, bytes: []const u8) void {
        const text = if (bytes.len != 0 and bytes[bytes.len - 1] == '\n') bytes[0 .. bytes.len - 1] else bytes;
        c_printk(@backingInt(this.level), text.ptr, text.len);
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const this: *PrintkWriter = @alignCast(@fieldParentPtr("interface", w));

        const buffered = w.buffered();
        if (buffered.len != 0) {
            this.emit(buffered);
            w.end = 0;
            return 0;
        }

        for (data[0 .. data.len - 1]) |bytes| {
            if (bytes.len == 0) continue;
            this.emit(bytes);
            return bytes.len;
        }

        const pattern = data[data.len - 1];
        if (splat == 0 or pattern.len == 0) return 0;
        this.emit(pattern);
        return pattern.len;
    }
};

pub fn logWithName(comptime module_name: []const u8) fn (comptime std.log.Level, comptime @EnumLiteral(), comptime fmt: []const u8, anytype) void {
    return struct {
        pub fn log(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime fmt: []const u8, args: anytype) void {
            const scope_name = if (scope == .default) module_name else @tagName(scope);

            var buffer: [PrintkWriter.line_capacity]u8 = undefined;
            var printk: PrintkWriter = .init(level, &buffer);
            printk.interface.print(scope_name ++ ": " ++ fmt, args) catch {};
            printk.interface.flush() catch {};
        }
    }.log;
}

// TODO REDO
pub const debug = struct {
    pub fn getDebugInfoAllocator() std.mem.Allocator {
        return heap.any_context_allocator;
    }

    pub const PrintLineError = error{SourceUnavailable};

    pub fn printLineFromFile(_: std.Io, _: *std.Io.Writer, _: std.debug.SourceLocation) PrintLineError!void {
        return PrintLineError.SourceUnavailable;
    }

    pub fn panic(message: []const u8, _: ?usize) noreturn {
        @branchHint(.cold);
        std.log.err("panic: {s}", .{message});
        @trap();
    }

    pub const SelfInfo = struct {
        pub const init: SelfInfo = .{};
        pub const can_unwind = true;

        extern fn c_ksym_symbol_len() usize;
        extern fn sprint_symbol([*]u8, c_ulong) c_int;
        extern fn stack_trace_save([*]usize, c_uint, c_uint) c_uint;

        pub const UnwindContext = struct {
            pc: usize,
            addresses: [max_frames]usize,
            len: usize,
            next: usize,

            const max_frames = 32;

            pub fn init(_: *const std.debug.cpu_context.Native) UnwindContext {
                var context: UnwindContext = .{ .pc = 0, .addresses = undefined, .len = 0, .next = 0 };
                context.len = stack_trace_save(&context.addresses, max_frames, 0);
                return context;
            }

            pub fn deinit(_: *UnwindContext) void {}

            pub fn getFp(_: *UnwindContext) usize {
                return 0;
            }
        };

        pub fn unwindFrame(_: *SelfInfo, _: std.Io, context: *UnwindContext) std.debug.SelfInfoError!usize {
            if (context.next == context.len) return 0;

            context.pc = context.addresses[context.next];
            context.next += 1;
            return context.pc;
        }

        pub fn deinit(_: *SelfInfo, _: std.Io) void {}

        pub fn getSymbols(
            _: *SelfInfo,
            _: std.Io,
            symbol_allocator: std.mem.Allocator,
            text_arena: std.mem.Allocator,
            address: usize,
            _: bool,
            symbols: *std.ArrayList(std.debug.Symbol),
        ) std.debug.SelfInfoError!void {
            const buffer = try text_arena.alloc(u8, c_ksym_symbol_len());
            const text = buffer[0..@intCast(sprint_symbol(buffer.ptr, address))];

            const name, const module = if (std.mem.lastIndexOf(u8, text, " [")) |bracket|
                .{ text[0..bracket], std.mem.trimEnd(u8, text[bracket + 2 ..], "]") }
            else
                .{ text, "vmlinux" };

            try symbols.append(symbol_allocator, .{
                .name = name,
                .compile_unit_name = module,
                .source_location = null,
            });
        }

        pub fn getModuleName(_: *SelfInfo, _: std.Io, _: usize) std.debug.SelfInfoError![]const u8 {
            return std.debug.SelfInfoError.MissingDebugInfo;
        }

        pub fn getModuleSlide(_: *SelfInfo, _: std.Io, _: usize) std.debug.SelfInfoError!usize {
            return std.debug.SelfInfoError.MissingDebugInfo;
        }
    };
};

fn cErrno(rc: c_int) linux.E {
    return linux.errno(@as(usize, @bitCast(@as(isize, rc))));
}

pub const Task = opaque {
    const Pid = opaque {};
    const PidType = enum(c_int) { pid, tgid, pgid, sid };

    extern fn c_get_current() *Task;
    pub fn current() *Task {
        return c_get_current();
    }

    extern fn wake_up_process(*Task) c_int;
    pub fn wakeUp(this: *Task) c_int {
        return wake_up_process(this);
    }

    extern fn find_get_pid(linux.pid_t) ?*Pid;
    extern fn get_pid_task(*Pid, PidType) ?*Task;
    extern fn put_pid(*Pid) void;
    pub fn fromTid(t: linux.pid_t) ?*Task {
        const pid_struct = find_get_pid(t) orelse return null;
        defer put_pid(pid_struct);
        return get_pid_task(pid_struct, .pid);
    }

    extern fn c_task_tgid_nr(*Task) linux.pid_t;
    pub fn tgidNr(this: *Task) linux.pid_t {
        return c_task_tgid_nr(this);
    }

    extern fn c_get_nr_threads(*Task) c_int;
    pub fn nrThreads(this: *Task) c_int {
        return c_get_nr_threads(this);
    }

    extern fn c_task_is_running(*Task) c_int;
    pub fn isRunning(this: *Task) bool {
        return c_task_is_running(this) != 0;
    }

    extern fn c_task_is_dead(*Task) c_int;
    pub fn isDead(this: *Task) bool {
        return c_task_is_dead(this) != 0;
    }

    pub const WorkNotifyMode = enum(c_int) {
        none = 0,
        @"resume",
        signal,
        signal_no_ipi,
        nmi_current,
    };

    pub const WorkAddError = error{
        KprobeLeakFailed,
        BadConfig,
        TooLateShuttingDown,
        Unknown,
    };

    extern fn c_task_work_resolve() c_int;
    pub fn resolveWorkAdd() WorkAddError!void {
        return switch (cErrno(c_task_work_resolve())) {
            .SUCCESS => {},
            .NOSYS => WorkAddError.KprobeLeakFailed,
            else => WorkAddError.Unknown,
        };
    }

    extern fn c_task_work_add(*Task, *CallbackHead, WorkNotifyMode) c_int;
    pub fn workAdd(this: *Task, work: *CallbackHead, notify: WorkNotifyMode) WorkAddError!void {
        return switch (cErrno(c_task_work_add(this, work, notify))) {
            .SUCCESS => {},
            .NOSYS => WorkAddError.KprobeLeakFailed,
            .INVAL => WorkAddError.BadConfig,
            .SRCH => WorkAddError.TooLateShuttingDown,
            else => WorkAddError.Unknown,
        };
    }

    extern fn c_snapshot_executable_vmas(*Task, ?[*:0]const u8, [*]VmaRange, c_int) c_int;
    pub fn snapshotExecutableVmas(this: *Task, filter: ?[*:0]const u8, buffer: []VmaRange) usize {
        return @intCast(c_snapshot_executable_vmas(this, filter, buffer.ptr, @intCast(buffer.len)));
    }

    extern fn c_get_task_struct(*Task) void;
    pub fn get(this: *Task) void {
        c_get_task_struct(this);
    }

    extern fn c_put_task_struct(*Task) void;
    pub fn put(this: *Task) void {
        c_put_task_struct(this);
    }
};

pub const CallbackHead = extern struct {
    next: ?*CallbackHead align(@alignOf(usize)),
    func: Func,

    pub const Func = *const fn (*CallbackHead) callconv(.c) void;
};

pub const VmaRange = extern struct {
    begin: usize,
    end: usize,

    pub fn contains(this: VmaRange, ip: usize) bool {
        return ip -% this.begin < this.end - this.begin;
    }
};

pub const Chardev = extern struct {
    _: [512]u8 align(8) = undefined,
    pub const IoctlFn = ?*const fn (*anyopaque, c_uint, c_ulong) callconv(.c) c_long;

    pub const RegisterError = error{
        OutOfMemory,
        Busy,
        Unexpected,
    };

    extern fn c_chardev_register(*Chardev, [*:0]const u8, IoctlFn) c_int;
    pub fn register(this: *Chardev, name: [:0]const u8, ioctl: IoctlFn) RegisterError!void {
        return switch (cErrno(c_chardev_register(this, name.ptr, ioctl))) {
            .SUCCESS => {},
            .NOMEM => RegisterError.OutOfMemory,
            .BUSY => RegisterError.Busy,
            else => RegisterError.Unexpected,
        };
    }

    extern fn c_chardev_unregister(*Chardev) void;
    pub fn unregister(this: *Chardev) void {
        c_chardev_unregister(this);
    }
};

pub const File = opaque {
    extern fn c_session_progress_page(*File) *anyopaque;
    pub fn sessionProgressPage(this: *File) *std.atomic.Value(usize) {
        return @ptrCast(@alignCast(c_session_progress_page(this)));
    }

    extern fn c_session_get_engine(*File) ?*anyopaque;
    pub fn sessionGetEngine(this: *File) ?*anyopaque {
        return c_session_get_engine(this);
    }

    extern fn c_session_set_engine(*File, ?*anyopaque) void;
    pub fn sessionSetEngine(this: *File, engine: ?*anyopaque) void {
        c_session_set_engine(this, engine);
    }

    extern fn c_session_lock(*File) void;
    pub fn sessionLock(this: *File) void {
        c_session_lock(this);
    }

    extern fn c_session_unlock(*File) void;
    pub fn sessionUnlock(this: *File) void {
        c_session_unlock(this);
    }
};

pub const PerfOverflowHandler = *const fn (*PerfEvent, *anyopaque, *PtRegs) callconv(.c) void;

pub const PerfEvent = opaque {
    extern fn perf_event_release_kernel(*PerfEvent) c_int;
    pub fn releaseKernel(this: *PerfEvent) c_int {
        return perf_event_release_kernel(this);
    }

    extern fn perf_event_enable(*PerfEvent) void;
    pub fn enable(this: *PerfEvent) void {
        perf_event_enable(this);
    }

    extern fn perf_event_disable(*PerfEvent) void;
    pub fn disable(this: *PerfEvent) void {
        perf_event_disable(this);
    }

    extern fn c_perf_event_overflow_handler_context(*PerfEvent) ?*anyopaque;
    pub fn overflowHandlerContext(this: *PerfEvent) ?*anyopaque {
        return c_perf_event_overflow_handler_context(this);
    }

    pub const CreateKernelCounterError = error{
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

    extern fn perf_event_create_kernel_counter(*linux.perf_event_attr, c_int, ?*Task, PerfOverflowHandler, ?*anyopaque) usize;
    pub fn createKernelCounter(
        attr: *linux.perf_event_attr,
        cpu: c_int,
        task: ?*Task,
        overflow_handler: PerfOverflowHandler,
        context: ?*anyopaque,
    ) CreateKernelCounterError!*PerfEvent {
        const rc = perf_event_create_kernel_counter(attr, cpu, task, overflow_handler, context);
        return switch (linux.errno(rc)) {
            .SUCCESS => @ptrFromInt(rc),
            .INVAL => CreateKernelCounterError.InvalidConfiguration,
            .SRCH => CreateKernelCounterError.TaskNotFound,
            .NODEV => CreateKernelCounterError.CpuOffline,
            .BUSY => CreateKernelCounterError.HardwareBusy,
            .OPNOTSUPP => CreateKernelCounterError.NotSupported,
            .NOMEM => CreateKernelCounterError.OutOfMemory,
            .NOENT => CreateKernelCounterError.HardwareNotFound,
            .@"2BIG" => CreateKernelCounterError.InvalidAttributeSize,
            else => CreateKernelCounterError.Unexpected,
        };
    }
};

pub const tracepoint = struct {
    extern fn c_tracepoint_init() void;
    pub fn init() void {
        c_tracepoint_init();
    }

    extern fn c_tracepoint_synchronize_unregister() void;
    pub fn synchronizeUnregister() void {
        c_tracepoint_synchronize_unregister();
    }
};

pub const RegisterTraceError = error{Failed};
pub const SchedWakingProbe = *const fn (data: ?*anyopaque, task: *Task) callconv(.c) void;
pub const SchedSwitchProbe = *const fn (data: ?*anyopaque, preempt: bool, prev: *Task, next: *Task) callconv(.c) void;
pub const SchedProcessExitProbe = *const fn (data: ?*anyopaque, task: *Task, group_dead: bool) callconv(.c) void;
pub const TaskNewtaskProbe = *const fn (data: ?*anyopaque, task: *Task, clone_flags: c_ulong) callconv(.c) void;

extern fn c_register_trace_sched_waking(SchedWakingProbe, ?*anyopaque) c_int;
pub fn registerTraceSchedWaking(probe: SchedWakingProbe, data: ?*anyopaque) RegisterTraceError!void {
    if (c_register_trace_sched_waking(probe, data) != 0) return RegisterTraceError.Failed;
}

extern fn c_unregister_trace_sched_waking(SchedWakingProbe, ?*anyopaque) void;
pub fn unregisterTraceSchedWaking(probe: SchedWakingProbe, data: ?*anyopaque) void {
    c_unregister_trace_sched_waking(probe, data);
}

extern fn c_register_trace_sched_switch(SchedSwitchProbe, ?*anyopaque) c_int;
pub fn registerTraceSchedSwitch(probe: SchedSwitchProbe, data: ?*anyopaque) RegisterTraceError!void {
    if (c_register_trace_sched_switch(probe, data) != 0) return RegisterTraceError.Failed;
}

extern fn c_unregister_trace_sched_switch(SchedSwitchProbe, ?*anyopaque) void;
pub fn unregisterTraceSchedSwitch(probe: SchedSwitchProbe, data: ?*anyopaque) void {
    c_unregister_trace_sched_switch(probe, data);
}

extern fn c_register_trace_sched_process_exit(SchedProcessExitProbe, ?*anyopaque) c_int;
pub fn registerTraceSchedProcessExit(probe: SchedProcessExitProbe, data: ?*anyopaque) RegisterTraceError!void {
    if (c_register_trace_sched_process_exit(probe, data) != 0) return RegisterTraceError.Failed;
}

extern fn c_unregister_trace_sched_process_exit(SchedProcessExitProbe, ?*anyopaque) void;
pub fn unregisterTraceSchedProcessExit(probe: SchedProcessExitProbe, data: ?*anyopaque) void {
    c_unregister_trace_sched_process_exit(probe, data);
}

extern fn c_register_trace_task_newtask(TaskNewtaskProbe, ?*anyopaque) c_int;
pub fn registerTraceTaskNewtask(probe: TaskNewtaskProbe, data: ?*anyopaque) RegisterTraceError!void {
    if (c_register_trace_task_newtask(probe, data) != 0) return RegisterTraceError.Failed;
}

extern fn c_unregister_trace_task_newtask(TaskNewtaskProbe, ?*anyopaque) void;
pub fn unregisterTraceTaskNewtask(probe: TaskNewtaskProbe, data: ?*anyopaque) void {
    c_unregister_trace_task_newtask(probe, data);
}

extern fn c_in_task() c_int;

/// True when running in process context (not hardirq/softirq/NMI).
pub fn inTask() bool {
    return c_in_task() != 0;
}

extern fn c_preemptible() c_int;
pub fn preemptible() bool {
    return c_preemptible() != 0;
}

extern fn c_in_atomic() c_int;
fn inAtomic() bool {
    return c_in_atomic() != 0;
}

extern fn c_irqs_disabled() c_int;
fn irqsDisabled() bool {
    return c_irqs_disabled() != 0;
}

pub fn assertSleepable() void {
    std.debug.assert(!inAtomic() and !irqsDisabled());
}

extern fn c_user_mode(*PtRegs) c_int;
fn userMode(regs: *PtRegs) bool {
    return c_user_mode(regs) != 0;
}

extern fn copy_from_user_nofault(*anyopaque, usize, usize) c_long;
fn copyFromUserNofault(dst: []u8, src: usize) c_long {
    return copy_from_user_nofault(dst.ptr, src, dst.len);
}

extern fn c_current_user_ip() usize;
pub fn currentUserSpaceIp(sample_regs: *PtRegs) usize {
    const syscall_instruction = switch (@import("builtin").cpu.arch) {
        .x86_64 => [_]u8{ 0x0f, 0x05 },
        else => @compileError("TODO: support other archs"),
    };

    if (userMode(sample_regs)) return sample_regs.ip;

    const ip = c_current_user_ip();
    const call_site = ip -% syscall_instruction.len;
    var opcode: [syscall_instruction.len]u8 = undefined;

    return if (copyFromUserNofault(&opcode, call_site) != 0 or
        !std.mem.eql(u8, &opcode, &syscall_instruction))
        ip
    else
        call_site;
}

pub const preempt = struct {
    extern fn c_preempt_disable() void;
    extern fn c_preempt_enable() void;

    pub inline fn disable() void {
        c_preempt_disable();
    }

    pub inline fn enable() void {
        c_preempt_enable();
    }
};

test "Allocator" {
    try std.heap.testAllocator(heap.allocator);
    try std.heap.testAllocatorAligned(heap.allocator);
    try std.heap.testAllocatorAlignedShrink(heap.allocator);
    try std.heap.testAllocatorLargeAlignment(heap.allocator);
}
