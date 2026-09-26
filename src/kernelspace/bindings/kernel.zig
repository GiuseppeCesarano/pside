// TODO: this file should be replaced when we have full support
// for translate-c in zig

const std = @import("std");
const linux = std.os.linux;
const arch = @import("builtin").cpu.arch;

const is_target_kernel = @import("builtin").target.os.tag == .freestanding;
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
            const cfree = if (is_target_kernel) c_kfree else std.c.free;

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
        };
    }

    extern fn c_kmalloc(c_ulong) ?*anyopaque;
    pub const allocator: std.mem.Allocator = .{
        .ptr = undefined,
        .vtable = &KAllocator(if (is_target_kernel) c_kmalloc else std.c.malloc).vtable,
    };

    extern fn c_kmalloc_atomic(c_ulong) ?*anyopaque;
    pub const atomic_allocator: std.mem.Allocator = .{
        .ptr = undefined,
        .vtable = &KAllocator(c_kmalloc_atomic).vtable,
    };
};

//TODO: redo
pub const PrintkWriter = struct {
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
        c_printk(@intFromEnum(this.level), text.ptr, text.len);
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

pub const Io = @import("Io.zig");
pub const io = Io.io;

// TODO REDO
pub const debug = struct {
    pub fn getDebugInfoAllocator() std.mem.Allocator {
        return heap.atomic_allocator;
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
        extern fn c_sprint_symbol([*]u8, usize) usize;
        extern fn c_stack_trace_save([*]usize, c_uint, c_uint) c_uint;

        pub const UnwindContext = struct {
            pc: usize,
            addresses: [max_frames]usize,
            len: usize,
            next: usize,

            const max_frames = 32;

            pub fn init(_: *const std.debug.cpu_context.Native) UnwindContext {
                var context: UnwindContext = .{ .pc = 0, .addresses = undefined, .len = 0, .next = 0 };
                context.len = c_stack_trace_save(&context.addresses, max_frames, 0);
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
            const text = buffer[0..c_sprint_symbol(buffer.ptr, address)];

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
            if (usec > 5)
                c_sleep(usec)
            else
                delay.us(usec);
        }
    };
};

fn cErrno(rc: c_int) linux.E {
    return linux.errno(@as(usize, @bitCast(@as(isize, rc))));
}

pub const Task = opaque {
    extern fn c_current_task() *Task;
    pub fn current() *Task {
        return c_current_task();
    }

    extern fn c_get_task_from_tid(linux.pid_t) ?*Task;
    pub fn fromTid(t: linux.pid_t) ?*Task {
        return c_get_task_from_tid(t);
    }

    extern fn c_task_work_resolve() c_int;
    pub fn resolveAddWork() WorkAddError!void {
        return switch (cErrno(c_task_work_resolve())) {
            .SUCCESS => {},
            .NOSYS => WorkAddError.KprobeLeakFailed,
            else => WorkAddError.Unknown,
        };
    }

    extern fn c_pid(*Task) linux.pid_t;
    pub fn pid(this: *Task) linux.pid_t {
        return c_pid(this);
    }

    extern fn c_task_thread_count(*Task) c_int;
    pub fn threadCount(this: *Task) usize {
        return @intCast(c_task_thread_count(this));
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
        KprobeLeakFailed,
        BadConfig,
        TooLateShuttingDown,
        Unknown,
    };

    extern fn c_task_work_add(*Task, *Work, NotifyMode) c_int;
    pub fn addWork(this: *Task, work: *Work, notify_mode: NotifyMode) WorkAddError!void {
        return switch (cErrno(c_task_work_add(this, work, notify_mode))) {
            .SUCCESS => {},
            .NOSYS => WorkAddError.KprobeLeakFailed,
            .INVAL => WorkAddError.BadConfig,
            .SRCH => WorkAddError.TooLateShuttingDown,
            else => WorkAddError.Unknown,
        };
    }

    extern fn c_snapshot_executable_vmas(*Task, ?[*:0]const u8, [*]vma.Range, c_int) c_int;
    pub fn snapshotExecutableVmas(this: *Task, filter: ?[*:0]const u8, buffer: []vma.Range) usize {
        return @intCast(c_snapshot_executable_vmas(this, filter, buffer.ptr, @intCast(buffer.len)));
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

pub const vma = struct {
    pub const Range = extern struct {
        begin: usize,
        end: usize,

        pub fn contains(this: Range, ip: usize) bool {
            return ip -% this.begin < this.end - this.begin;
        }
    };
};

pub const CharDevice = extern struct {
    _: [512]u8 = undefined,
    pub const IoctlHandler = ?*const fn (*anyopaque, c_uint, c_ulong) callconv(.c) c_long;

    pub const RegisterError = error{
        OutOfMemory,
        Busy,
        Unexpected,
    };

    extern fn c_chardev_register(*CharDevice, [*:0]const u8, IoctlHandler) c_int;
    pub fn create(this: *CharDevice, file_name: [:0]const u8, handler: IoctlHandler) RegisterError!void {
        return switch (cErrno(c_chardev_register(this, file_name.ptr, handler))) {
            .SUCCESS => {},
            .NOMEM => RegisterError.OutOfMemory,
            .BUSY => RegisterError.Busy,
            else => RegisterError.Unexpected,
        };
    }

    extern fn c_chardev_unregister(*CharDevice) void;
    pub fn remove(this: *CharDevice) void {
        c_chardev_unregister(this);
    }
};

pub const PerfEvent = opaque {
    const PerfOverflowHandler = *const fn (*PerfEvent, *anyopaque, *PtRegs) callconv(.c) void;

    pub const InitError = error{
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
    pub fn init(attr: *linux.perf_event_attr, cpu: c_int, pid: linux.pid_t, callback: PerfOverflowHandler, cntxt: ?*anyopaque) InitError!*PerfEvent {
        const rc = c_perf_event_create_kernel_counter(attr, cpu, pid, callback, cntxt);
        return switch (linux.errno(rc)) {
            .SUCCESS => @ptrFromInt(rc),
            .INVAL => InitError.InvalidConfiguration,
            .SRCH => InitError.TaskNotFound,
            .NODEV => InitError.CpuOffline,
            .BUSY => InitError.HardwareBusy,
            .OPNOTSUPP => InitError.NotSupported,
            .NOMEM => InitError.OutOfMemory,
            .NOENT => InitError.HardwareNotFound,
            .@"2BIG" => InitError.InvalidAttributeSize,
            else => InitError.Unexpected,
        };
    }

    extern fn c_perf_event_release_kernel(*PerfEvent) c_int;
    pub fn deinit(this: ?*PerfEvent) void {
        if (this) |t| _ = c_perf_event_release_kernel(t);
    }

    extern fn c_perf_event_enable(*PerfEvent) void;
    pub fn enable(this: *PerfEvent) void {
        c_perf_event_enable(this);
    }

    extern fn c_perf_event_disable(*PerfEvent) void;
    pub fn disable(this: *PerfEvent) void {
        c_perf_event_disable(this);
    }

    extern fn c_perf_event_context(*PerfEvent) ?*anyopaque;
    pub fn context(this: *PerfEvent) ?*anyopaque {
        return c_perf_event_context(this);
    }
};

pub const Thread = opaque {
    pub const Handler = *const fn (?*anyopaque) callconv(.c) c_int;

    pub const SpawnError = error{
        OutOfMemory,
        Interrupted,
        Unexpected,
    };

    extern fn c_kthread_run(thread_handler: Handler, data: ?*anyopaque, name: [*:0]const u8) usize;
    pub fn run(thread_handler: Handler, data: ?*anyopaque, name: [*:0]const u8) SpawnError!*Thread {
        const rc = c_kthread_run(thread_handler, data, name);
        return switch (linux.errno(rc)) {
            .SUCCESS => @ptrFromInt(rc),
            .NOMEM => SpawnError.OutOfMemory,
            .INTR => SpawnError.Interrupted,
            else => SpawnError.Unexpected,
        };
    }

    extern fn c_kthread_stop(*Thread) c_int;
    pub fn stop(this: *Thread) c_int {
        return c_kthread_stop(this);
    }

    extern fn c_kthread_should_stop() bool;
    pub fn shouldStop() bool {
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

    pub const RegistrationError = error{
        Failed,
    };

    pub const sched = struct {
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

        pub const process_exit = struct {
            pub const Callback = *const fn (data: ?*anyopaque, task: *Task, group_dead: bool) callconv(.c) void;

            extern fn c_register_sched_process_exit(probe: Callback, data: ?*anyopaque) c_int;
            pub fn register(trace: Callback, data: ?*anyopaque) RegistrationError!void {
                if (c_register_sched_process_exit(trace, data) != 0) return RegistrationError.Failed;
            }

            extern fn c_unregister_sched_process_exit(probe: Callback, data: ?*anyopaque) void;
            pub fn unregister(trace: Callback, data: ?*anyopaque) void {
                c_unregister_sched_process_exit(trace, data);
            }
        };
    };

    pub const task = struct {
        pub const newtask = struct {
            pub const Callback = *const fn (data: ?*anyopaque, task: *Task, clone_flags: c_ulong) callconv(.c) void;

            extern fn c_register_task_newtask(probe: Callback, data: ?*anyopaque) c_int;
            pub fn register(trace: Callback, data: ?*anyopaque) RegistrationError!void {
                if (c_register_task_newtask(trace, data) != 0) return RegistrationError.Failed;
            }

            extern fn c_unregister_task_newtask(probe: Callback, data: ?*anyopaque) void;
            pub fn unregister(trace: Callback, data: ?*anyopaque) void {
                c_unregister_task_newtask(trace, data);
            }
        };
    };
};

pub const execution = struct {
    extern fn c_in_task() c_int;

    /// True when running in process context (not hardirq/softirq/NMI).
    pub fn inTask() bool {
        return c_in_task() != 0;
    }

    extern fn c_can_sleep() c_int;

    pub fn canSleep() bool {
        return c_can_sleep() != 0;
    }

    extern fn c_current_user_ip() usize;
    extern fn c_regs_in_kernel(*PtRegs) c_int;
    extern fn c_copy_from_user_nofault(*anyopaque, usize, usize) c_long;
    pub fn currentUserSpaceIp(sample_regs: *PtRegs) usize {
        const syscall_instruction = switch (@import("builtin").cpu.arch) {
            .x86_64 => [_]u8{ 0x0f, 0x05 },
            else => @compileError("TODO: support other archs"),
        };

        if (c_regs_in_kernel(sample_regs) == 0) return sample_regs.ip;

        const ip = c_current_user_ip();
        const call_site = ip -% syscall_instruction.len;
        var opcode: [syscall_instruction.len]u8 = undefined;

        return if (c_copy_from_user_nofault(&opcode, call_site, opcode.len) != 0 or
            !std.mem.eql(u8, &opcode, &syscall_instruction))
            ip
        else
            call_site;
    }
};

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

pub const Completion = extern struct {
    _: [64]u8 = undefined,

    extern fn c_init_completion(*Completion) void;
    pub fn init(this: *Completion) void {
        c_init_completion(this);
    }

    extern fn c_wait_for_completion(*Completion) void;
    pub fn wait(this: *Completion) void {
        c_wait_for_completion(this);
    }

    extern fn c_wait_for_completion_timeout(*Completion, c_ulong) c_ulong;
    pub fn timedWait(this: *Completion, timeout_ms: c_ulong) bool {
        return c_wait_for_completion_timeout(this, timeout_ms) != 0;
    }

    extern fn c_complete(*Completion) void;
    pub fn signal(this: *Completion) void {
        c_complete(this);
    }

    extern fn c_reinit_completion(*Completion) void;
    pub fn reinit(this: *Completion) void {
        c_reinit_completion(this);
    }
};

pub const File = opaque {
    pub const WriteError = error{WriteFailed};

    extern fn c_fget(linux.fd_t) ?*File;
    pub fn get(fd: linux.fd_t) ?*File {
        return c_fget(fd);
    }

    extern fn c_fput(*File) void;
    pub fn put(this: *File) void {
        c_fput(this);
    }

    extern fn c_kernel_write(*File, [*]const u8, usize, *i64) isize;
    pub fn write(this: *File, buf: []const u8, offset: *i64) WriteError!usize {
        const rc = c_kernel_write(this, buf.ptr, buf.len, offset);
        if (rc < 0) return WriteError.WriteFailed;
        return @intCast(rc);
    }

    pub fn writeAll(this: *File, bytes: []const u8, offset: *i64) WriteError!void {
        var written: usize = 0;
        while (written < bytes.len) {
            const n = try this.write(bytes[written..], offset);
            if (n == 0) return WriteError.WriteFailed;
            written += n;
        }
    }

    extern fn c_file_size(*File) isize;
    pub fn size(this: *File) isize {
        return c_file_size(this);
    }

    extern fn c_session_progress_page(*File) *anyopaque;
    pub fn progressPage(this: *File) *std.atomic.Value(usize) {
        return @ptrCast(@alignCast(c_session_progress_page(this)));
    }

    extern fn c_session_get_engine(*File) ?*anyopaque;
    pub fn getEngine(this: *File) ?*anyopaque {
        return c_session_get_engine(this);
    }

    extern fn c_session_set_engine(*File, ?*anyopaque) void;
    pub fn setEngine(this: *File, engine: ?*anyopaque) void {
        c_session_set_engine(this, engine);
    }

    extern fn c_session_lock(*File) void;
    pub fn lock(this: *File) void {
        c_session_lock(this);
    }

    extern fn c_session_unlock(*File) void;
    pub fn unlock(this: *File) void {
        c_session_unlock(this);
    }
};

test "Allocator" {
    try std.heap.testAllocator(heap.allocator);
    try std.heap.testAllocatorAligned(heap.allocator);
    try std.heap.testAllocatorAlignedShrink(heap.allocator);
    try std.heap.testAllocatorLargeAlignment(heap.allocator);
}
