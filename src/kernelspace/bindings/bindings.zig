const std = @import("std");
const linux = std.os.linux;

const Task = @import("kernel.zig").Task;

extern fn c_in_nmi() c_int;
pub fn inNmi() bool {
    return c_in_nmi() != 0;
}

pub const TaskState = enum(c_uint) {
    running = 0x0,
    idle = 0x402,
};

extern fn c_set_current_state(TaskState) void;
pub fn setCurrentState(state: TaskState) void {
    c_set_current_state(state);
}

pub const HrtimerMode = enum(c_uint) { abs = 0x0 };

extern fn schedule_hrtimeout_range_clock(?*i64, u64, HrtimerMode, linux.clockid_t) c_int;
pub fn scheduleHrtimeoutRangeClock(expires: ?*i64, delta: u64, mode: HrtimerMode, clock_id: linux.clockid_t) c_int {
    return schedule_hrtimeout_range_clock(expires, delta, mode, clock_id);
}

pub const kthread = struct {
    pub const ThreadFn = *const fn (?*anyopaque) callconv(.c) c_int;

    pub const RunError = error{
        OutOfMemory,
        Interrupted,
        Unexpected,
    };

    extern fn c_kthread_run(ThreadFn, ?*anyopaque, [*:0]const u8) usize;
    pub fn run(threadfn: ThreadFn, context: ?*anyopaque, name: [*:0]const u8) RunError!*Task {
        const rc = c_kthread_run(threadfn, context, name);
        return switch (linux.errno(rc)) {
            .SUCCESS => @ptrFromInt(rc),
            .NOMEM => RunError.OutOfMemory,
            .INTR => RunError.Interrupted,
            else => RunError.Unexpected,
        };
    }

    extern fn kthread_complete_and_exit(*Completion, c_long) noreturn;
    pub fn completeAndExit(completion: *Completion, code: c_long) noreturn {
        kthread_complete_and_exit(completion, code);
    }

    extern fn kthread_func(*Task) ?ThreadFn;
    pub fn func(task: *Task) ?ThreadFn {
        return kthread_func(task);
    }

    extern fn kthread_data(*Task) ?*anyopaque;
    pub fn data(task: *Task) ?*anyopaque {
        return kthread_data(task);
    }
};

pub const Completion = extern struct {
    _: [64]u8 align(8) = undefined,

    extern fn c_init_completion(*Completion) void;
    pub fn init(this: *Completion) void {
        c_init_completion(this);
    }

    extern fn c_reinit_completion(*Completion) void;
    pub fn reinit(this: *Completion) void {
        c_reinit_completion(this);
    }

    pub fn complete(this: *Completion) void {
        @extern(*const fn (*Completion) callconv(.c) void, .{ .name = "complete" })(this);
    }

    extern fn wait_for_completion(*Completion) void;
    pub fn wait(this: *Completion) void {
        wait_for_completion(this);
    }

    extern fn wait_for_completion_state(*Completion, TaskState) c_int;
    pub fn waitState(this: *Completion, state: TaskState) c_int {
        return wait_for_completion_state(this, state);
    }
};

pub const File = opaque {
    extern fn fget(c_uint) ?*File;
    pub fn get(fd: c_uint) ?*File {
        return fget(fd);
    }

    extern fn fput(*File) void;
    pub fn put(this: *File) void {
        fput(this);
    }

    extern fn c_file_size(*File) i64;
    pub fn size(this: *File) i64 {
        return c_file_size(this);
    }
};

pub const Spinlock = extern struct {
    _: [64]u8 align(8) = undefined,

    pub const IrqFlags = c_ulong;

    extern fn c_spin_lock_init(*Spinlock) void;
    pub fn init(this: *Spinlock) void {
        c_spin_lock_init(this);
    }

    extern fn c_spin_lock_irqsave(*Spinlock) IrqFlags;
    pub fn lockIrqsave(this: *Spinlock) IrqFlags {
        std.debug.assert(!inNmi());
        return c_spin_lock_irqsave(this);
    }

    extern fn c_spin_unlock_irqrestore(*Spinlock, IrqFlags) void;
    pub fn unlockIrqrestore(this: *Spinlock, flags: IrqFlags) void {
        c_spin_unlock_irqrestore(this, flags);
    }
};

pub const WaitBitQueueEntry = extern struct {
    _: [64]u8 align(8) = undefined,

    extern fn init_wait_var_entry(*WaitBitQueueEntry, *const anyopaque, c_int) void;
    pub fn initWaitVar(this: *WaitBitQueueEntry, variable: *const anyopaque, flags: c_int) void {
        init_wait_var_entry(this, variable, flags);
    }
};

pub const WaitQueueHead = opaque {
    extern fn c_prepare_to_wait_event(*WaitQueueHead, *WaitBitQueueEntry, TaskState) c_long;
    pub fn prepareToWaitEvent(this: *WaitQueueHead, entry: *WaitBitQueueEntry, state: TaskState) c_long {
        return c_prepare_to_wait_event(this, entry, state);
    }

    extern fn c_finish_wait(*WaitQueueHead, *WaitBitQueueEntry) void;
    pub fn finishWait(this: *WaitQueueHead, entry: *WaitBitQueueEntry) void {
        c_finish_wait(this, entry);
    }
};

extern fn __var_waitqueue(*const anyopaque) *WaitQueueHead;
pub fn varWaitqueue(variable: *const anyopaque) *WaitQueueHead {
    return __var_waitqueue(variable);
}

extern fn wake_up_var(*const anyopaque) void;
pub fn wakeUpVar(variable: *const anyopaque) void {
    wake_up_var(variable);
}

extern fn c_smp_mb() void;
pub fn smpMb() void {
    c_smp_mb();
}

pub const ktime = struct {
    extern fn ktime_get_real_fast_ns() u64;
    pub fn getRealFastNs() u64 {
        return ktime_get_real_fast_ns();
    }

    extern fn ktime_get_mono_fast_ns() u64;
    pub fn getMonoFastNs() u64 {
        return ktime_get_mono_fast_ns();
    }

    extern fn ktime_get_boot_fast_ns() u64;
    pub fn getBootFastNs() u64 {
        return ktime_get_boot_fast_ns();
    }
};

extern fn c_hrtimer_resolution() c_uint;
pub fn hrtimerResolution() c_uint {
    return c_hrtimer_resolution();
}
