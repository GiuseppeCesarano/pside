const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const File = std.Io.File;
const Dir = std.Io.Dir;
const HostName = net.HostName;
const IpAddress = net.IpAddress;
const process = std.process;
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const assert = std.debug.assert;

const bindings = @import("bindings.zig");
const kernel = @import("kernel.zig");

const KernelIo = @This();

allocator: Allocator,
atomic_allocator: Allocator,

lock: bindings.Spinlock,

jobs: std.DoublyLinkedList,

idle_workers: std.SinglyLinkedList,
workers_count: std.atomic.Value(u32),
stop_workers: std.atomic.Value(bool),
stopped_workers: bindings.Completion,

// TODO: https://codeberg.org/ziglang/zig/pulls/31235
files: [max_files]std.atomic.Value(?*bindings.File),
const max_files = 16;

// TODO: #31235
pub const AdoptFileError = error{ BadFileDescriptor, ProcessFdQuotaExceeded };

pub fn init(
    this: *KernelIo,
    allocator: Allocator,
    atomic_allocator: Allocator,
    workers_count: u32,
) !void {
    errdefer this.* = undefined;

    this.allocator = allocator;
    this.atomic_allocator = atomic_allocator;

    this.lock.init();

    this.jobs = .{};

    this.idle_workers = .{};
    this.workers_count = .init(0);
    this.stop_workers = .init(false);
    this.stopped_workers.init();

    // TODO:REMOVE ME #31235
    this.files = @splat(.init(null));

    try this.startWorkers(workers_count);
}

// TODO: #31235
pub fn adoptFile(this: *KernelIo, fd: std.os.linux.fd_t) AdoptFileError!File {
    const fd_index = std.math.cast(c_uint, fd) orelse return AdoptFileError.BadFileDescriptor;
    const kernel_file = bindings.File.get(fd_index) orelse return AdoptFileError.BadFileDescriptor;
    errdefer kernel_file.put();

    for (&this.files, 0..) |*slot, index|
        if (slot.cmpxchgStrong(null, kernel_file, .release, .monotonic) == null)
            return .{ .handle = @intCast(index), .flags = .{ .nonblocking = false } };

    return AdoptFileError.ProcessFdQuotaExceeded;
}

// TODO: #31235
fn adoptedFile(userdata: ?*anyopaque, file: File) ?*bindings.File {
    const kernel_io: *KernelIo = @ptrCast(@alignCast(userdata.?));
    const index = std.math.cast(usize, file.handle).?;
    if (index >= kernel_io.files.len) unreachable;

    return kernel_io.files[index].load(.acquire);
}

fn startWorkers(this: *KernelIo, workers_count: u32) !void {
    errdefer this.stopWorkers();

    for (0..workers_count) |_| {
        const worker = try this.allocator.create(Worker);
        errdefer this.allocator.destroy(worker);

        try worker.spawn(this, null);
    }
}

pub fn deinit(this: *KernelIo) void {
    this.stopWorkers();

    while (this.jobs.popFirst()) |node| {
        const future: *Future = @fieldParentPtr("node", node);
        future.destroy(if (future.atomically_allocated) this.atomic_allocator else this.allocator);
    }
}

fn stopWorkers(this: *KernelIo) void {
    const flags = this.lock.lockIrqsave();
    this.stop_workers.store(true, .monotonic);
    while (this.idle_workers.popFirst()) |node| {
        const worker: *Worker = @fieldParentPtr("node", node);
        worker.waker.complete();
    }
    this.lock.unlockIrqrestore(flags);

    for (0..this.workers_count.load(.monotonic)) |_| this.stopped_workers.wait();
}

pub fn io(this: *KernelIo) Io {
    return .{ .userdata = this, .vtable = &vtable };
}

const vtable: Io.VTable = vtable: {
    var v = Io.failing.vtable.*;
    v.async = async;
    v.concurrent = concurrent;
    v.await = await;
    v.cancel = cancel;
    v.recancel = recancel;
    v.swapCancelProtection = swapCancelProtection;
    v.checkCancel = checkCancel;
    v.futexWait = futexWait;
    v.futexWaitUncancelable = futexWaitUncancelable;
    v.futexWake = futexWake;
    v.now = now;
    v.clockResolution = clockResolution;
    v.sleep = sleep;
    v.fileLength = fileLength;
    v.fileClose = fileClose;
    v.fileWritePositional = fileWritePositional;
    break :vtable v;
};

fn async(
    userdata: ?*anyopaque,
    result: []u8,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    func: *const fn (context: *const anyopaque, result: *anyopaque) void,
) ?*Io.AnyFuture {
    assert(!bindings.inNmi());
    const kernel_io: *KernelIo = @ptrCast(@alignCast(userdata.?));

    const atomic = !kernel.preemptible();
    const future = Future.create(
        if (atomic) kernel_io.atomic_allocator else kernel_io.allocator,
        atomic,
        result.len,
        result_alignment,
        context,
        context_alignment,
        func,
    ) catch {
        func(context.ptr, result.ptr);
        return null;
    };

    const flags = kernel_io.lock.lockIrqsave();
    defer kernel_io.lock.unlockIrqrestore(flags);

    if (kernel_io.idle_workers.popFirst()) |worker_node| {
        const worker: *Worker = @fieldParentPtr("node", worker_node);
        future.status = .running;
        worker.job = future;
        worker.waker.complete();
    } else kernel_io.jobs.append(&future.node);

    return @ptrCast(future);
}

fn concurrent(
    userdata: ?*anyopaque,
    result_len: usize,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    func: *const fn (context: *const anyopaque, result: *anyopaque) void,
) Io.ConcurrentError!*Io.AnyFuture {
    assert(!bindings.inNmi());
    const kernel_io: *KernelIo = @ptrCast(@alignCast(userdata.?));

    const atomic = !kernel.preemptible();
    const allocator = if (atomic) kernel_io.atomic_allocator else kernel_io.allocator;

    const future = Future.create(
        allocator,
        atomic,
        result_len,
        result_alignment,
        context,
        context_alignment,
        func,
    ) catch return Io.ConcurrentError.ConcurrencyUnavailable;
    errdefer future.destroy(allocator);
    future.status = .running;

    const flags = kernel_io.lock.lockIrqsave();

    if (kernel_io.idle_workers.popFirst()) |worker_node| {
        const worker: *Worker = @fieldParentPtr("node", worker_node);
        worker.job = future;
        worker.waker.complete();
        kernel_io.lock.unlockIrqrestore(flags);
    } else {
        kernel_io.lock.unlockIrqrestore(flags);
        if (atomic) return Io.ConcurrentError.ConcurrencyUnavailable;
        const worker = kernel_io.allocator.create(Worker) catch return Io.ConcurrentError.ConcurrencyUnavailable;
        errdefer kernel_io.allocator.destroy(worker);
        worker.spawn(kernel_io, future) catch return Io.ConcurrentError.ConcurrencyUnavailable;
    }

    return @ptrCast(future);
}

fn await(userdata: ?*anyopaque, any_future: *Io.AnyFuture, result: []u8, _: Alignment) void {
    kernel.assertSleepable();
    const kernel_io: *KernelIo = @ptrCast(@alignCast(userdata.?));
    const future: *Future = @ptrCast(@alignCast(any_future));

    const flags = kernel_io.lock.lockIrqsave();
    const not_ran = future.status == .pending;
    if (not_ran) {
        kernel_io.jobs.remove(&future.node);
        future.status = .running;
    }
    kernel_io.lock.unlockIrqrestore(flags);

    if (not_ran) {
        const worker = Worker.current();
        const previous = if (worker) |w| w.job else null;
        if (worker) |w| w.job = future;
        future.start();
        if (worker) |w| w.job = previous;
    }
    _ = future.done.waitState(.idle);

    @memcpy(result, future.resultPointer());
    const allocator = if (future.atomically_allocated) kernel_io.atomic_allocator else kernel_io.allocator;
    future.destroy(allocator);
}

fn cancel(userdata: ?*anyopaque, any_future: *Io.AnyFuture, result: []u8, result_alignment: Alignment) void {
    const future: *Future = @ptrCast(@alignCast(any_future));

    _ = future.cancel.fetchOr(.{ .requested = true }, .seq_cst);
    if (future.runner.load(.seq_cst)) |runner| _ = runner.wakeUp();

    await(userdata, any_future, result, result_alignment);
}

fn recancel(_: ?*anyopaque) void {
    const job = Worker.current().?.job.?;
    const previous = job.cancel.fetchXor(.{ .requested = true, .acknowledged = true }, .monotonic);
    assert(previous.acknowledged and !previous.requested);
}

fn swapCancelProtection(_: ?*anyopaque, new: Io.CancelProtection) Io.CancelProtection {
    const worker = Worker.current() orelse return .blocked;
    const job = worker.job orelse return .blocked;
    const old = job.cancel.load(.monotonic).protection;
    if (old != new) _ = job.cancel.fetchXor(.{ .protection = .blocked }, .monotonic);
    return old;
}

fn checkCancel(_: ?*anyopaque) Io.Cancelable!void {
    const worker = Worker.current() orelse return;
    const job = worker.job orelse return;
    if (job.cancel.cmpxchgStrong(.{ .requested = true }, .{ .acknowledged = true }, .monotonic, .monotonic) == null)
        return error.Canceled;
}

fn futexWait(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: Io.Timeout) Io.Cancelable!void {
    kernel.assertSleepable();
    const word: *const std.atomic.Value(u32) = @ptrCast(ptr);
    const deadline = timeout.toTimestamp(.{ .userdata = userdata, .vtable = &vtable });

    const clock: std.os.linux.clockid_t = if (deadline) |d| toLinuxClock(d.clock) else .MONOTONIC;
    const deadline_ns: ?i64 = if (deadline) |d| @intCast(d.raw.nanoseconds) else null;

    var entry: bindings.WaitBitQueueEntry = .{};
    entry.initWaitVar(ptr, 0);
    const wq_head = bindings.varWaitqueue(ptr);
    defer wq_head.finishWait(&entry);

    var timed_out = false;
    _ = wq_head.prepareToWaitEvent(&entry, .idle);
    while (!timed_out and word.load(.monotonic) == expected) : (_ = wq_head.prepareToWaitEvent(&entry, .idle)) {
        try checkCancel(userdata);
        timed_out = scheduleUntil(clock, deadline_ns);
    }
}

fn futexWaitUncancelable(_: ?*anyopaque, ptr: *const u32, expected: u32) void {
    kernel.assertSleepable();
    const word: *const std.atomic.Value(u32) = @ptrCast(ptr);

    var entry: bindings.WaitBitQueueEntry = .{};
    entry.initWaitVar(ptr, 0);
    const wq_head = bindings.varWaitqueue(ptr);
    defer wq_head.finishWait(&entry);

    _ = wq_head.prepareToWaitEvent(&entry, .idle);
    while (word.load(.monotonic) == expected) : (_ = wq_head.prepareToWaitEvent(&entry, .idle))
        _ = scheduleUntil(.MONOTONIC, null);
}

fn futexWake(_: ?*anyopaque, ptr: *const u32, _: u32) void {
    bindings.smpMb();
    bindings.wakeUpVar(ptr);
}

fn now(_: ?*anyopaque, clock: Io.Clock) Io.Timestamp {
    return .{ .nanoseconds = switch (clock) {
        .real => bindings.ktime.getRealFastNs(),
        .awake => bindings.ktime.getMonoFastNs(),
        .boot => bindings.ktime.getBootFastNs(),
        .cpu_process, .cpu_thread => return .zero,
    } };
}

fn clockResolution(_: ?*anyopaque, clock: Io.Clock) Io.Clock.ResolutionError!Io.Duration {
    return switch (clock) {
        .real, .awake, .boot => .fromNanoseconds(bindings.hrtimerResolution()),
        .cpu_process, .cpu_thread => Io.Clock.ResolutionError.ClockUnavailable,
    };
}

fn sleep(userdata: ?*anyopaque, timeout: Io.Timeout) Io.Cancelable!void {
    kernel.assertSleepable();
    const deadline = timeout.toTimestamp(.{ .userdata = userdata, .vtable = &vtable });

    const clock: std.os.linux.clockid_t = if (deadline) |d| toLinuxClock(d.clock) else .MONOTONIC;
    const deadline_ns: ?i64 = if (deadline) |d| @intCast(d.raw.nanoseconds) else null;

    var timed_out = false;
    while (!timed_out) {
        bindings.setCurrentState(.idle);
        errdefer bindings.setCurrentState(.running);

        try checkCancel(userdata);
        timed_out = scheduleUntil(clock, deadline_ns);
    }
}

fn scheduleUntil(clock: std.os.linux.clockid_t, deadline_ns: ?i64) bool {
    var expires = deadline_ns;
    return bindings.scheduleHrtimeoutRangeClock(if (expires) |*e| e else null, 0, .abs, clock) == 0;
}

fn toLinuxClock(clock: Io.Clock) std.os.linux.clockid_t {
    return switch (clock) {
        .real => .REALTIME,
        .awake => .MONOTONIC,
        .boot => .BOOTTIME,
        .cpu_process, .cpu_thread => unreachable,
    };
}

fn fileLength(userdata: ?*anyopaque, file: File) File.LengthError!u64 {
    const kernel_file = adoptedFile(userdata, file) orelse return File.LengthError.Unexpected;
    return @intCast(kernel_file.size());
}

fn fileClose(userdata: ?*anyopaque, files: []const File) void {
    const kernel_io: *KernelIo = @ptrCast(@alignCast(userdata.?));

    for (files) |file| {
        const index: usize = @intCast(file.handle);
        const kernel_file = kernel_io.files[index].swap(null, .acquire).?;
        kernel_file.put();
    }
}

fn fileWritePositional(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    data_and_splat: []const []const u8,
    splat_repeats: usize,
    offset: u64,
) File.WritePositionalError!usize {
    // TODO: consider vfs_iter_write
    const kernel_file = adoptedFile(userdata, file) orelse return File.WritePositionalError.NotOpenForWriting;
    const data = data_and_splat[0 .. data_and_splat.len - 1];
    const splat = data_and_splat[data_and_splat.len - 1];

    const start = std.math.cast(i64, offset) orelse return File.WritePositionalError.FileTooBig;
    var pos = start;

    if (try kernel_file.write(header, &pos) < header.len) return @intCast(pos - start);

    for (data) |bytes| {
        const written_bytes = kernel_file.write(bytes, &pos) catch |err|
            return if (pos == start) err else @intCast(pos - start);

        if (written_bytes < bytes.len) return @intCast(pos - start);
    }

    for (0..splat_repeats) |_| {
        const written_bytes = kernel_file.write(splat, &pos) catch |err|
            return if (pos == start) err else @intCast(pos - start);

        if (written_bytes < splat.len) return @intCast(pos - start);
    }

    return @intCast(pos - start);
}

const Future = struct {
    node: std.DoublyLinkedList.Node,

    atomically_allocated: bool,

    func: *const fn (context: *const anyopaque, result: *anyopaque) void,
    status: Status,

    cancel: std.atomic.Value(Cancel),
    runner: std.atomic.Value(?*kernel.Task),

    done: bindings.Completion,
    context_alignment: Alignment,
    result_offset: usize,
    alloc_len: usize,

    const Status = enum { pending, running };
    const Cancel = packed struct(u8) {
        requested: bool = false,
        acknowledged: bool = false,
        protection: Io.CancelProtection = .unblocked,
        _: u5 = 0,
    };

    fn create(
        gpa: Allocator,
        atomically_allocated: bool,
        result_len: usize,
        result_alignment: Alignment,
        context: []const u8,
        context_alignment: Alignment,
        func: *const fn (context: *const anyopaque, result: *anyopaque) void,
    ) Allocator.Error!*Future {
        const max_context_misalignment = context_alignment.toByteUnits() -| @alignOf(Future);
        const worst_case_context_offset = context_alignment.forward(@sizeOf(Future) + max_context_misalignment);
        const worst_case_result_offset = result_alignment.forward(worst_case_context_offset + context.len);
        const alloc_len = worst_case_result_offset + result_len;

        const future: *Future = @ptrCast(@alignCast(try gpa.alignedAlloc(u8, .of(Future), alloc_len)));
        errdefer comptime unreachable;

        const actual_context_addr = context_alignment.forward(@intFromPtr(future) + @sizeOf(Future));
        const actual_result_addr = result_alignment.forward(actual_context_addr + context.len);
        const actual_result_offset = actual_result_addr - @intFromPtr(future);
        future.* = .{
            .node = .{},
            .atomically_allocated = atomically_allocated,
            .func = func,
            .status = .pending,
            .cancel = .init(.{}),
            .runner = .init(null),
            .done = undefined,
            .context_alignment = context_alignment,
            .result_offset = actual_result_offset,
            .alloc_len = alloc_len,
        };
        future.done.init();
        @memcpy(future.contextPointer()[0..context.len], context);
        return future;
    }

    fn destroy(future: *Future, gpa: Allocator) void {
        const base: [*]align(@alignOf(Future)) u8 = @ptrCast(future);
        gpa.free(base[0..future.alloc_len]);
    }

    fn resultPointer(future: *Future) [*]u8 {
        const base: [*]u8 = @ptrCast(future);
        return base + future.result_offset;
    }

    fn contextPointer(future: *Future) [*]u8 {
        const base: [*]u8 = @ptrCast(future);
        const context_offset = future.context_alignment.forward(@intFromPtr(future) + @sizeOf(Future)) - @intFromPtr(future);
        return base + context_offset;
    }

    fn start(this: *Future) void {
        this.func(this.contextPointer(), this.resultPointer());
        this.done.complete();
    }
};

pub const Worker = struct {
    kernel_io: *KernelIo,

    node: std.SinglyLinkedList.Node = .{},

    thread: *kernel.Task,
    job: ?*Future,
    waker: bindings.Completion,

    fn spawn(this: *Worker, kernel_io: *KernelIo, job: ?*Future) !void {
        this.kernel_io = kernel_io;
        this.job = job;
        this.waker.init();

        _ = kernel_io.workers_count.fetchAdd(1, .monotonic);
        errdefer _ = kernel_io.workers_count.fetchSub(1, .monotonic);

        _ = try bindings.kthread.run(workerLoop, this, "zig io worker");
    }

    fn current() ?*Worker {
        const task = kernel.Task.current();
        if (bindings.kthread.func(task) != workerLoop) return null;
        return @ptrCast(@alignCast(bindings.kthread.data(task).?));
    }

    fn workerLoop(data: ?*anyopaque) callconv(.c) c_int {
        const this: *Worker = @ptrCast(@alignCast(data.?));
        this.thread = kernel.Task.current();
        const kernel_io = this.kernel_io;

        while (!kernel_io.stop_workers.load(.monotonic)) if (this.job != null)
            this.runJob()
        else
            this.pickJobOrWaitForOne();

        kernel_io.allocator.destroy(this);
        bindings.kthread.completeAndExit(&kernel_io.stopped_workers, 0);
    }

    fn runJob(this: *Worker) void {
        this.job.?.runner.store(this.thread, .monotonic);
        this.job.?.start();
        this.job = null;
    }

    fn pickJobOrWaitForOne(this: *Worker) void {
        const kernel_io = this.kernel_io;

        const flags = kernel_io.lock.lockIrqsave();

        if (kernel_io.stop_workers.load(.monotonic)) {
            kernel_io.lock.unlockIrqrestore(flags);
            return;
        }

        if (kernel_io.jobs.popFirst()) |node| {
            const job: *Future = @fieldParentPtr("node", node);
            job.status = .running;
            this.job = job;
            kernel_io.lock.unlockIrqrestore(flags);
        } else {
            kernel_io.idle_workers.prepend(&this.node);
            kernel_io.lock.unlockIrqrestore(flags);
            _ = this.waker.waitState(.idle);
            this.waker.reinit();
        }
    }
};

pub const Debug = struct {
    kernel_io: KernelIo,

    pub fn init(this: *Debug, allocator: Allocator, atomic_allocator: Allocator) !void {
        try this.kernel_io.init(allocator, atomic_allocator, 0);
    }

    pub fn deinit(this: *Debug) void {
        this.kernel_io.deinit();
    }

    pub fn io(this: *Debug) Io {
        return .{ .userdata = &this.kernel_io, .vtable = &Debug.vtable };
    }

    const vtable: Io.VTable = vtable: {
        var v = KernelIo.vtable;
        v.futexWait = Debug.futexWait;
        v.futexWaitUncancelable = Debug.futexWaitUncancelable;
        v.futexWake = Debug.futexWake;
        break :vtable v;
    };

    fn futexWait(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: Io.Timeout) Io.Cancelable!void {
        const word: *const std.atomic.Value(u32) = @ptrCast(ptr);
        const deadline = timeout.toTimestamp(.{ .userdata = userdata, .vtable = &Debug.vtable });

        while (word.load(.monotonic) == expected) {
            try checkCancel(userdata);
            if (deadline) |d| if (now(userdata, d.clock).nanoseconds >= d.raw.nanoseconds) return;
            std.atomic.spinLoopHint();
        }
    }

    fn futexWaitUncancelable(_: ?*anyopaque, ptr: *const u32, expected: u32) void {
        const word: *const std.atomic.Value(u32) = @ptrCast(ptr);
        while (word.load(.monotonic) == expected) std.atomic.spinLoopHint();
    }

    fn futexWake(_: ?*anyopaque, _: *const u32, _: u32) void {}
};
