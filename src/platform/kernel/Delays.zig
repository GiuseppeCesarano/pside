const std = @import("std");
const Allocator = std.mem.Allocator;

const kernel = @import("kernel");
const Task = kernel.Task;

const DelayPool = @import("DelayPool.zig");
pub const Error = DelayPool.Error;

const Delays = @This();

pool: DelayPool,
io: std.Io,
allocator: Allocator,
atomic_allocator: Allocator,

pub const empty: Delays = .{
    .pool = .empty,
    .io = undefined,
    .allocator = undefined,
    .atomic_allocator = undefined,
};

pub fn init(this: *Delays, io: std.Io, allocator: Allocator, atomic_allocator: Allocator) Allocator.Error!void {
    try this.pool.init(io, allocator);
    this.io = io;
    this.allocator = allocator;
    this.atomic_allocator = atomic_allocator;
}

pub fn deinit(this: *Delays) void {
    this.pool.deinit(this.allocator, this.atomic_allocator);
    this.* = undefined;
}

pub fn delay(this: *Delays, task: *Task, us: usize) Error!void {
    if (us == 0 or task.isDead()) return;

    this.pool.delay(this.allocator, this.atomic_allocator, task, us) catch |err| switch (err) {
        // Past exit_task_work the work can never run; the task is off any critical path.
        Error.TooLateShuttingDown => {},
        else => |e| return e,
    };
}

pub fn delayExiting(this: *Delays, task: *Task, us: usize) void {
    std.debug.assert(task == Task.current());
    if (us == 0 or !kernel.preemptible()) return;

    this.io.sleep(.fromMicroseconds(@intCast(us)), .awake) catch unreachable;
}

// Signalling from inside the gate deadlocks against a spinwaiting tracepoint
pub fn pend(this: *Delays, task: *Task, us: usize) Error!void {
    if (us == 0 or task.isDead()) return;
    if (task.isRunning()) return this.delay(task, us);

    try this.pool.pendDelay(this.allocator, this.atomic_allocator, task, us);
}

pub fn flush(this: *Delays) Error!void {
    try this.pool.flushPending();
}
