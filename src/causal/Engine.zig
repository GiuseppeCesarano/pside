// Time unit convention: All time variables use microseconds (us) unless otherwise marked.

const std = @import("std");
const linux = std.os.linux;

const safety = @import("safety");

const Planner = @import("Planner.zig");
const Sink = @import("Sink.zig");
const Speedup = @import("Speedup.zig");

const Engine = @This();

progress: *std.atomic.Value(usize),

planner: Planner,
sink: Sink,
speedup: Speedup,

profiler: ?std.Io.Future(LoopError!void),
state: safety.State(Lifecycle),
address: safety.Pinned,

const Lifecycle = enum { idle, attached, profiling };
const LoopError = std.Io.Cancelable || Speedup.Error || Sink.Error;
pub const AttachError = Speedup.AttachError;
const clock: std.Io.Clock = .boot;

pub fn init(allocator: std.mem.Allocator, atomic_allocator: std.mem.Allocator, progress_ptr: *std.atomic.Value(usize)) !Engine {
    return .{
        .progress = progress_ptr,

        .planner = .init(0),
        .sink = .empty,
        .speedup = try .init(allocator, atomic_allocator),

        .profiler = null,
        .state = .init(.idle),
        .address = .unbound,
    };
}

pub fn deinit(this: *Engine, io: std.Io) void {
    this.address.assertCurrentIfBound();
    if (this.profiler) |*profiler| profiler.cancel(io) catch {};
    this.speedup.deinit();
    this.sink.deinit(io);

    this.* = undefined;
}

pub fn isProfiling(this: *const Engine) bool {
    return this.profiler != null;
}

pub fn attach(
    this: *Engine,
    io: std.Io,
    pid: linux.pid_t,
    vma_name: [:0]const u8,
    attribute_kernel_samples: bool,
) AttachError!void {
    this.state.assertEql(.idle);
    this.state.transition(.attached);
    errdefer this.state.transition(.idle);

    this.planner = .init(@intCast(pid));
    try this.speedup.profilePid(io, pid, vma_name, attribute_kernel_samples);
}

pub fn start(this: *Engine, io: std.Io, fd: linux.fd_t) !void {
    this.state.assertEql(.attached);
    this.state.transition(.profiling);
    errdefer this.state.transition(.attached);
    this.address.bind();
    errdefer this.address.unbind();

    try this.sink.start(io, fd);
    errdefer this.sink.stop(io);

    this.profiler = try io.concurrent(profilingLoop, .{ this, io });
}

fn profilingLoop(this: *Engine, io: std.Io) LoopError!void {
    while (io.checkCancel()) {
        const experiment = this.planner.nextExperiment();

        const base_progress = this.progress.load(.monotonic);
        const base_time: std.Io.Timestamp = .now(io, clock);
        this.speedup.beginExperiment(experiment.speedup_percent);

        const slept = io.sleep(experiment.duration, clock);
        const outcome = try this.speedup.endExperiment();
        try slept;

        const progress_delta = this.progress.load(.monotonic) -% base_progress;
        const time_delta = base_time.untilNow(io, clock);
        this.planner.adjustDuration(progress_delta);

        if (outcome) |o| try this.sink.recordThroughput(
            io,
            o.relative_ip,
            progress_delta,
            time_delta,
            o.injected_us,
            experiment.speedup_percent,
        );
    } else |_| return std.Io.Cancelable.Canceled;
}
