// Time unit convention: All time variables use microseconds (us) unless otherwise marked.

const std = @import("std");
const Pid = std.os.linux.pid_t;

const kernel = @import("kernel");

const ExperimentPlanner = @import("Engine/ExperimentPlanner.zig");
const ExperimentRecorder = @import("Engine/ExperimentRecorder.zig");
const ExperimentRunner = @import("Engine/ExperimentRunner.zig");

const Engine = @This();

// Experiment pacing: grow the window until the target makes measurable progress,
// shrink it back once progress comes easily again.
const initial_experiment_duration_us = 50 * std.time.us_per_ms;
const max_experiment_duration_us = 1 * std.time.us_per_s;
const progress_grow_threshold = 5;
const progress_decay_threshold = progress_grow_threshold * 4;

progress: *std.atomic.Value(usize),
experiment_duration: usize,

planner: ExperimentPlanner,
recorder: ExperimentRecorder,
runner: ExperimentRunner,

profiler_thread: ?*kernel.Thread,
deinit_guard: std.atomic.Value(bool),

pub fn init(progress_ptr: *std.atomic.Value(usize)) !Engine {
    try kernel.Task.resolveAddWork();

    return .{
        .progress = progress_ptr,
        .experiment_duration = 0,

        .planner = .init(0),
        .recorder = .empty,
        .runner = try .init(),

        .profiler_thread = null,
        .deinit_guard = .init(false),
    };
}

pub fn deinit(this: *Engine) void {
    if (this.deinit_guard.swap(true, .seq_cst)) return;

    // Stopping the loop runs recorder.finish() from inside the thread, so the
    // terminating record lands before the recorder is torn down below.
    if (this.profiler_thread) |t| _ = t.stop();

    this.runner.deinit();
    this.recorder.deinit();
}

pub fn profilePid(this: *Engine, pid: Pid, fd: std.os.linux.fd_t, vma_name: [:0]const u8, attribute_kernel_samples: bool) !void {
    this.planner = .init(@intCast(pid));
    this.experiment_duration = initial_experiment_duration_us;

    try this.runner.profilePid(pid, vma_name, attribute_kernel_samples);

    try this.recorder.start(fd, vma_name);

    this.profiler_thread = try kernel.Thread.run(profilingLoop, this, "pside_loop");
}

fn profilingLoop(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *Engine = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldStop() and !this.runner.anErrorHasOccurred()) {
        const experiment = this.planner.nextExperiment(ExperimentRunner.sampler_frequency);
        this.runner.beginExperiment(experiment.delay_per_tick);

        const base = this.takeReading();
        this.runExperimentWindow(base.progress);

        const relative_ip = this.runner.capturedRelativeIp();
        const should_stop = kernel.Thread.shouldStop() or this.runner.anErrorHasOccurred();

        if (!should_stop and relative_ip != null) {
            this.runner.delayEveryoneLagging();
            this.record(base, relative_ip.?, experiment);
        }

        this.runner.endExperiment();
    }

    this.recorder.finish() catch
        std.log.err("Could not emit last empty record, file corrupted", .{});

    return 0;
}

fn runExperimentWindow(this: *Engine, baseline_progress: usize) void {
    kernel.time.sleep.us(this.experiment_duration);

    var progress_delta = this.progress.load(.monotonic) -% baseline_progress;
    while (progress_delta < progress_grow_threshold and !kernel.Thread.shouldStop()) : (progress_delta = this.progress.load(.monotonic) -% baseline_progress) {
        this.experiment_duration = @min(max_experiment_duration_us, this.experiment_duration *| 2);
        kernel.time.sleep.us(this.experiment_duration / 2);
    }

    if (progress_delta > progress_decay_threshold)
        this.experiment_duration = @max(initial_experiment_duration_us, this.experiment_duration / 2);
}

fn record(this: *Engine, base: ExperimentRecorder.Reading, relative_ip: usize, experiment: ExperimentPlanner.Experiment) void {
    const end = this.takeReading();

    this.recorder.recordThroughput(base, end, experiment.delay_per_tick, relative_ip, experiment.speedup_percent) catch
        std.log.warn("Writer buffer full, dropping sample", .{});
}

fn takeReading(this: *Engine) ExperimentRecorder.Reading {
    return .{
        .progress = this.progress.load(.monotonic),
        .vclock = this.runner.getMasterClock(),
        .time_us = kernel.time.now.us(),
    };
}
