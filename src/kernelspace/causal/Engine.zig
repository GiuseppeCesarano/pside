// Time unit convention: All time variables use microseconds (us) unless otherwise marked.

const std = @import("std");
const linux = std.os.linux;

const kernel = @import("kernel");

const ExperimentPlanner = @import("ExperimentPlanner.zig");
const ExperimentRecorder = @import("ExperimentRecorder.zig");
const ExperimentRunner = @import("ExperimentRunner.zig");

const Engine = @This();

const progress_grow_threshold = 5;
const progress_decay_threshold = progress_grow_threshold * 4;

progress: *std.atomic.Value(usize),

planner: ExperimentPlanner,
recorder: ExperimentRecorder,
runner: ExperimentRunner,

profiler_thread: ?*kernel.Thread,
deinit_guard: std.atomic.Value(bool),

pub fn init(progress_ptr: *std.atomic.Value(usize)) !Engine {
    return .{
        .progress = progress_ptr,

        .planner = .init(0),
        .recorder = .empty,
        .runner = try .init(),

        .profiler_thread = null,
        .deinit_guard = .init(false),
    };
}

pub fn deinit(this: *Engine) void {
    if (this.deinit_guard.swap(true, .seq_cst)) return;

    if (this.profiler_thread) |t| _ = t.stop();
    this.runner.deinit();
    this.recorder.deinit();
}

pub fn profilePid(
    this: *Engine,
    pid: linux.pid_t,
    fd: linux.fd_t,
    vma_name: [:0]const u8,
    attribute_kernel_samples: bool,
) !void {
    this.planner = .init(@intCast(pid));
    try this.runner.profilePid(pid, vma_name, attribute_kernel_samples);
    try this.recorder.start(fd);
    this.profiler_thread = try kernel.Thread.run(profilingLoop, this, "pside_loop");
}

fn profilingLoop(ctx: ?*anyopaque) callconv(.c) c_int {
    const this: *Engine = @ptrCast(@alignCast(ctx));

    while (!kernel.Thread.shouldStop() and !this.runner.anErrorHasOccurred()) {
        const experiment = this.planner.nextExperiment(ExperimentRunner.sampler_frequency);
        this.runner.beginExperiment(experiment.delay_per_tick);

        const base = this.takeReading();
        const enough_progress = this.runExperimentWindow(experiment.duration, base.progress);

        const relative_ip = this.runner.capturedRelativeIp();
        const should_stop = kernel.Thread.shouldStop() or this.runner.anErrorHasOccurred();

        if (enough_progress and !should_stop and relative_ip != null) {
            this.runner.delayEveryoneLagging();
            this.record(base, relative_ip.?, experiment);
        }

        this.runner.endExperiment();
    }

    return 0;
}

fn runExperimentWindow(this: *Engine, experiment_duration: usize, baseline_progress: usize) bool {
    var progress_delta: usize = 0;
    var duration = experiment_duration;
    var extension: usize = 0;
    while (extension < 8) : (extension += 1) {
        kernel.time.sleep.us(duration);
        progress_delta = this.progress.load(.monotonic) -% baseline_progress;

        if (progress_delta >= progress_grow_threshold or kernel.Thread.shouldStop()) break;
        duration = this.planner.extendExperimentDuration();
    } else return false;

    if (progress_delta > progress_decay_threshold)
        this.planner.reduceExperimentDuration();

    return true;
}

fn record(this: *Engine, base: ExperimentRecorder.Reading, relative_ip: usize, experiment: ExperimentPlanner.Experiment) void {
    const end = this.takeReading();

    this.recorder.recordThroughput(
        base,
        end,
        experiment.delay_per_tick,
        relative_ip,
        experiment.speedup_percent,
    ) catch
        std.log.warn("Writer buffer full, dropping sample", .{});
}

fn takeReading(this: *Engine) ExperimentRecorder.Reading {
    return .{
        .progress = this.progress.load(.monotonic),
        .vclock = this.runner.getMasterClock(),
        .time_us = kernel.time.now.us(),
    };
}
