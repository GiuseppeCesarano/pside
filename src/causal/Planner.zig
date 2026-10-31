const std = @import("std");

const Planner = @This();

prng: std.Random.DefaultPrng,
experiment_duration: std.Io.Duration,

pub const Experiment = struct {
    speedup_percent: u8,
    duration: std.Io.Duration,
};

const initial_experiment_duration: std.Io.Duration = .fromMilliseconds(50);
const max_experiment_duration: std.Io.Duration = .fromSeconds(1);
const progress_grow_threshold = 5;
const progress_decay_threshold = progress_grow_threshold * 4;

pub fn init(seed: u64) Planner {
    return .{
        .prng = .init(seed),
        .experiment_duration = initial_experiment_duration,
    };
}

pub fn nextExperiment(this: *Planner) Experiment {
    const random = this.prng.random();

    // 27 rolls over 21 levels: 0-6 all saturate to 0%, so the baseline every
    // other level is read against gets 7/27 and the rest 1/27 each.
    const roll = random.uintLessThan(u8, 27);
    const speedup_percent = (roll -| 6) * 5;

    return .{
        .speedup_percent = speedup_percent,
        .duration = this.experiment_duration,
    };
}

pub fn adjustDuration(this: *Planner, progress_delta: usize) void {
    if (progress_delta < progress_grow_threshold)
        this.experiment_duration.nanoseconds = @min(max_experiment_duration.nanoseconds, this.experiment_duration.nanoseconds * 2)
    else if (progress_delta > progress_decay_threshold)
        this.experiment_duration.nanoseconds = @max(initial_experiment_duration.nanoseconds, @divTrunc(this.experiment_duration.nanoseconds, 2));
}
