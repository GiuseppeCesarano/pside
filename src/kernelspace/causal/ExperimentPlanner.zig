const std = @import("std");

const ExperimentPlanner = @This();

const initial_experiment_duration = 50 * std.time.us_per_ms;

prng: std.Random.DefaultPrng,
experiment_duration: usize,

pub fn init(seed: u64) ExperimentPlanner {
    return .{
        .prng = .init(seed),
        .experiment_duration = initial_experiment_duration,
    };
}

pub const Experiment = struct {
    speedup_percent: u16,
    delay_per_tick: u16,
    duration: usize,
};

pub fn nextExperiment(this: *ExperimentPlanner, sampler_frequency: u32) Experiment {
    const random = this.prng.random();

    const roll = random.uintLessThan(u16, 27);
    const speedup_percent = (roll -| 6) * 5;
    const sampler_period = 1_000_000 / sampler_frequency;
    const delay_per_tick: u16 = @intCast((@as(u32, speedup_percent) * sampler_period) / 100);

    return .{
        .speedup_percent = speedup_percent,
        .delay_per_tick = delay_per_tick,
        .duration = this.experiment_duration,
    };
}

pub fn extendExperimentDuration(this: *ExperimentPlanner) usize {
    const previous = this.experiment_duration;
    this.experiment_duration = @min(
        1 * std.time.us_per_s,
        previous *| 2,
    );

    return this.experiment_duration - previous;
}

pub fn reduceExperimentDuration(this: *ExperimentPlanner) void {
    this.experiment_duration = @max(
        initial_experiment_duration,
        this.experiment_duration / 2,
    );
}
