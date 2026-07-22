const std = @import("std");

const ExperimentPlanner = @This();

pub const Experiment = struct {
    speedup_percent: u16,
    delay_per_tick: u16,
};

prng: std.Random.DefaultPrng,

pub fn init(generator_seed: u64) ExperimentPlanner {
    return .{ .prng = .init(generator_seed) };
}

pub fn nextExperiment(this: *ExperimentPlanner, sampler_frequency: u32) Experiment {
    const random = this.prng.random();

    const roll = random.uintLessThan(u16, 27);
    const speedup_percent = (roll -| 6) * 5;
    const sampler_period = 1_000_000 / sampler_frequency;
    const delay_per_tick: u16 = @intCast(((@as(u32, speedup_percent) * sampler_period) / 100));

    return .{ .speedup_percent = speedup_percent, .delay_per_tick = delay_per_tick };
}
