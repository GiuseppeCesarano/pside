const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub const Ticks = u16;
pub const Epoch = u32;

pub const Master = bitpack struct(u64) {
    ticks: Ticks,
    epoch: Epoch,
    _: u16 = 0,

    pub fn begin(epoch: Epoch) Master {
        return .{ .ticks = 0, .epoch = epoch };
    }
};

pub const Value = bitpack struct(u64) {
    ticks: Ticks,
    master_at_sleep: Ticks,
    epoch: Epoch,

    pub fn at(master: Master) Value {
        return .{ .ticks = master.ticks, .master_at_sleep = master.ticks, .epoch = master.epoch };
    }

    fn inEpoch(this: Value, epoch: Epoch) ?Value {
        if (this.epoch == epoch) return this;
        if (this.epoch > epoch) return null;
        return .at(.begin(epoch));
    }
};

const one_tick: Value = .{ .ticks = 1, .master_at_sleep = 0, .epoch = 0 };

pub const no_recent_hit = std.math.maxInt(u32);

pub const Slot = struct {
    value: std.atomic.Value(Value),
    since_hit: std.atomic.Value(u32),

    fn init(value: Value) Slot {
        return .{ .value = .init(value), .since_hit = .init(no_recent_hit) };
    }

    pub fn lag(this: *const Slot, master: Master) ?Ticks {
        const clock = this.value.load(.monotonic).inEpoch(master.epoch) orelse return null;
        return master.ticks -| clock.ticks;
    }

    pub fn tick(this: *Slot, epoch: Epoch) ?Ticks {
        const old = this.value.fetchAdd(one_tick, .monotonic);
        assert(old.ticks != std.math.maxInt(Ticks));
        if (old.epoch == epoch) return old.ticks + 1;
        if (old.epoch > epoch) return null;

        var ticked = old;
        ticked.ticks += 1;
        const first: Value = .{ .ticks = 1, .master_at_sleep = 0, .epoch = epoch };
        _ = this.value.cmpxchgStrong(ticked, first, .monotonic, .monotonic) orelse return 1;

        const raced = this.value.fetchAdd(one_tick, .monotonic);
        assert(raced.epoch >= epoch);
        return if (raced.epoch == epoch) raced.ticks + 1 else null;
    }

    pub fn catchUp(this: *Slot, master: Master, tolerance: Ticks) ?Ticks {
        const caught_up: Value = .at(master);
        var seen = this.value.load(.monotonic);
        return for (0..max_retries) |_| {
            const clock = seen.inEpoch(master.epoch) orelse break null;
            const behind = master.ticks -| clock.ticks;
            if (behind <= tolerance) break null;
            seen = this.value.cmpxchgWeak(seen, caught_up, .monotonic, .monotonic) orelse break behind;
        } else null;
    }

    pub fn settle(this: *Slot, master: Master) Ticks {
        const clock = this.value.load(.monotonic).inEpoch(master.epoch).?;
        this.value.store(.at(master), .monotonic);
        return master.ticks - clock.ticks;
    }

    pub fn sleep(this: *Slot, master: Master) void {
        var seen = this.value.load(.monotonic);
        for (0..max_retries) |_| {
            var asleep = seen.inEpoch(master.epoch) orelse break;
            asleep.master_at_sleep = master.ticks;
            seen = this.value.cmpxchgWeak(seen, asleep, .monotonic, .monotonic) orelse break;
        }
    }

    pub fn wake(this: *Slot, master: Master, waker_lag: Ticks) ?Ticks {
        const woken: Value = .at(master);
        var seen = this.value.load(.monotonic);
        return for (0..max_retries) |_| {
            const clock = seen.inEpoch(master.epoch) orelse break null;
            const owed = (waker_lag + clock.master_at_sleep) -| clock.ticks;
            seen = this.value.cmpxchgWeak(seen, woken, .monotonic, .monotonic) orelse break owed;
        } else null;
    }

    pub fn countSinceHit(this: *Slot, hit: bool) u32 {
        const since_hit = if (hit) 0 else this.since_hit.load(.monotonic) +| 1;
        this.since_hit.store(since_hit, .monotonic);
        return since_hit;
    }
};

const max_retries = 8;

test "a stale epoch reads as the start of the current one" {
    const stale: Value = .{ .ticks = 900, .master_at_sleep = 950, .epoch = 3 };
    try testing.expectEqual(Value.at(.begin(4)), stale.inEpoch(4).?);
}

test "the first catchUp of an epoch pays from zero" {
    const master: Master = .{ .ticks = 7, .epoch = 5 };
    var slot: Slot = .init(.{ .ticks = 900, .master_at_sleep = 950, .epoch = 4 });
    try testing.expectEqual(7, slot.catchUp(master, 0).?);
    try testing.expectEqual(Value.at(master), slot.value.load(.monotonic));
}

test "every verb refuses a straggler from the previous epoch" {
    const master: Master = .{ .ticks = 900, .epoch = 4 };
    var slot: Slot = .init(.{ .ticks = 2, .master_at_sleep = 1, .epoch = 5 });
    const untouched = slot.value.load(.monotonic);

    try testing.expectEqual(null, slot.lag(master));
    try testing.expectEqual(null, slot.catchUp(master, 0));
    try testing.expectEqual(null, slot.wake(master, 0));
    slot.sleep(master);
    try testing.expectEqual(untouched, slot.value.load(.monotonic));
}

test "lag is how far the slot trails the master" {
    const slot: Slot = .init(.{ .ticks = 3, .master_at_sleep = 3, .epoch = 1 });
    try testing.expectEqual(7, slot.lag(.{ .ticks = 10, .epoch = 1 }).?);
    try testing.expectEqual(0, slot.lag(.{ .ticks = 2, .epoch = 1 }).?);
}

test "tick advances the slot by one and returns where it landed" {
    var slot: Slot = .init(.{ .ticks = 3, .master_at_sleep = 1, .epoch = 1 });
    const ticked: Value = .{ .ticks = 4, .master_at_sleep = 1, .epoch = 1 };
    try testing.expectEqual(4, slot.tick(1).?);
    try testing.expectEqual(ticked, slot.value.load(.monotonic));
}

test "the first tick of an epoch lands on one" {
    var slot: Slot = .init(.{ .ticks = 900, .master_at_sleep = 950, .epoch = 4 });
    const first: Value = .{ .ticks = 1, .master_at_sleep = 0, .epoch = 5 };
    try testing.expectEqual(1, slot.tick(5).?);
    try testing.expectEqual(first, slot.value.load(.monotonic));
}

test "a straggler tick lands on the newer epoch but reports nothing" {
    var slot: Slot = .init(.{ .ticks = 2, .master_at_sleep = 1, .epoch = 5 });
    const bumped: Value = .{ .ticks = 3, .master_at_sleep = 1, .epoch = 5 };
    try testing.expectEqual(null, slot.tick(4));
    try testing.expectEqual(bumped, slot.value.load(.monotonic));
}

test "catchUp pays the lag and lands on the master" {
    const master: Master = .{ .ticks = 10, .epoch = 1 };
    var slot: Slot = .init(.{ .ticks = 3, .master_at_sleep = 1, .epoch = 1 });
    try testing.expectEqual(7, slot.catchUp(master, 0).?);
    try testing.expectEqual(Value.at(master), slot.value.load(.monotonic));
}

test "catchUp writes nothing while the lag is within tolerance" {
    const master: Master = .{ .ticks = 10, .epoch = 1 };
    const within = [_]struct { Value, Ticks }{
        .{ .{ .ticks = 10, .master_at_sleep = 4, .epoch = 1 }, 0 },
        .{ .{ .ticks = 11, .master_at_sleep = 4, .epoch = 1 }, 0 },
        .{ .{ .ticks = 8, .master_at_sleep = 4, .epoch = 1 }, 2 },
    };
    for (within) |case| {
        const value, const tolerance = case;
        var slot: Slot = .init(value);
        try testing.expectEqual(null, slot.catchUp(master, tolerance));
        try testing.expectEqual(value, slot.value.load(.monotonic));
    }

    var beyond: Slot = .init(.{ .ticks = 8, .master_at_sleep = 4, .epoch = 1 });
    try testing.expectEqual(2, beyond.catchUp(master, 1).?);
    try testing.expectEqual(Value.at(master), beyond.value.load(.monotonic));
}

test "settle pays the lag and lands on the master" {
    const master: Master = .{ .ticks = 10, .epoch = 1 };
    var slot: Slot = .init(.{ .ticks = 3, .master_at_sleep = 1, .epoch = 1 });
    try testing.expectEqual(7, slot.settle(master));
    try testing.expectEqual(Value.at(master), slot.value.load(.monotonic));
}

test "sleep stamps the master without moving the slot" {
    var slot: Slot = .init(.{ .ticks = 3, .master_at_sleep = 0, .epoch = 1 });
    const asleep: Value = .{ .ticks = 3, .master_at_sleep = 9, .epoch = 1 };
    slot.sleep(.{ .ticks = 9, .epoch = 1 });
    try testing.expectEqual(asleep, slot.value.load(.monotonic));
}

test "wake charges the waker's lag plus what was owed at sleep, not the time asleep" {
    const master: Master = .{ .ticks = 50, .epoch = 1 };

    var behind: Slot = .init(.{ .ticks = 3, .master_at_sleep = 9, .epoch = 1 });
    try testing.expectEqual(2 + 6, behind.wake(master, 2).?);
    try testing.expectEqual(Value.at(master), behind.value.load(.monotonic));

    var ahead: Slot = .init(.{ .ticks = 12, .master_at_sleep = 9, .epoch = 1 });
    try testing.expectEqual(5 - 3, ahead.wake(master, 5).?);

    var far_ahead: Slot = .init(.{ .ticks = 20, .master_at_sleep = 9, .epoch = 1 });
    try testing.expectEqual(0, far_ahead.wake(master, 5).?);
}

test "countSinceHit counts misses since the last hit and pins at the sentinel" {
    var slot: Slot = .init(.at(.begin(0)));
    try testing.expectEqual(0, slot.countSinceHit(true));
    try testing.expectEqual(1, slot.countSinceHit(false));

    slot.since_hit.store(no_recent_hit, .monotonic);
    try testing.expectEqual(no_recent_hit, slot.countSinceHit(false));
}
