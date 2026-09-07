const Abi = u32;

const sign_mask: u32 = 0x8000_0000;
const exp_mask: u32 = 0x7F80_0000;
const frac_mask: u32 = 0x007F_FFFF;
const implicit_bit: u32 = 0x0080_0000;
const quiet_bit: u32 = 0x0040_0000;
const inf_bits: u32 = 0x7F80_0000;
const default_nan: u32 = 0x7FC0_0000;
const frac_bits = 23;
const exp_bias = 127;
const exp_max = 0xFF;

export fn __divsf3(a: Abi, b: Abi) callconv(.c) Abi {
    return divide(a, b);
}

export fn __floatundisf(a: u64) callconv(.c) Abi {
    return fromUnsigned64(a);
}

fn divide(ua: u32, ub: u32) u32 {
    const sign = (ua ^ ub) & sign_mask;
    const ea: i32 = @intCast((ua & exp_mask) >> frac_bits);
    const eb: i32 = @intCast((ub & exp_mask) >> frac_bits);
    const fa = ua & frac_mask;
    const fb = ub & frac_mask;

    if (ea == exp_max) {
        if (fa != 0) return ua | quiet_bit;
        if (eb == exp_max) return if (fb != 0) ub | quiet_bit else default_nan;
        return sign | inf_bits;
    }
    if (eb == exp_max) {
        if (fb != 0) return ub | quiet_bit;
        return sign;
    }

    var sa: u32 = undefined;
    var na = ea;
    if (ea == 0) {
        if (fa == 0) {
            if (eb == 0 and fb == 0) return default_nan;
            return sign;
        }
        const shift: u5 = @intCast(@clz(fa) - 8);
        sa = fa << shift;
        na = 1 - @as(i32, shift);
    } else {
        sa = fa | implicit_bit;
    }

    var sb: u32 = undefined;
    var nb = eb;
    if (eb == 0) {
        if (fb == 0) return sign | inf_bits;
        const shift: u5 = @intCast(@clz(fb) - 8);
        sb = fb << shift;
        nb = 1 - @as(i32, shift);
    } else {
        sb = fb | implicit_bit;
    }

    const numerator = @as(u64, sa) << 31;
    const quotient = numerator / sb;
    const remainder = numerator % sb;

    var exp = na - nb + exp_bias;
    var drop: u6 = 8;
    if (quotient < @as(u64, 1) << 31) {
        drop = 7;
        exp -= 1;
    }

    if (exp >= exp_max) return sign | inf_bits;

    if (exp <= 0) {
        const extra = 1 - exp;
        if (extra > 40) return sign;
        drop += @intCast(extra);
        exp = 0;
    }

    const sig: u32 = @truncate(quotient >> drop);
    const round = (quotient >> (drop - 1)) & 1;
    const sticky = (quotient & ((@as(u64, 1) << (drop - 1)) - 1)) != 0 or remainder != 0;

    var result = sign | (@as(u32, @intCast(exp)) << frac_bits) | (sig & frac_mask);
    if (round != 0 and (sticky or sig & 1 != 0)) result += 1;
    return result;
}

fn fromUnsigned64(a: u64) u32 {
    if (a == 0) return 0;

    const msb: u32 = 63 - @as(u32, @clz(a));
    const exp: u32 = msb + exp_bias;

    if (msb <= frac_bits) {
        const sig: u32 = @truncate(a << @intCast(frac_bits - msb));
        return (exp << frac_bits) | (sig & frac_mask);
    }

    const drop: u6 = @intCast(msb - frac_bits);
    const sig: u32 = @truncate(a >> drop);
    const round = (a >> (drop - 1)) & 1;
    const sticky = (a & ((@as(u64, 1) << (drop - 1)) - 1)) != 0;

    var result = (exp << frac_bits) | (sig & frac_mask);
    if (round != 0 and (sticky or sig & 1 != 0)) result += 1;
    return result;
}

const std = @import("std");

fn expectDivide(a: f32, b: f32) !void {
    const expected: u32 = @bitCast(a / b);
    const actual = divide(@bitCast(a), @bitCast(b));
    const both_nan = expected & 0x7FFF_FFFF > inf_bits and actual & 0x7FFF_FFFF > inf_bits;
    if (!both_nan and expected != actual) {
        std.debug.print("{d} / {d}: expected {x}, got {x}\n", .{ a, b, expected, actual });
        return error.TestUnexpectedResult;
    }
}

fn expectFromUnsigned64(a: u64) !void {
    const expected: u32 = @bitCast(@as(f32, @floatFromInt(a)));
    const actual = fromUnsigned64(a);
    if (expected != actual) {
        std.debug.print("{d}: expected {x}, got {x}\n", .{ a, expected, actual });
        return error.TestUnexpectedResult;
    }
}

test "divide special values" {
    const values = [_]f32{
        0.0,                    -0.0,
        1.0,                    -1.0,
        2.0,                    0.5,
        3.0,                    -7.25,
        std.math.inf(f32),      -std.math.inf(f32),
        std.math.nan(f32),      std.math.floatMax(f32),
        std.math.floatMin(f32), std.math.floatTrueMin(f32),
        -std.math.floatMin(f32),
    };
    for (values) |a| for (values) |b| try expectDivide(a, b);
}

test "divide random values" {
    var prng: std.Random.DefaultPrng = .init(0x9E3779B97F4A7C15);
    const random = prng.random();
    for (0..200_000) |_| {
        const a: f32 = @bitCast(random.int(u32));
        const b: f32 = @bitCast(random.int(u32));
        try expectDivide(a, b);
    }
}

test "divide subnormal results" {
    var prng: std.Random.DefaultPrng = .init(0xD1B54A32D192ED03);
    const random = prng.random();
    for (0..200_000) |_| {
        const a: f32 = @bitCast(random.uintLessThan(u32, 0x0100_0000));
        const b: f32 = @bitCast(random.int(u32) | 0x4000_0000);
        try expectDivide(a, b);
    }
}

test "fromUnsigned64 boundaries" {
    const values = [_]u64{
        0,                  1,
        2,                  3,
        0x7F_FFFF,          0x80_0000,
        0x80_0001,          0xFF_FFFF,
        0x100_0000,         0x100_0001,
        0x100_0002,         0x100_0003,
        1 << 32,            (1 << 32) + 1,
        1 << 63,            (1 << 63) + (1 << 39),
        std.math.maxInt(u64),
        std.math.maxInt(u64) - 1,
    };
    for (values) |a| try expectFromUnsigned64(a);
}

test "fromUnsigned64 random values" {
    var prng: std.Random.DefaultPrng = .init(0xBF58476D1CE4E5B9);
    const random = prng.random();
    for (0..200_000) |_| {
        try expectFromUnsigned64(random.int(u64));
        try expectFromUnsigned64(random.uintLessThan(u64, 1 << 30));
    }
}
