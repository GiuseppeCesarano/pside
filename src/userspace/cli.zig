//TODO: swap for https://codeberg.org/ziglang/zig/issues/30677

const std = @import("std");

fn OptionsImpl(ItType: type) type {
    return struct {
        pub const Iterator = struct {
            pub const Mask = std.bit_set.IntegerBitSet(128);
            args: ItType,
            mask: Mask.MaskInt,

            pub fn next(this: *Iterator) ?[]const u8 {
                while (this.mask & 1 == 0 and this.args.next() != null) : (this.mask >>= 1) {}

                this.mask >>= 1;
                return this.args.next();
            }

            pub fn count(this: Iterator) usize {
                return @popCount(this.mask);
            }
        };

        pub fn Parsed(FlagsSchema: type) type {
            return struct {
                flags: FlagsSchema,
                positional_arguments: ?Iterator,
                unknown_flags: ?Iterator,
                parse_errors: ?Iterator,
            };
        }

        args: ItType,

        pub fn parse(this: @This(), FlagsSchema: type) Parsed(FlagsSchema) {
            const schema = @typeInfo(FlagsSchema).@"struct";
            var parsed_flags: FlagsSchema = .{};

            var args = this.args;
            const Mask = Iterator.Mask;
            var positional_mask: Mask = .empty;
            var unknown_flags_mask: Mask = .empty;
            var parse_errors_mask: Mask = .empty;
            var i: usize = 0;

            while (args.next()) |arg| : (i += 1) {
                if (i + 1 >= Mask.bit_length) {
                    parse_errors_mask = .full;
                    break;
                }

                const is_positional = !std.mem.startsWith(u8, arg, "-");
                positional_mask.setValue(i, is_positional);
                if (is_positional) continue;

                inline for (schema.field_names, schema.field_types) |name, Type| {
                    if (flagSuffix(arg, name)) |suffix| {
                        const parse_target = if (suffix.len != 0)
                            suffix[1..]
                        else if (Type == bool)
                            "true"
                        else if (args.next()) |target| blk: {
                            i += 1;
                            break :blk target;
                        } else break;

                        if (parseValue(Type, parse_target)) |value|
                            @field(parsed_flags, name) = value
                        else |_|
                            parse_errors_mask.set(i);

                        break;
                    }
                } else {
                    unknown_flags_mask.set(i);
                }
            }

            return .{
                .flags = parsed_flags,
                .positional_arguments = if (positional_mask.count() != 0) .{ .mask = positional_mask.mask, .args = this.args } else null,
                .unknown_flags = if (unknown_flags_mask.count() != 0) .{ .mask = unknown_flags_mask.mask, .args = this.args } else null,
                .parse_errors = if (parse_errors_mask.count() != 0) .{ .mask = parse_errors_mask.mask, .args = this.args } else null,
            };
        }
    };
}

fn flagSuffix(arg: []const u8, name: []const u8) ?[]const u8 {
    const suffix = std.mem.cutPrefix(u8, arg[1..], name) orelse return null;
    return if (suffix.len == 0 or suffix[0] == '=') suffix else null;
}

fn parseValue(Type: type, text: []const u8) !Type {
    return switch (Type) {
        i32, i64, u32, u64 => std.fmt.parseInt(Type, text, 0),
        f32, f64 => std.fmt.parseFloat(Type, text),
        bool => if (std.mem.eql(u8, text, "true")) true else if (std.mem.eql(u8, text, "false")) false else error.BoolDoNotMatch,
        []const u8 => text,
        else => @compileError("Only the following types are allowed:\ni32\ni64\nu32\nu64\nf32\nf64\nbool\n[]const u8\n"),
    };
}

pub const Options = OptionsImpl(std.process.Args.Iterator);

pub fn execute(
    args_it: anytype,
    comptime default_handler: anytype,
    comptime subcommands: anytype,
    data: anytype,
) !@typeInfo(@TypeOf(default_handler)).@"fn".return_type.? {
    var args = args_it;
    if (args.next()) |possible_subcommand| {
        inline for (subcommands) |subcommand| {
            if (std.mem.eql(u8, possible_subcommand, functionName(subcommand)))
                return @call(.auto, subcommand, prependTuple(data, Options{ .args = args }));
        }
    }

    return @call(.auto, default_handler, prependTuple(data, Options{ .args = args_it }));
}

pub fn validateOptions(optional_errors: ?Options.Iterator, comptime msg: []const u8) !void {
    if (optional_errors) |errors| {
        @branchHint(.cold);
        var it = errors;
        while (it.next()) |flag| std.log.err("{s}{s}", .{ msg, flag });
        return error.InvalidOption;
    }
}

fn functionName(comptime function: anytype) []const u8 {
    @setEvalBranchQuota(10_000);
    if (@typeInfo(@TypeOf(function)) != .@"fn") @compileError("subcommand field must be populated with a tuple of structs.");

    const type_name = @typeName(@TypeOf(.{function}));
    const start_target = " (function '";
    const function_name_start = comptime std.mem.find(u8, type_name, start_target).? + start_target.len;
    const function_name_end = comptime std.mem.findPos(u8, type_name, function_name_start, "')").?;

    return type_name[function_name_start..function_name_end];
}

fn prependTuple(tuple: anytype, value: anytype) PrependedTuple(@TypeOf(tuple), @TypeOf(value)) {
    var prepended: PrependedTuple(@TypeOf(tuple), @TypeOf(value)) = undefined;

    prepended[0] = value;
    inline for (tuple, 1..) |field, i| {
        prepended[i] = field;
    }

    return prepended;
}

fn PrependedTuple(Tuple: type, Value: type) type {
    const fields_types = @typeInfo(Tuple).@"struct".field_types;

    var types: [fields_types.len + 1]type = undefined;
    types[0] = Value;

    @memcpy(types[1..], fields_types);

    return @Tuple(&types);
}

const OptionsTest = OptionsImpl(std.mem.SplitIterator(u8, .scalar));

test "all types via =value" {
    const Flags = struct {
        i32: i32 = 0,
        i64: i64 = 0,
        u32: u32 = 0,
        u64: u64 = 0,
        f32: f32 = 0,
        f64: f64 = 0,
        b: bool = false,
    };

    const parsed = (OptionsTest{ .args = std.mem.splitScalar(u8, "-i32=10 -i64=20 -u32=30 -u64=40 -f32=1.5 -f64=2.25 -b=true", ' ') }).parse(Flags).flags;

    try std.testing.expect(parsed.i32 == 10);
    try std.testing.expect(parsed.i64 == 20);
    try std.testing.expect(parsed.u32 == 30);
    try std.testing.expect(parsed.u64 == 40);
    try std.testing.expect(std.math.approxEqAbs(f32, parsed.f32, 1.5, 0.0001));
    try std.testing.expect(std.math.approxEqAbs(f64, parsed.f64, 2.25, 0.0001));
    try std.testing.expect(parsed.b == true);
}

test "space separated" {
    const Flags = struct {
        x: i32 = 0,
        y: f64 = 0,
        s: []const u8 = "default",
    };

    const parsed = (OptionsTest{ .args = std.mem.splitScalar(u8, "-x 999 -y 123.75 -s hello", ' ') }).parse(Flags).flags;

    try std.testing.expect(parsed.x == 999);
    try std.testing.expect(std.math.approxEqAbs(f64, parsed.y, 123.75, 0.0001));
    try std.testing.expect(std.mem.eql(u8, parsed.s, "hello"));
}

test "bool auto-true" {
    const Flags = struct { verbose: bool = false };
    const parsed = (OptionsTest{ .args = std.mem.splitScalar(u8, "-verbose", ' ') }).parse(Flags).flags;

    try std.testing.expect(parsed.verbose == true);
}

test "string with =" {
    const Flags = struct { name: []const u8 = "" };
    const parsed = (OptionsTest{ .args = std.mem.splitScalar(u8, "-name=alpha", ' ') }).parse(Flags).flags;

    try std.testing.expect(std.mem.eql(u8, parsed.name, "alpha"));
}

test "last wins" {
    const Flags = struct { x: i32 = 0 };
    const parsed = (OptionsTest{ .args = std.mem.splitScalar(u8, "-x=1 -x=2 -x=3", ' ') }).parse(Flags).flags;

    try std.testing.expect(parsed.x == 3);
}

test "non-flags and unmatched flags iteration" {
    const Flags = struct { x: i32 = 0 };

    const input = "-x=1 file1 -bad -x=2 file2 -unknown=val file3 -x=3";
    const res = (OptionsTest{ .args = std.mem.splitScalar(u8, input, ' ') }).parse(Flags);

    try std.testing.expect(res.flags.x == 3);

    var nf = res.positional_arguments.?;
    try std.testing.expect(nf.count() == 3);
    try std.testing.expect(std.mem.eql(u8, nf.next().?, "file1"));
    try std.testing.expect(std.mem.eql(u8, nf.next().?, "file2"));
    try std.testing.expect(std.mem.eql(u8, nf.next().?, "file3"));

    var uf = res.unknown_flags.?;
    try std.testing.expect(uf.count() == 2);
    try std.testing.expect(std.mem.eql(u8, uf.next().?, "-bad"));
    try std.testing.expect(std.mem.eql(u8, uf.next().?, "-unknown=val"));
}

test "parse error: invalid int" {
    const Flags = struct {
        x: i32 = 0,
    };

    const res = (OptionsTest{
        .args = std.mem.splitScalar(u8, "-x=lol", ' '),
    }).parse(Flags);

    try std.testing.expect(res.flags.x == 0);

    var pe = res.parse_errors.?;
    try std.testing.expect(pe.count() == 1);

    const first = pe.next().?;
    try std.testing.expect(std.mem.eql(u8, first, "-x=lol"));
    try std.testing.expect(pe.next() == null);
}

test "parse error: invalid float" {
    const Flags = struct {
        y: f64 = 0,
    };

    const res = (OptionsTest{
        .args = std.mem.splitScalar(u8, "-y=NaNish", ' '),
    }).parse(Flags);

    try std.testing.expect(res.flags.y == 0);

    var pe = res.parse_errors.?;
    try std.testing.expect(pe.count() == 1);

    const first = pe.next().?;
    try std.testing.expect(std.mem.eql(u8, first, "-y=NaNish"));
}

test "parse error: invalid bool" {
    const Flags = struct {
        b: bool = false,
    };

    const res = (OptionsTest{
        .args = std.mem.splitScalar(u8, "-b=maybe", ' '),
    }).parse(Flags);

    try std.testing.expect(res.flags.b == false);

    var pe = res.parse_errors.?;
    try std.testing.expect(pe.count() == 1);

    const first = pe.next().?;
    try std.testing.expect(std.mem.eql(u8, first, "-b=maybe"));
}

test "multiple parse errors" {
    const Flags = struct {
        a: i32 = 0,
        b: f32 = 0,
    };

    const input = "-a=lol -b=notfloat";
    const res = (OptionsTest{
        .args = std.mem.splitScalar(u8, input, ' '),
    }).parse(Flags);

    try std.testing.expect(res.flags.a == 0);
    try std.testing.expect(res.flags.b == 0);

    var pe = res.parse_errors.?;
    try std.testing.expect(pe.count() == 2);

    const one = pe.next().?;
    const two = pe.next().?;

    try std.testing.expect(std.mem.eql(u8, one, "-a=lol"));
    try std.testing.expect(std.mem.eql(u8, two, "-b=notfloat"));
    try std.testing.expect(pe.next() == null);
}

test "parse error does not interfere with valid flags" {
    const Flags = struct {
        x: i32 = 0,
        y: i32 = 0,
    };

    const input = "-x=10 -y=bad -x=20";
    const res = (OptionsTest{
        .args = std.mem.splitScalar(u8, input, ' '),
    }).parse(Flags);

    try std.testing.expect(res.flags.x == 20);

    try std.testing.expect(res.flags.y == 0);

    var pe = res.parse_errors.?;
    try std.testing.expect(pe.count() == 1);
    try std.testing.expect(std.mem.eql(u8, pe.next().?, "-y=bad"));
}

test "parse_errors iterator: mixed flags, unknown flags, and parse errors" {
    const Flags = struct {
        a: i32 = 0,
        b: i32 = 0,
    };

    const input = "-a=lol file -b maybe -unknown=5 -a=5 -b=-93";

    const res = (OptionsTest{
        .args = std.mem.splitScalar(u8, input, ' '),
    }).parse(Flags);

    try std.testing.expect(res.flags.a == 5);
    try std.testing.expect(res.flags.b == -93);

    var pe = res.parse_errors.?;
    try std.testing.expect(pe.count() == 2);

    const e1 = pe.next().?;
    try std.testing.expect(std.mem.eql(u8, e1, "-a=lol"));
}
