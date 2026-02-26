//TODO: swap for https://codeberg.org/ziglang/zig/issues/30677

const std = @import("std");

fn OptionsImpl(ItType: type) type {
    return struct {
        const allowed_types = struct {
            pub const map = struct {
                const types = [_]type{
                    i32,
                    i64,
                    u32,
                    u64,
                    f32,
                    f64,
                    bool,
                    []const u8,
                };

                const names = names_block: {
                    var ret: [types.len][]const u8 = undefined;

                    for (&ret, types) |*name, Type| {
                        name.* = @typeName(Type);
                    }

                    break :names_block ret;
                };
            };

            const Tag = tag_block: {
                var field_values: [map.names.len]u8 = undefined;

                for (&field_values, 0..) |*value, i| {
                    value.* = i;
                }

                break :tag_block @Enum(u8, .exhaustive, &map.names, &field_values);
            };

            const Union = union_block: {
                const Attributes = std.builtin.Type.UnionField.Attributes;

                var fields_attributes: [map.types.len]Attributes = undefined;
                for (&fields_attributes, map.types) |*attributes, Type| {
                    attributes.* = .{ .@"align" = @alignOf(Type) };
                }

                break :union_block @Union(.auto, null, &map.names, &map.types, &fields_attributes);
            };

            pub fn tagFromType(Type: type) Tag {
                const index = std.mem.findScalar(type, &map.types, Type) orelse
                    @compileError("Only the following types are allowed:\ni32\ni64\nu32\nu64\nf32\nf64\nbool\n[]const u8\n");

                return @enumFromInt(index);
            }
        };

        const FlagInfo = struct {
            name: []const u8,
            type_tag: allowed_types.Tag,
            offset_in_parent: usize,

            pub fn init(Parent: type, field: std.builtin.Type.StructField) FlagInfo {
                return .{
                    .name = field.name,
                    .type_tag = allowed_types.tagFromType(field.type),
                    .offset_in_parent = @offsetOf(Parent, field.name),
                };
            }

            fn parseIntoField(this: FlagInfo, parent_ptr: *anyopaque, parse_target: []const u8) !void {
                const value: allowed_types.Union = switch (this.type_tag) {
                    .i32 => .{ .i32 = try std.fmt.parseInt(i32, parse_target, 0) },
                    .i64 => .{ .i64 = try std.fmt.parseInt(i64, parse_target, 0) },
                    .u32 => .{ .u32 = try std.fmt.parseInt(u32, parse_target, 0) },
                    .u64 => .{ .u64 = try std.fmt.parseInt(u64, parse_target, 0) },
                    .f32 => .{ .f32 = try std.fmt.parseFloat(f32, parse_target) },
                    .f64 => .{ .f64 = try std.fmt.parseFloat(f64, parse_target) },
                    .bool => .{ .bool = if (std.mem.eql(u8, parse_target, "true")) true else if (std.mem.eql(u8, parse_target, "false")) false else return error.BoolDoNotMatch },
                    .@"[]const u8" => .{ .@"[]const u8" = parse_target },
                };

                const field_ptr: *anyopaque = @as([*]u8, @ptrCast(parent_ptr)) + this.offset_in_parent;

                inline for (allowed_types.map.types, 0..) |Type, i| {
                    if (i == @intFromEnum(this.type_tag)) {
                        @as(*Type, @ptrCast(@alignCast(field_ptr))).* = @field(value, allowed_types.map.names[i]);
                        return;
                    }
                }
            }
        };

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
            var parsed_flags: FlagsSchema = .{};
            const flags_info = createFlagsInfo(FlagsSchema);

            var args = this.args;
            const Mask = Iterator.Mask;
            var positional_mask: Mask = .initEmpty();
            var unknown_flags_mask: Mask = .initEmpty();
            var parse_errors_mask: Mask = .initEmpty();
            var i: Mask.ShiftInt = 0;

            while (args.next()) |arg| : (i +|= 1) {
                const is_positional = !std.mem.startsWith(u8, arg, "-");
                positional_mask.setValue(i, is_positional);
                if (is_positional) continue;

                for (flags_info) |flag_info| {
                    const postfix = std.mem.cutPrefix(u8, arg[1..], flag_info.name) orelse continue;
                    if (postfix.len != 0 and postfix[0] != '=') continue;

                    const parse_target = if (postfix.len != 0)
                        postfix[1..]
                    else if (flag_info.type_tag == .bool)
                        "true"
                    else if (args.next()) |target| blk: {
                        i +|= 1;
                        break :blk target;
                    } else break;

                    flag_info.parseIntoField(&parsed_flags, parse_target) catch parse_errors_mask.set(i);

                    break;
                } else {
                    unknown_flags_mask.set(i);
                }
            }

            if (i > std.math.maxInt(Mask.ShiftInt)) parse_errors_mask = .initFull();

            return .{
                .flags = parsed_flags,
                .positional_arguments = if (positional_mask.count() != 0) .{ .mask = positional_mask.mask, .args = this.args } else null,
                .unknown_flags = if (unknown_flags_mask.count() != 0) .{ .mask = unknown_flags_mask.mask, .args = this.args } else null,
                .parse_errors = if (parse_errors_mask.count() != 0) .{ .mask = parse_errors_mask.mask, .args = this.args } else null,
            };
        }

        fn createFlagsInfo(FlagsSchema: type) [std.meta.fields(FlagsSchema).len]FlagInfo {
            const info = @typeInfo(FlagsSchema);

            if (info != .@"struct") {
                @compileError("Input must be a struct\n");
            }

            comptime var runtime_flags: [info.@"struct".fields.len]FlagInfo = undefined;
            comptime for (info.@"struct".fields, &runtime_flags) |field, *runtime_flag| {
                runtime_flag.* = .init(FlagsSchema, field);
            };

            return runtime_flags;
        }
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
            if (std.mem.eql(u8, possible_subcommand, &functionName(subcommand)))
                return @call(.auto, subcommand, prependTuple(data, Options{ .args = args }));
        }
    }

    return @call(.auto, default_handler, prependTuple(data, Options{ .args = args_it }));
}

fn functionName(function: anytype) [functionNameLen(function)]u8 {
    const type_name = @typeName(@TypeOf(.{function}));
    const start_target = " (function '";
    const function_name_start = comptime std.mem.find(u8, type_name, start_target).? + start_target.len;
    const function_name_end = comptime std.mem.findPos(u8, type_name, function_name_start, "')").?;

    const name_slice = type_name[function_name_start..function_name_end];

    comptime var name: [name_slice.len]u8 = undefined;
    @memcpy(&name, name_slice);

    return name;
}

fn functionNameLen(function: anytype) usize {
    if (@typeInfo(@TypeOf(function)) != .@"fn") @compileError("subcommand field must be populated with a tuple of structs.");

    const type_name = @typeName(@TypeOf(.{function}));
    const start_target = " (function '";
    const function_name_start = comptime std.mem.find(u8, type_name, start_target).? + start_target.len;
    const function_name_end = comptime std.mem.findPos(u8, type_name, function_name_start, "')").?;

    return type_name[function_name_start..function_name_end].len;
}

fn prependTuple(tuple: anytype, value: anytype) PrependedTuple(@TypeOf(tuple), @TypeOf(value)) {
    var preappended: PrependedTuple(@TypeOf(tuple), @TypeOf(value)) = undefined;

    preappended[0] = value;
    inline for (tuple, 1..) |field, i| {
        preappended[i] = field;
    }

    return preappended;
}

fn PrependedTuple(Tuple: type, Value: type) type {
    const struct_fields = @typeInfo(Tuple).@"struct".fields;

    var types: [struct_fields.len + 1]type = undefined;

    types[0] = Value;
    for (types[1..], struct_fields) |*current_type, field| {
        current_type.* = field.type;
    }

    return std.meta.Tuple(&types);
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

    const parsed = ((OptionsTest{ .args = std.mem.splitScalar(u8, "-i32=10 -i64=20 -u32=30 -u64=40 -f32=1.5 -f64=2.25 -b=true", ' ') }).parse(Flags)).flags;

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

    const parsed = ((OptionsTest{ .args = std.mem.splitScalar(u8, "-x 999 -y 123.75 -s hello", ' ') }).parse(Flags)).flags;

    try std.testing.expect(parsed.x == 999);
    try std.testing.expect(std.math.approxEqAbs(f64, parsed.y, 123.75, 0.0001));
    try std.testing.expect(std.mem.eql(u8, parsed.s, "hello"));
}

test "bool auto-true" {
    const Flags = struct { verbose: bool = false };
    const parsed = ((OptionsTest{ .args = std.mem.splitScalar(u8, "-verbose", ' ') }).parse(Flags)).flags;

    try std.testing.expect(parsed.verbose == true);
}

test "string with =" {
    const Flags = struct { name: []const u8 = "" };
    const parsed = ((OptionsTest{ .args = std.mem.splitScalar(u8, "-name=alpha", ' ') }).parse(Flags)).flags;

    try std.testing.expect(std.mem.eql(u8, parsed.name, "alpha"));
}

test "last wins" {
    const Flags = struct { x: i32 = 0 };
    const parsed = ((OptionsTest{ .args = std.mem.splitScalar(u8, "-x=1 -x=2 -x=3", ' ') }).parse(Flags)).flags;

    try std.testing.expect(parsed.x == 3);
}

test "Options.parse fuzz" {
    const Flags = struct {
        i: i32 = 0,
        f: f64 = 0,
        b: bool = false,
        s: []const u8 = "",
    };

    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            _ = (OptionsTest{ .args = std.mem.splitScalar(u8, input, ' ') }).parse(Flags);
        }
    };

    try std.testing.fuzz(Context{}, Context.testOne, .{});
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
