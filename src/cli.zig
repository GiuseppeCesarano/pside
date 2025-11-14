const std = @import("std");

fn OptionsImpl(ItType: type) type {
    return struct {
        const AllowedTypes = enum {
            i32,
            i64,
            u32,
            u64,
            f32,
            f64,
            bool,
            str,

            pub fn fromType(Type: type) @This() {
                return switch (Type) {
                    i32 => .i32,
                    i64 => .i64,
                    u32 => .u32,
                    u64 => .u64,
                    f32 => .f32,
                    f64 => .f64,
                    bool => .bool,
                    []const u8 => .str,

                    else => @compileError("Only the following types are allowed:\ni32\ni64\nu32\nu64\nf32\nf64\nbool\n[]const u8\n"),
                };
            }
            pub fn toType(t: @This()) type {
                return switch (t) {
                    .i32 => i32,
                    .i64 => i64,
                    .u32 => u32,
                    .u64 => u64,
                    .f32 => f32,
                    .f64 => f64,
                    .bool => bool,
                    .str => []const u8,
                };
            }
        };

        const RuntimeFlagInfo = struct {
            const FieldInfo = struct {
                type: AllowedTypes,
                offset: usize,
            };

            name: []const u8,
            field: FieldInfo,

            pub fn init(Parent: type, field: std.builtin.Type.StructField) @This() {
                if (field.is_comptime) @compileLog(field.name ++ "\n");

                return .{
                    .name = field.name,
                    .field = .{ .type = .fromType(field.type), .offset = @offsetOf(Parent, field.name) },
                };
            }
        };

        args_it: ItType,

        pub fn parseFlags(this: @This(), Flags: type) !Flags {
            var parsed_flags: Flags = .{};
            const flags_info = createRuntimeFlagsInfo(Flags);

            var args_it_copy = this.args_it;
            while (args_it_copy.next()) |arg| {
                if (!std.mem.startsWith(u8, arg, "-")) continue;

                for (flags_info) |flag_info| {
                    if (!std.mem.startsWith(u8, arg[1..], flag_info.name)) continue;
                    const arg_postfix = arg[1 + flag_info.name.len ..];
                    if (arg_postfix.len != 0 and arg_postfix[0] != '=') continue;

                    const value_string: []const u8 = if (arg_postfix.len != 0)
                        arg_postfix[1..]
                    else
                        args_it_copy.next() orelse
                            if (flag_info.field.type == .bool) "true" else return error.ValueNotSpecified;

                    const field_ptr = @as([*]u8, @ptrCast(&parsed_flags)) + flag_info.field.offset;
                    switch (flag_info.field.type) {
                        .i32 => @as(*i32, @ptrCast(@alignCast(field_ptr))).* = try std.fmt.parseInt(i32, value_string, 0),
                        .i64 => @as(*i64, @ptrCast(@alignCast(field_ptr))).* = try std.fmt.parseInt(i64, value_string, 0),
                        .u32 => @as(*u32, @ptrCast(@alignCast(field_ptr))).* = try std.fmt.parseInt(u32, value_string, 0),
                        .u64 => @as(*u64, @ptrCast(@alignCast(field_ptr))).* = try std.fmt.parseInt(u64, value_string, 0),
                        .f32 => @as(*f32, @ptrCast(@alignCast(field_ptr))).* = try std.fmt.parseFloat(f32, value_string),
                        .f64 => @as(*f64, @ptrCast(@alignCast(field_ptr))).* = try std.fmt.parseFloat(f64, value_string),
                        .bool => @as(*bool, @ptrCast(field_ptr)).* = if (std.mem.eql(u8, value_string, "true")) true else if (std.mem.eql(u8, value_string, "false")) false else return error.BoolDoNotMat,
                        .str => @as(*[]const u8, @ptrCast(@alignCast(field_ptr))).* = value_string,
                    }

                    break;
                }
            }

            return parsed_flags;
        }

        fn createRuntimeFlagsInfo(Flags: type) [std.meta.fields(Flags).len]RuntimeFlagInfo {
            const info = @typeInfo(Flags);

            if (info != .@"struct") {
                @compileError("Input must be a struct\n");
            }

            comptime var runtime_flags: [info.@"struct".fields.len]RuntimeFlagInfo = undefined;
            comptime for (info.@"struct".fields, &runtime_flags) |field, *runtime_flag| {
                runtime_flag.* = .init(Flags, field);
            };

            return runtime_flags;
        }
    };
}

pub const Options = OptionsImpl(std.process.ArgIterator);
pub const Handler = *const fn (Options) void;

pub const SubCommand = struct {
    name: []const u8,
    handler: Handler,
};

pub fn execute(args_it: anytype, default_handler: Handler, subcommands: []SubCommand) void {
    var args_it_copy = args_it;
    if (args_it_copy.next()) |possible_subcommand| {
        if (findSubcommand(subcommands, possible_subcommand)) |subcommand| {
            subcommand.handler(.{ .args_it = args_it_copy });
            return;
        }
    }

    default_handler(.{ .args_it = args_it });
}

fn findSubcommand(subcommands: []SubCommand, name: []const u8) ?*const SubCommand {
    for (subcommands) |subcommand| {
        if (std.mem.eql(u8, subcommand.name, name)) {
            return &subcommand;
        }
    }

    return null;
}

const TestOptions = OptionsImpl(std.mem.SplitIterator(u8, .scalar));

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

    const parsed = try (TestOptions{ .args_it = std.mem.splitScalar(u8, "-i32=10 -i64=20 -u32=30 -u64=40 -f32=1.5 -f64=2.25 -b=true", ' ') }).parseFlags(Flags);

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

    const parsed = try (TestOptions{ .args_it = std.mem.splitScalar(u8, "-x 999 -y 123.75 -s hello", ' ') }).parseFlags(Flags);

    try std.testing.expect(parsed.x == 999);
    try std.testing.expect(std.math.approxEqAbs(f64, parsed.y, 123.75, 0.0001));
    try std.testing.expect(std.mem.eql(u8, parsed.s, "hello"));
}

test "bool auto-true" {
    const Flags = struct { verbose: bool = false };
    const parsed = try (TestOptions{ .args_it = std.mem.splitScalar(u8, "-verbose", ' ') }).parseFlags(Flags);

    try std.testing.expect(parsed.verbose == true);
}

test "string with =" {
    const Flags = struct { name: []const u8 = "" };
    const parsed = try (TestOptions{ .args_it = std.mem.splitScalar(u8, "-name=alpha", ' ') }).parseFlags(Flags);

    try std.testing.expect(std.mem.eql(u8, parsed.name, "alpha"));
}

test "missing value for non-bool" {
    const Flags = struct { n: i32 = 0 };

    try std.testing.expectError(error.ValueNotSpecified, (TestOptions{ .args_it = std.mem.splitScalar(u8, "-n", ' ') }).parseFlags(Flags));
}

test "invalid bool value" {
    const Flags = struct { b: bool = false };

    try std.testing.expectError(error.BoolDoNotMat, (TestOptions{ .args_it = std.mem.splitScalar(u8, "-b=maybe", ' ') }).parseFlags(Flags));
}

test "last wins" {
    const Flags = struct { x: i32 = 0 };
    const parsed = try (TestOptions{ .args_it = std.mem.splitScalar(u8, "-x=1 -x=2 -x=3", ' ') }).parseFlags(Flags);

    try std.testing.expect(parsed.x == 3);
}

test "Options.parseFlags fuzz" {
    const Flags = struct {
        i: i32 = 0,
        f: f64 = 0,
        b: bool = false,
        s: []const u8 = "",
    };

    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            _ = (TestOptions{ .args_it = std.mem.splitScalar(u8, input, ' ') }).parseFlags(Flags) catch {};
        }
    };

    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
