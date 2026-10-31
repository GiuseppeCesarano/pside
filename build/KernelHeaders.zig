const std = @import("std");

const KernelHeaders = @This();

release: []const u8,
build_dir: std.Build.LazyPath,
source_dir: std.Build.LazyPath,
config: std.StringHashMapUnmanaged([]const u8),
exports_ref_stack_chk_guard: bool,

pub const Detection = union(enum) { usable: KernelHeaders, unusable: []const u8 };
pub const base_features: std.Target.Cpu.Feature.Set = .empty;

pub fn detect(b: *std.Build) !Detection {
    b.graph.poisonCache();
    const io = b.graph.io;

    const uts = std.posix.uname();
    const release = b.graph.dupeString(std.mem.sliceTo(&uts.release, 0));
    const build_dir = b.fmt("/lib/modules/{s}/build", .{release});

    std.Io.Dir.accessAbsolute(io, build_dir, .{}) catch |err| return .{ .unusable = switch (err) {
        error.FileNotFound => b.fmt(
            \\Kernel headers for the running kernel ({s}) are not installed, expected at {s}
            \\Install them with:
            \\    {s}
            \\then rerun zig build
        , .{ release, build_dir, headersInstallCommand(b, release) }),
        else => b.fmt("Could not access the kernel headers at {s} ({s})", .{ build_dir, @errorName(err) }),
    } };

    const source_dir = findSourceDir(b, release, build_dir);

    for ([_]struct { dir: []const u8, file: []const u8 }{
        .{ .dir = build_dir, .file = "include/config/auto.conf" },
        .{ .dir = build_dir, .file = "include/generated/autoconf.h" },
        .{ .dir = build_dir, .file = "scripts/module.lds" },
        .{ .dir = build_dir, .file = "Module.symvers" },
        .{ .dir = source_dir, .file = "include/linux/kconfig.h" },
        .{ .dir = source_dir, .file = "include/linux/compiler_types.h" },
    }) |required|
        std.Io.Dir.accessAbsolute(io, b.pathJoin(&.{ required.dir, required.file }), .{}) catch |err| return .{ .unusable = b.fmt(
            \\Kernel headers at {s} are incomplete, missing {s} ({s})
            \\Reinstall the kernel headers package for {s}
        , .{ required.dir, required.file, @errorName(err), release }) };

    var this: KernelHeaders = .{
        .release = release,
        .build_dir = b.graph.cwdRelativePath(build_dir),
        .source_dir = b.graph.cwdRelativePath(source_dir),
        .config = .empty,
        .exports_ref_stack_chk_guard = false,
    };

    const auto_conf = try std.Io.Dir.cwd().readFileAlloc(io, b.pathJoin(&.{ build_dir, "include/config/auto.conf" }), b.allocator, .unlimited);
    var lines = std.mem.tokenizeScalar(u8, auto_conf, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "CONFIG_")) continue;
        const option, const value = std.mem.cutScalar(u8, line, '=') orelse continue;
        try this.config.put(b.allocator, option, std.mem.trim(u8, value, "\""));
    }

    if (this.isEnabled("CONFIG_STACKPROTECTOR") and this.isEnabled("CONFIG_SMP")) {
        const symvers = try std.Io.Dir.cwd().readFileAlloc(io, b.pathJoin(&.{ build_dir, "Module.symvers" }), b.allocator, .unlimited);
        this.exports_ref_stack_chk_guard = std.mem.containsAtLeast(u8, symvers, 1, "\t__ref_stack_chk_guard\t");
    }

    if (this.unsupportedConfig(b)) |reason| return .{ .unusable = reason };
    return .{ .usable = this };
}

pub fn addCSourceFile(this: KernelHeaders, b: *std.Build, module: *std.Build.Module, file: std.Build.LazyPath, basename: []const u8) !void {
    for ([_]std.Build.LazyPath{
        this.source_dir.path(b, "arch/x86/include"),
        this.build_dir.path(b, "arch/x86/include/generated"),
        this.source_dir.path(b, "include"),
        this.build_dir.path(b, "include"),
        this.source_dir.path(b, "arch/x86/include/uapi"),
        this.build_dir.path(b, "arch/x86/include/generated/uapi"),
        this.source_dir.path(b, "include/uapi"),
        this.build_dir.path(b, "include/generated/uapi"),
        b.path("src/platform/kernel"),
    }) |dir| module.addIncludePath(dir);

    for ([_][2][]const u8{
        .{ "__KERNEL__", "1" },
        .{ "MODULE", "1" },
        .{ "KBUILD_MODNAME", "\"pside\"" },
        .{ "__KBUILD_MODNAME", "pside" },
        .{ "KBUILD_BASENAME", b.fmt("\"{s}\"", .{basename}) },
    }) |macro| module.addCMacro(macro[0], macro[1]);
    if (this.isEnabled("CONFIG_FUNCTION_TRACER")) module.addCMacro("CC_USING_FENTRY", "1");
    if (module.optimize.? == .debug) module.addCMacro("DEBUG", "1");

    var flags: std.ArrayList([]const u8) = .empty;
    try flags.appendSlice(b.allocator, &.{
        "-std=gnu11",
        "-fms-extensions",
        "-fshort-wchar",
        "-funsigned-char",
        "-fno-strict-aliasing",
        "-fno-strict-overflow",
        "-fno-delete-null-pointer-checks",
        "-fstrict-flex-arrays=3",
        "-fno-builtin-wcslen",
        "-mno-fp-ret-in-387",
        "-mstack-alignment=8",
        "-mskip-rax-setup",
        "-falign-loops=1",
        "-Wno-microsoft-anon-tag",
        "-Wno-duplicate-decl-specifier",
        "-Wno-enum-enum-conversion",
    });

    try flags.append(b.allocator, if (this.isEnabled("CONFIG_CC_OPTIMIZE_FOR_SIZE")) "-Os" else "-O2");

    if (this.isEnabled("CONFIG_X86_KERNEL_IBT"))
        try flags.appendSlice(b.allocator, &.{ "-fcf-protection=branch", "-fno-jump-tables" })
    else
        try flags.append(b.allocator, "-fcf-protection=none");

    if (this.hasRetpoline()) {
        try flags.append(b.allocator, "-mindirect-branch-cs-prefix");
        if (this.isAnyEnabled(&.{ "CONFIG_MITIGATION_RETHUNK", "CONFIG_RETHUNK" }))
            try flags.append(b.allocator, "-mfunction-return=thunk-extern");
    }

    if (this.isEnabled("CONFIG_CALL_PADDING")) if (this.config.get("CONFIG_FUNCTION_PADDING_BYTES")) |bytes|
        try flags.appendSlice(b.allocator, &.{
            "-Xclang",
            b.fmt("-fpatchable-function-entry={s}", .{bytes}),
            "-Xclang",
            b.fmt("-fpatchable-function-entry-offset={s}", .{bytes}),
        });

    if (this.config.get("CONFIG_FUNCTION_ALIGNMENT")) |alignment| if (!std.mem.eql(u8, alignment, "0"))
        try flags.append(b.allocator, b.fmt("-falign-functions={s}", .{alignment}));

    if (this.isEnabled("CONFIG_STACKPROTECTOR")) {
        try flags.append(b.allocator, if (this.isEnabled("CONFIG_STACKPROTECTOR_STRONG")) "-fstack-protector-strong" else "-fstack-protector");
        if (!this.isEnabled("CONFIG_SMP"))
            try flags.append(b.allocator, "-mstack-protector-guard=global")
        else if (this.exports_ref_stack_chk_guard)
            try flags.appendSlice(b.allocator, &.{ "-mstack-protector-guard-reg=gs", "-mstack-protector-guard-symbol=__ref_stack_chk_guard" });
    }

    if (this.isEnabled("CONFIG_INIT_STACK_ALL_ZERO"))
        try flags.append(b.allocator, "-ftrivial-auto-var-init=zero")
    else if (this.isEnabled("CONFIG_INIT_STACK_ALL_PATTERN"))
        try flags.append(b.allocator, "-ftrivial-auto-var-init=pattern");

    if (this.isEnabled("CONFIG_ZERO_CALL_USED_REGS")) try flags.append(b.allocator, "-fzero-call-used-regs=used-gpr");

    module.addCSourceFile(.{ .file = file, .flags = flags.items });
}

pub fn zigFeatures(this: KernelHeaders) std.Target.Cpu.Feature.Set {
    _ = this;
    return base_features;
}

fn findSourceDir(b: *std.Build, release: []const u8, build_dir: []const u8) []const u8 {
    const io = b.graph.io;

    const makefile_include: ?[]const u8 = blk: {
        const makefile = std.Io.Dir.cwd().readFileAlloc(io, b.pathJoin(&.{ build_dir, "Makefile" }), b.allocator, .limited(1024 * 1024)) catch break :blk null;
        var lines = std.mem.tokenizeScalar(u8, makefile, '\n');
        break :blk while (lines.next()) |line| {
            const included = std.mem.cutPrefix(u8, std.mem.trim(u8, line, " \t\r"), "include ") orelse continue;
            const dir = std.mem.trim(u8, std.mem.cutSuffix(u8, included, "/Makefile") orelse continue, " \t");
            if (std.Io.Dir.path.isAbsolute(dir)) break dir;
        } else null;
    };

    const candidates = [_]?[]const u8{ build_dir, makefile_include, b.fmt("/lib/modules/{s}/source", .{release}) };
    return for (candidates) |candidate| {
        if (candidate) |dir| if (std.Io.Dir.accessAbsolute(io, b.pathJoin(&.{ dir, "include/linux/kconfig.h" }), .{})) break dir else |_| {};
    } else build_dir;
}

fn unsupportedConfig(this: KernelHeaders, b: *std.Build) ?[]const u8 {
    if (!this.isEnabled("CONFIG_MODULES"))
        return b.fmt("The running kernel ({s}) was built without loadable module support (CONFIG_MODULES)", .{this.release});

    if (!this.isEnabled("CONFIG_X86_64"))
        return b.fmt("The running kernel ({s}) is not an x86_64 kernel, the only kind pside's kernel module supports", .{this.release});

    for ([_][]const u8{ "CONFIG_CFI_CLANG", "CONFIG_CFI" }) |option| if (this.isEnabled(option))
        return b.fmt("The running kernel ({s}) enforces kernel control-flow integrity ({s}), and Zig cannot emit the type hashes it checks on indirect calls", .{ this.release, option });

    for ([_][]const u8{ "CONFIG_RANDSTRUCT_FULL", "CONFIG_RANDSTRUCT_PERFORMANCE", "CONFIG_GCC_PLUGIN_RANDSTRUCT" }) |option| if (this.isEnabled(option))
        return b.fmt("The running kernel ({s}) randomizes kernel struct layouts ({s}), which pside's kernel module cannot reproduce", .{ this.release, option });

    return null;
}

fn hasRetpoline(this: KernelHeaders) bool {
    return this.isAnyEnabled(&.{ "CONFIG_MITIGATION_RETPOLINE", "CONFIG_RETPOLINE" });
}

fn hasSls(this: KernelHeaders) bool {
    return this.isAnyEnabled(&.{ "CONFIG_MITIGATION_SLS", "CONFIG_SLS" });
}

fn isEnabled(this: KernelHeaders, option: []const u8) bool {
    const value = this.config.get(option) orelse return false;
    return std.mem.eql(u8, value, "y");
}

fn isAnyEnabled(this: KernelHeaders, options: []const []const u8) bool {
    for (options) |option| if (this.isEnabled(option)) return true;
    return false;
}

const Distro = enum { arch, debian, fedora, suse, alpine };

fn headersInstallCommand(b: *std.Build, release: []const u8) []const u8 {
    const distro = detectDistro(b) orelse return b.fmt("your distribution's kernel headers package for {s}", .{release});

    switch (distro) {
        .arch => {
            inline for (.{ "lts", "zen", "hardened" }) |flavour|
                if (std.mem.endsWith(u8, release, "-" ++ flavour)) return "sudo pacman -S linux-" ++ flavour ++ "-headers";
            return "sudo pacman -S linux-headers";
        },
        .debian => return b.fmt("sudo apt install linux-headers-{s}", .{release}),
        .fedora => return b.fmt("sudo dnf install kernel-devel-{s}", .{release}),
        .suse => return "sudo zypper install kernel-default-devel",
        .alpine => return "sudo apk add linux-lts-dev",
    }
}

fn detectDistro(b: *std.Build) ?Distro {
    const os_release = std.Io.Dir.cwd().readFileAlloc(b.graph.io, "/etc/os-release", b.allocator, .limited(64 * 1024)) catch return null;

    var lines = std.mem.tokenizeScalar(u8, os_release, '\n');
    while (lines.next()) |line| {
        const ids = std.mem.cutPrefix(u8, line, "ID=") orelse std.mem.cutPrefix(u8, line, "ID_LIKE=") orelse continue;
        var values = std.mem.tokenizeAny(u8, ids, "\" ");
        while (values.next()) |value| if (std.meta.stringToEnum(Distro, value)) |distro| return distro;
    }

    return null;
}
