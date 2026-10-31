const std = @import("std");

const KernelHeaders = @import("build/KernelHeaders.zig");

pub fn build(b: *std.Build) !void {
    const is_release_bundle = b.option(bool, "release", "Build CLI in ReleaseSmall and Kernel in ReleaseFast") orelse false;
    const optimize = if (is_release_bundle) .small else b.standardOptimizeOption(.{});
    const kernel_optimize = if (is_release_bundle) .fast else optimize;
    const target = b.standardTargetOptions(.{
        .whitelist = &.{.{
            .os_tag = .linux,
            .cpu_arch = .x86_64, // bindings.c, waiting for translate-c to support kernel modules for arm/riscv
        }},
    });
    const kernel_headers = try KernelHeaders.detect(b);
    const kernel_target = kernelTarget(b, target, kernel_headers);

    const communications_mod = b.addModule("communications", .{
        .root_source_file = b.path("src/common/communications.zig"),
        .target = target,
        .optimize = optimize,
    });

    const serialization_mod = b.addModule("serialization", .{
        .root_source_file = b.path("src/common/serialization.zig"),
        .target = target,
        .optimize = optimize,
    });

    const ref_gate_mod = b.addModule("RefGate", .{
        .root_source_file = b.path("src/concurrent/RefGate.zig"),
    });

    const bit_search_mod = b.addModule("BitSearch", .{
        .root_source_file = b.path("src/concurrent/BitSearch.zig"),
    });

    const safety_mod = b.addModule("safety", .{
        .root_source_file = b.path("src/common/safety.zig"),
    });

    const bindings_mod = b.addModule("kernel_bindings", .{
        .root_source_file = b.path("src/platform/kernel/kernel.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "safety", .module = safety_mod }},
    });

    const delay_pool_mod = b.addModule("DelayPool", .{
        .root_source_file = b.path("src/platform/kernel/DelayPool.zig"),
        .imports = &.{
            .{ .name = "kernel", .module = bindings_mod },
            .{ .name = "BitSearch", .module = bit_search_mod },
            .{ .name = "safety", .module = safety_mod },
        },
    });

    const engine_mod = b.addModule("Engine", .{
        .root_source_file = b.path("src/causal/Engine.zig"),
        .imports = &.{
            .{ .name = "kernel", .module = bindings_mod },
            .{ .name = "DelayPool", .module = delay_pool_mod },
            .{ .name = "RefGate", .module = ref_gate_mod },
            .{ .name = "BitSearch", .module = bit_search_mod },
            .{ .name = "safety", .module = safety_mod },
            .{ .name = "serialization", .module = serialization_mod },
        },
    });

    const kernel_obj_options: std.Build.ObjectOptions = .{
        .name = "pside_zig",
        .use_llvm = true,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/platform/kernel/module.zig"),
            .target = kernel_target,
            .optimize = kernel_optimize,
            .link_libc = false,
            .link_libcpp = false,
            .strip = false,
            .unwind_tables = .none,
            .code_model = .kernel,
            .stack_protector = false,
            .stack_check = false,
            .pic = false,
            .red_zone = false,
            .omit_frame_pointer = false,
            .error_tracing = false,
            .no_builtin = true,
            .imports = &.{
                .{ .name = "communications", .module = communications_mod },
                .{ .name = "kernel", .module = bindings_mod },
                .{ .name = "Engine", .module = engine_mod },
            },
        }),
    };

    const check = b.step("check", "Check for compilation errors");
    const check_obj = b.addObject(kernel_obj_options);
    check.dependOn(&check_obj.step);

    switch (kernel_headers) {
        .usable => |headers| try installKernelModule(b, headers, kernel_obj_options),
        .unusable => |reason| b.getInstallStep().dependOn(&b.addFail(reason).step),
    }

    const cli_mod = b.addModule("cli", .{
        .root_source_file = b.path("src/tool/cli.zig"),
        .target = target,
        .optimize = optimize,
    });

    const user_ids_mod = b.addModule("UserIds", .{
        .root_source_file = b.path("src/tool/UserIds.zig"),
        .target = target,
        .optimize = optimize,
    });

    const driver_mod = b.addModule("driver", .{
        .root_source_file = b.path("src/tool/driver/driver.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "cli", .module = cli_mod },
            .{ .name = "communications", .module = communications_mod },
            .{ .name = "UserIds", .module = user_ids_mod },
        },
    });

    const record_mod = b.addModule("record", .{
        .root_source_file = b.path("src/tool/record/record.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "cli", .module = cli_mod },
            .{ .name = "communications", .module = communications_mod },
            .{ .name = "safety", .module = safety_mod },
            .{ .name = "serialization", .module = serialization_mod },
            .{ .name = "UserIds", .module = user_ids_mod },
        },
    });

    const report_mod = b.addModule("report", .{
        .root_source_file = b.path("src/tool/report/report.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "cli", .module = cli_mod },
            .{ .name = "communications", .module = communications_mod },
            .{ .name = "safety", .module = safety_mod },
            .{ .name = "serialization", .module = serialization_mod },
        },
    });

    const executable_options: std.Build.ExecutableOptions = .{
        .name = "pside",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tool/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "cli", .module = cli_mod },
                .{ .name = "driver", .module = driver_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "report", .module = report_mod },
            },
            .pic = true,
        }),
    };
    const executable = b.addExecutable(executable_options);
    b.installArtifact(executable);

    const check_exe = b.addExecutable(executable_options);
    check.dependOn(&check_exe.step);

    installWebAssets(b);

    const test_step = b.step("test", "Run tests");
    for ([_]*std.Build.Module{ cli_mod, bindings_mod, report_mod, record_mod, driver_mod }) |module|
        test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = module })).step);

    const standalone_tests = [_]struct {
        name: []const u8,
        path: []const u8,
        sanitize_thread: bool = false,
        use_llvm: ?bool = null,
        imports: []const std.Build.Module.Import = &.{},
    }{
        .{ .name = "concurrent_refgate", .path = "src/concurrent/RefGate.zig", .sanitize_thread = true },
        .{ .name = "concurrent_bitsearch", .path = "src/concurrent/BitSearch.zig", .sanitize_thread = true },
        .{ .name = "causal_threadclocks", .path = "src/causal/ThreadClocks.zig", .sanitize_thread = true, .imports = &.{
            .{ .name = "RefGate", .module = ref_gate_mod },
            .{ .name = "BitSearch", .module = bit_search_mod },
            .{ .name = "safety", .module = safety_mod },
        } },
        .{ .name = "common_safety", .path = "src/common/safety.zig", .sanitize_thread = true },
        .{ .name = "common_serialization", .path = "src/common/serialization.zig" },
        .{ .name = "traced_x86_64", .path = "src/tool/record/traced/x86_64.zig" },
        .{ .name = "pside_include", .path = "include/pside.zig", .use_llvm = true },
    };
    for (standalone_tests) |spec| {
        const tests = b.addTest(.{
            .root_module = b.addModule(spec.name, .{
                .root_source_file = b.path(spec.path),
                .target = target,
                .optimize = optimize,
                .sanitize_thread = spec.sanitize_thread,
                .imports = spec.imports,
            }),
            .use_llvm = spec.use_llvm,
        });
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }
}

fn kernelTarget(b: *std.Build, target: std.Build.ResolvedTarget, kernel_headers: KernelHeaders.Detection) std.Build.ResolvedTarget {
    return b.resolveTargetQuery(switch (target.result.cpu.arch) {
        .x86_64 => .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .eabi,
            .cpu_features_add = switch (kernel_headers) {
                .usable => |headers| headers.zigFeatures(),
                .unusable => KernelHeaders.base_features,
            },
            .cpu_features_sub = std.Target.x86.featureSet(&.{ .x87, .mmx, .sse, .sse2, .avx, .avx2 }),
        },
        else => @panic("Correct feature flags unimplemented for target arch..."),
    });
}

fn installWebAssets(b: *std.Build) void {
    const uplot = b.dependency("uplot", .{});
    const web_dir: std.Build.InstallDir = .{ .custom = "usr/share/pside" };
    const web_files = [_]struct { source: std.Build.LazyPath, dest: []const u8 }{
        .{ .source = b.path("src/tool/report/web/index.html"), .dest = "index.html" },
        .{ .source = uplot.path("dist/uPlot.iife.min.js"), .dest = "uplot.min.js" },
        .{ .source = uplot.path("dist/uPlot.min.css"), .dest = "uplot.min.css" },
    };
    for (web_files) |file|
        b.getInstallStep().dependOn(&b.addInstallFileWithDir(file.source, web_dir, file.dest).step);
}

fn installKernelModule(b: *std.Build, headers: KernelHeaders, zig_obj_options: std.Build.ObjectOptions) !void {
    const optimize = zig_obj_options.root_module.optimize.?;
    const lto: std.zig.LtoMode = if (optimize == .debug) .none else .full;
    const link_options: std.Build.Module.CreateOptions = .{
        .target = zig_obj_options.root_module.resolved_target.?,
        .optimize = optimize,
        .link_libc = false,
        .strip = optimize != .debug,
        .unwind_tables = .none,
        .code_model = .kernel,
        .stack_protector = false,
        .stack_check = false,
        .sanitize_c = .off,
        .pic = false,
        .red_zone = false,
        .omit_frame_pointer = false,
    };

    const zig_obj = try addZigObject(b, zig_obj_options, lto);
    const bindings_obj = try addBindingsObject(b, headers, link_options, lto);
    const compiler_rt_obj = try addCompilerRtObject(b, link_options);

    const prelink_obj = addKernelObject(b, "pside_prelink", link_options);
    for ([_]std.Build.LazyPath{ bindings_obj, zig_obj, compiler_rt_obj }) |object|
        prelink_obj.root_module.addObjectFile(object);

    const mod_c = generateModC(b, headers, prelink_obj.getEmittedBin());

    const ko_obj = addKernelObject(b, "pside", link_options);
    ko_obj.compress_debug_sections = .zlib;
    ko_obj.setLinkerScript(headers.build_dir.path(b, "scripts/module.lds"));
    ko_obj.root_module.addObjectFile(prelink_obj.getEmittedBin());
    try headers.addCSourceFile(b, ko_obj.root_module, mod_c, "pside.mod");

    const install_ko = b.addInstallFile(ko_obj.getEmittedBin(), b.fmt("lib/modules/{s}/extra/pside.ko", .{headers.release}));
    b.getInstallStep().dependOn(&install_ko.step);
}

fn addZigObject(b: *std.Build, options: std.Build.ObjectOptions, lto: std.zig.LtoMode) !std.Build.LazyPath {
    const object = b.addObject(options);
    object.bundle_compiler_rt = false;
    object.function_sections = true;
    object.link_gc_sections = true;
    object.lto = lto;
    try keepSymbols(b, object, &.{ "init_module", "cleanup_module", "description", "license", "pside_engine_release" });

    return object.getEmittedBin();
}

fn addBindingsObject(b: *std.Build, headers: KernelHeaders, options: std.Build.Module.CreateOptions, lto: std.zig.LtoMode) !std.Build.LazyPath {
    const object = addKernelObject(b, "pside_kernel_c", options);
    object.lto = lto;
    try headers.addCSourceFile(b, object.root_module, b.path("src/platform/kernel/bindings.c"), "kernel");

    return object.getEmittedBin();
}

fn addCompilerRtObject(b: *std.Build, options: std.Build.Module.CreateOptions) !std.Build.LazyPath {
    var compiler_rt_options = options;
    compiler_rt_options.root_source_file = .{ .relative = .{ .base = .zig_lib, .sub_path = "compiler_rt.zig" } };
    compiler_rt_options.optimize = .fast;
    compiler_rt_options.strip = true;

    const compiler_rt = b.addObject(.{
        .name = "compiler_rt",
        .use_llvm = true,
        .root_module = b.createModule(compiler_rt_options),
    });
    compiler_rt.bundle_compiler_rt = false;
    compiler_rt.function_sections = true;

    const used_compiler_rt = addKernelObject(b, "compiler_rt_gc", options);
    used_compiler_rt.link_gc_sections = true;
    used_compiler_rt.root_module.addObjectFile(compiler_rt.getEmittedBin());
    try keepSymbols(b, used_compiler_rt, &.{"__divti3"});

    return used_compiler_rt.getEmittedBin();
}

fn generateModC(b: *std.Build, headers: KernelHeaders, prelink_obj: std.Build.LazyPath) std.Build.LazyPath {
    const modpost = b.addExecutable(.{
        .name = "modpost",
        .root_module = b.createModule(.{
            .root_source_file = b.path("build/modpost.zig"),
            .target = b.graph.host,
        }),
    });

    const run_modpost = b.addRunArtifact(modpost);
    run_modpost.addFileArg(prelink_obj);
    run_modpost.addFileArg(headers.build_dir.path(b, "Module.symvers"));

    return run_modpost.addOutputFileArg2("pside.mod.c", .{});
}

fn addKernelObject(b: *std.Build, name: []const u8, options: std.Build.Module.CreateOptions) *std.Build.Step.Compile {
    const object = b.addObject(.{
        .name = name,
        .use_llvm = true,
        .use_lld = true,
        .root_module = b.createModule(options),
    });
    object.bundle_compiler_rt = false;

    return object;
}

fn keepSymbols(b: *std.Build, object: *std.Build.Step.Compile, symbols: []const []const u8) !void {
    for (symbols) |symbol| try object.force_undefined_symbols.put(b.allocator, symbol, {});
}
