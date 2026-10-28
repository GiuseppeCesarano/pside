const std = @import("std");

const KernelHeaders = @import("build/KernelHeaders.zig");

pub fn build(b: *std.Build) !void {
    const is_release_bundle = b.option(bool, "release", "Build CLI in ReleaseSmall and Kernel in ReleaseFast") orelse false;
    const optimize = if (is_release_bundle) .small else b.standardOptimizeOption(.{});
    const kernel_optimize = if (is_release_bundle) .fast else optimize;
    const target = b.standardTargetOptions(.{
        .whitelist = &.{.{
            .os_tag = .linux,
            .cpu_arch = .x86_64, // kernel.c, waiting for translate-c to support kernel modules for arm/riscv
        }},
    });
    const kernel_headers = try KernelHeaders.detect(b);
    const kernel_target = b.resolveTargetQuery(switch (target.result.cpu.arch) {
        .x86_64 => .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .none,
            .cpu_features_add = switch (kernel_headers) {
                .usable => |headers| headers.zigFeatures(),
                .unusable => KernelHeaders.base_features,
            },
            .cpu_features_sub = std.Target.x86.featureSet(&.{ .x87, .mmx, .sse, .sse2, .avx, .avx2 }),
        },
        else => @panic("Correct feature flags unimplemented for target arch..."),
    });

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
        .root_source_file = b.path("src/kernelspace/concurrent/RefGate.zig"),
    });

    const bit_search_mod = b.addModule("BitSearch", .{
        .root_source_file = b.path("src/kernelspace/concurrent/BitSearch.zig"),
    });

    const safety_mod = b.addModule("safety", .{
        .root_source_file = b.path("src/common/safety.zig"),
    });

    const bindings_mod = b.addModule("kernel_bindings", .{
        .root_source_file = b.path("src/kernelspace/bindings/kernel.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "safety", .module = safety_mod }},
    });

    const kernel_obj_options: std.Build.ObjectOptions = .{
        .name = "pside_zig",
        .use_llvm = true,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/kernelspace/main.zig"),
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
                .{ .name = "RefGate", .module = ref_gate_mod },
                .{ .name = "BitSearch", .module = bit_search_mod },
                .{ .name = "safety", .module = safety_mod },
                .{ .name = "serialization", .module = serialization_mod },
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
        .root_source_file = b.path("src/userspace/cli.zig"),
        .target = target,
        .optimize = optimize,
    });

    const user_ids_mod = b.addModule("UserIds", .{
        .root_source_file = b.path("src/userspace/UserIds.zig"),
        .target = target,
        .optimize = optimize,
    });

    const driver_mod = b.addModule("driver", .{
        .root_source_file = b.path("src/userspace/driver/driver.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "cli", .module = cli_mod },
            .{ .name = "communications", .module = communications_mod },
            .{ .name = "UserIds", .module = user_ids_mod },
        },
    });

    const record_mod = b.addModule("record", .{
        .root_source_file = b.path("src/userspace/record/record.zig"),
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
        .root_source_file = b.path("src/userspace/report/report.zig"),
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
            .root_source_file = b.path("src/userspace/main.zig"),
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

    const uplot = b.dependency("uplot", .{});
    const web_dir: std.Build.InstallDir = .{ .custom = "usr/share/pside" };
    const web_files = [_]struct { source: std.Build.LazyPath, dest: []const u8 }{
        .{ .source = b.path("src/userspace/report/web/index.html"), .dest = "index.html" },
        .{ .source = uplot.path("dist/uPlot.iife.min.js"), .dest = "uplot.min.js" },
        .{ .source = uplot.path("dist/uPlot.min.css"), .dest = "uplot.min.css" },
    };
    for (web_files) |file|
        b.getInstallStep().dependOn(&b.addInstallFileWithDir(file.source, web_dir, file.dest).step);

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
        .{ .name = "concurrent_refgate", .path = "src/kernelspace/concurrent/RefGate.zig", .sanitize_thread = true },
        .{ .name = "concurrent_bitsearch", .path = "src/kernelspace/concurrent/BitSearch.zig", .sanitize_thread = true },
        .{ .name = "causal_threadclocks", .path = "src/kernelspace/causal/time/ThreadClocks.zig", .sanitize_thread = true, .imports = &.{ .{ .name = "RefGate", .module = ref_gate_mod }, .{ .name = "BitSearch", .module = bit_search_mod }, .{ .name = "safety", .module = safety_mod } } },
        .{ .name = "common_safety", .path = "src/common/safety.zig", .sanitize_thread = true },
        .{ .name = "common_serialization", .path = "src/common/serialization.zig" },
        .{ .name = "kernelspace_soft_float", .path = "src/kernelspace/soft_float.zig" },
        .{ .name = "traced_x86_64", .path = "src/userspace/record/traced/x86_64.zig" },
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

fn installKernelModule(b: *std.Build, headers: KernelHeaders, zig_obj_options: std.Build.ObjectOptions) !void {
    const target = zig_obj_options.root_module.resolved_target.?;
    const optimize = zig_obj_options.root_module.optimize.?;
    const lto: std.zig.LtoMode = if (optimize == .debug) .none else .full;

    const zig_kernel_obj = b.addObject(zig_obj_options);
    for ([_][]const u8{
        "init_module",
        "cleanup_module",
        "description",
        "license",
        "pside_engine_release",
    }) |symbol|
        try zig_kernel_obj.force_undefined_symbols.put(b.allocator, symbol, {});

    zig_kernel_obj.bundle_compiler_rt = false;
    zig_kernel_obj.link_function_sections = true;
    zig_kernel_obj.link_gc_sections = true;
    zig_kernel_obj.lto = lto;

    const c_module_options: std.Build.Module.CreateOptions = .{
        .target = target,
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

    const kernel_c_obj = b.addObject(.{
        .name = "pside_kernel_c",
        .use_llvm = true,
        .use_lld = true,
        .root_module = b.createModule(c_module_options),
    });
    kernel_c_obj.bundle_compiler_rt = false;
    kernel_c_obj.lto = lto;
    try headers.addCSourceFile(b, kernel_c_obj.root_module, b.path("src/kernelspace/bindings/kernel.c"), "kernel");

    const prelink_obj = b.addObject(.{
        .name = "pside_prelink",
        .use_llvm = true,
        .use_lld = true,
        .root_module = b.createModule(c_module_options),
    });
    prelink_obj.bundle_compiler_rt = false;
    prelink_obj.root_module.addObjectFile(kernel_c_obj.getEmittedBin());
    prelink_obj.root_module.addObjectFile(zig_kernel_obj.getEmittedBin());

    const modpost_exe = b.addExecutable(.{
        .name = "modpost",
        .root_module = b.createModule(.{
            .root_source_file = b.path("build/modpost.zig"),
            .target = b.graph.host,
        }),
    });
    const run_modpost = b.addRunArtifact(modpost_exe);
    run_modpost.addFileArg(prelink_obj.getEmittedBin());
    run_modpost.addFileArg(headers.build_dir.path(b, "Module.symvers"));
    const mod_c = run_modpost.addOutputFileArg2("pside.mod.c", .{});

    const ko_obj = b.addObject(.{
        .name = "pside",
        .use_llvm = true,
        .use_lld = true,
        .root_module = b.createModule(c_module_options),
    });
    ko_obj.bundle_compiler_rt = false;
    ko_obj.setLinkerScript(headers.build_dir.path(b, "scripts/module.lds"));
    ko_obj.root_module.addObjectFile(prelink_obj.getEmittedBin());
    try headers.addCSourceFile(b, ko_obj.root_module, mod_c, "pside.mod");

    const install_ko = b.addInstallFile(ko_obj.getEmittedBin(), b.fmt("lib/modules/{s}/extra/pside.ko", .{headers.release}));
    b.getInstallStep().dependOn(&install_ko.step);
}
