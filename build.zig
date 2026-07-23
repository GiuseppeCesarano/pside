const std = @import("std");

pub fn build(b: *std.Build) !void {
    const is_release_bundle = b.option(bool, "release", "Build CLI in ReleaseSmall and Kernel in ReleaseFast") orelse false;
    const optimize = if (is_release_bundle) .ReleaseSmall else b.standardOptimizeOption(.{});
    const kernel_optimize = if (is_release_bundle) .ReleaseFast else optimize;
    const target = b.standardTargetOptions(.{
        .whitelist = &.{.{
            .os_tag = .linux,
            .cpu_arch = .x86_64, // kernel.c, waiting for translate-c to support kernel modules for arm/riscv
        }},
    });
    const kernel_target = b.resolveTargetQuery(switch (target.result.cpu.arch) {
        .x86_64 => .{
            .cpu_arch = .x86_64,
            .os_tag = .freestanding,
            .abi = .none,
            .cpu_features_add = std.Target.x86.featureSet(&.{ .soft_float, .retpoline, .retpoline_external_thunk }),
            .cpu_features_sub = std.Target.x86.featureSet(&.{ .mmx, .sse, .sse2, .avx, .avx2 }),
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

    const bindings_mod = b.addModule("kernel_bindings", .{
        .root_source_file = b.path("src/kernelspace/bindings/kernel.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
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
            .single_threaded = true,
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
                .{ .name = "serialization", .module = serialization_mod },
            },
        }),
    };

    const check = b.step("check", "Check for compilation errors");
    const check_obj = b.addObject(kernel_obj_options);
    check.dependOn(&check_obj.step);

    const zig_kernel_obj = b.addObject(kernel_obj_options);
    try zig_kernel_obj.force_undefined_symbols.put(b.allocator, "init_module", {});
    try zig_kernel_obj.force_undefined_symbols.put(b.allocator, "cleanup_module", {});
    try zig_kernel_obj.force_undefined_symbols.put(b.allocator, "description", {});
    try zig_kernel_obj.force_undefined_symbols.put(b.allocator, "license", {});
    try zig_kernel_obj.force_undefined_symbols.put(b.allocator, "pside_engine_release", {});
    zig_kernel_obj.bundle_compiler_rt = true;
    zig_kernel_obj.link_function_sections = true;
    zig_kernel_obj.link_gc_sections = true;

    // kbuild expects a .<obj>.cmd file for every prebuilt object it links.
    const kbuild_cmd_name = try std.mem.concat(b.allocator, u8, &.{ ".", zig_kernel_obj.out_filename, ".cmd" });
    const kbuild_debug_flags = if (kernel_optimize == .Debug) "ccflags-y := -DDEBUG" else "";
    const strip_kernel_mod = "strip --strip-debug" ++
        " --remove-section=.BTF" ++
        " --remove-section=.BTF.ext" ++
        " --remove-section=.eh_frame" ++
        " --remove-section=.eh_frame_hdr" ++
        " --remove-section=.gcc_except_table" ++
        " --remove-section=.comment" ++
        " --remove-section=.note.GNU-stack" ++
        " pside.ko";

    const kernel_module_files = b.addWriteFiles();
    _ = kernel_module_files.addCopyFile(zig_kernel_obj.getEmittedBin(), zig_kernel_obj.out_filename);
    _ = kernel_module_files.addCopyFile(b.path("src/kernelspace/bindings/kernel.c"), "kernel.c");
    _ = kernel_module_files.add(kbuild_cmd_name, "");
    _ = kernel_module_files.add("Makefile", b.fmt(
        "{s}\n" ++
            "obj-m += pside.o\n" ++
            "pside-objs := kernel.o {s}\n" ++
            "\n" ++
            "PWD := $(CURDIR)\n" ++
            "\n" ++
            "# Zig can't emit rethunk/endbr yet, neutering objtool silences the mitigation warnings.\n" ++
            "all:\n" ++
            "\tstrip --strip-debug {s}\n" ++
            "\t$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules objtool=true\n" ++
            "\t{s}\n" ++
            "\n" ++
            "clean:\n" ++
            "\t$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean\n",
        .{ kbuild_debug_flags, zig_kernel_obj.out_filename, zig_kernel_obj.out_filename, strip_kernel_mod },
    ));
    kernel_module_files.step.dependOn(&zig_kernel_obj.step);

    const run_kbuild = b.addSystemCommand(&.{"make"});
    run_kbuild.setCwd(kernel_module_files.getDirectory());
    run_kbuild.step.dependOn(&kernel_module_files.step);

    const built_ko = try kernel_module_files.getDirectory().join(b.allocator, "pside.ko");
    const uts = std.posix.uname();
    const ko_install_path = try std.mem.concat(b.allocator, u8, &.{ "lib/modules/", std.mem.sliceTo(&uts.release, 0), "/extra/pside.ko" });
    const install_ko = b.addInstallFile(built_ko, ko_install_path);
    install_ko.step.dependOn(&run_kbuild.step);
    b.getInstallStep().dependOn(&install_ko.step);

    const cli_mod = b.addModule("cli", .{
        .root_source_file = b.path("src/userspace/cli.zig"),
        .target = target,
        .optimize = optimize,
    });

    const record_mod = b.addModule("record", .{
        .root_source_file = b.path("src/userspace/record/record.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "cli", .module = cli_mod },
            .{ .name = "communications", .module = communications_mod },
            .{ .name = "serialization", .module = serialization_mod },
        },
    });

    const output_file_parse_results_mod = b.addModule("OutputFileParseResults", .{
        .root_source_file = b.path("src/userspace/report/OutputFileParseResults.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "serialization", .module = serialization_mod },
        },
    });

    const report_mod = b.addModule("report", .{
        .root_source_file = b.path("src/userspace/report/report.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "cli", .module = cli_mod },
            .{ .name = "communications", .module = communications_mod },
            .{ .name = "OutputFileParseResults", .module = output_file_parse_results_mod },
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
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = cli_mod })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = bindings_mod })).step);

    const standalone_tests = [_]struct {
        name: []const u8,
        path: []const u8,
        sanitize_thread: bool = false,
        use_llvm: ?bool = null,
    }{
        .{ .name = "thread_safe_refgate", .path = "src/kernelspace/causal/Engine/thread_safe/RefGate.zig", .sanitize_thread = true },
        .{ .name = "thread_safe_threadclocks", .path = "src/kernelspace/causal/Engine/thread_safe/ThreadClocks.zig", .sanitize_thread = true },
        .{ .name = "thread_safe_pool", .path = "src/kernelspace/causal/Engine/thread_safe/Pool.zig", .sanitize_thread = true },
        .{ .name = "virtual_time_keeper", .path = "src/kernelspace/causal/Engine/VirtualTimeKeeper.zig", .sanitize_thread = true },
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
            }),
            .use_llvm = spec.use_llvm,
        });
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }
}
