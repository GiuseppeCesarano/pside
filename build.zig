const std = @import("std");

pub fn build(b: *std.Build) void {
    const is_release_bundle = b.option(bool, "release", "Build CLI in ReleaseSmall and Kernel in ReleaseFast") orelse false;
    const target = b.standardTargetOptions(.{
        .whitelist = &.{
            .{
                .os_tag = .linux,
                .cpu_arch = .x86_64, // kernel.c, waiting for translate-c to support kernel modules for arm/riscv
            },
        },
    });
    const optimize = if (is_release_bundle) .ReleaseSmall else b.standardOptimizeOption(.{});
    const kernel_optimize = if (is_release_bundle) .ReleaseFast else optimize;

    var kernel_target = target;
    kernel_target.query.cpu_arch = kernel_target.query.cpu_arch orelse @import("builtin").cpu.arch;
    kernel_target.query = switch (kernel_target.query.cpu_arch.?) {
        .x86_64 => .{
            .cpu_arch = .x86_64,
            .os_tag = .freestanding,
            .abi = .none,
            .cpu_features_add = std.Target.x86.featureSet(&.{ .soft_float, .retpoline, .retpoline_external_thunk }),
            .cpu_features_sub = std.Target.x86.featureSet(&.{ .mmx, .sse, .sse2, .avx, .avx2 }),
        },
        else => @panic("Correct feature flags unimplemented for target arch..."),
    };

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

    const object_options: std.Build.ObjectOptions = .{
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
    const check_obj = b.addObject(object_options);
    check.dependOn(&check_obj.step);

    const zig_kernel_obj = b.addObject(object_options);

    const cmd_name = std.mem.concat(b.allocator, u8, &.{ ".", zig_kernel_obj.out_filename, ".cmd" }) catch @panic("OOM");
    const is_debug = optimize == .Debug;
    const debug_flag = if (is_debug) "ccflags-y := -DDEBUG" else "";
    const strip_zig_obj = b.fmt("strip --strip-debug {s}", .{zig_kernel_obj.out_filename});
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
    _ = kernel_module_files.add(cmd_name, "");
    _ = kernel_module_files.add("Makefile", b.fmt(
        \\{s}
        \\obj-m += pside.o
        \\pside-objs := kernel.o {s}
        \\
        \\PWD := $(CURDIR)
        \\
        \\all:
    ++ "\n\t{s}\n\t" ++
        \\$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
    ++ "\n\t{s}" ++
        \\ 
        \\clean:
    ++ "\n\t" ++
        \\$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
    , .{ debug_flag, zig_kernel_obj.out_filename, strip_zig_obj, strip_kernel_mod }));
    kernel_module_files.step.dependOn(&zig_kernel_obj.step);

    const compile = b.addSystemCommand(&.{"make"});
    compile.setCwd(kernel_module_files.getDirectory());
    compile.step.dependOn(&kernel_module_files.step);

    const source = kernel_module_files.getDirectory().join(b.allocator, "pside.ko") catch @panic("OOM");
    const dest = brk: {
        var uts: std.os.linux.utsname = undefined;
        _ = std.os.linux.uname(&uts);
        const release = uts.release;
        const release_end = std.mem.findScalar(u8, &release, 0) orelse release.len;
        break :brk std.mem.concat(b.allocator, u8, &.{ "lib/modules/", release[0..release_end], "/extra/pside.ko" }) catch @panic("OOM");
    };
    const install_ko = b.addInstallFile(source, dest);
    install_ko.step.dependOn(&compile.step);
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
        }),
    };
    const executable = b.addExecutable(executable_options);
    b.installArtifact(executable);

    const check_exe = b.addExecutable(executable_options);
    check.dependOn(&check_exe.step);

    const uplot = b.dependency("uplot", .{});
    const web_dir: std.Build.InstallDir = .{ .custom = "usr/share/pside" };

    b.getInstallStep().dependOn(&b.addInstallFileWithDir(
        b.path("src/userspace/report/web/index.html"),
        web_dir,
        "index.html",
    ).step);
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(
        uplot.path("dist/uPlot.iife.min.js"),
        web_dir,
        "uplot.min.js",
    ).step);
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(
        uplot.path("dist/uPlot.min.css"),
        web_dir,
        "uplot.min.css",
    ).step);

    const cli_tests = b.addTest(.{ .root_module = cli_mod });
    const run_cli_tests = b.addRunArtifact(cli_tests);

    const bindings_tests = b.addTest(.{ .root_module = bindings_mod });
    const run_bindings_tests = b.addRunArtifact(bindings_tests);

    const thread_safe_tests = b.addTest(.{ .root_module = b.addModule("thread_safe", .{
        .root_source_file = b.path("src/kernelspace/causal/thread_safe.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = true,
    }) });
    const run_thread_safe_tests = b.addRunArtifact(thread_safe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_cli_tests.step);
    test_step.dependOn(&run_bindings_tests.step);
    test_step.dependOn(&run_thread_safe_tests.step);
}
