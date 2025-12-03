const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .whitelist = &.{
            .{
                .os_tag = .linux,
                .cpu_arch = .x86_64, // bindings.c is specific to x86_64, waiting for translate-c to support kernel modules for arm/riscv
            },
        },
    });
    const optimize = b.standardOptimizeOption(.{});

    const check = b.step("check", "Check for compilation errors");

    const command_mod = b.addModule("cli", .{
        .root_source_file = b.path("src/common/commands.zig"),
        .target = target,
        .optimize = optimize,
    });

    const kernel_module_files = createKernelModuleFiles(b, optimize == .Debug, createZigKernelObj(b, target, optimize, &.{command_mod}, check));

    const is_build_standalone = b.option(bool, "standalone", "Create a self-contained build folder that can be used" ++
        " to compile the kernel module on another system without requiring the Zig compiler.") orelse false;
    if (is_build_standalone) {
        installKernelModuleFiles(b, kernel_module_files);
    } else {
        installCompiledKernelModuleObject(b, kernel_module_files);
    }

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
            .{ .name = "command", .module = command_mod },
        },
    });

    const report_mod = b.addModule("report", .{
        .root_source_file = b.path("src/userspace/report/report.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "cli", .module = cli_mod }},
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

    // Zls check without emitting object
    const check_exe = b.addExecutable(executable_options);
    check.dependOn(&check_exe.step);

    // Tests
    const cli_tests = b.addTest(.{
        .root_module = cli_mod,
    });
    const run_cli_tests = b.addRunArtifact(cli_tests);

    const kernel_bindings_test_only_mod = b.addModule("kbtom", .{
        .root_source_file = b.path("src/kernelspace/bindings/kernel.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const kbto_tests = b.addTest(.{
        .root_module = kernel_bindings_test_only_mod,
    });
    const run_kbto_tests = b.addRunArtifact(kbto_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_cli_tests.step);
    test_step.dependOn(&run_kbto_tests.step);
}

fn createZigKernelObj(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, deps: []const *std.Build.Module, check_step: *std.Build.Step) *std.Build.Step.Compile {
    var kernel_target = target;
    kernel_target.query.cpu_arch = kernel_target.query.cpu_arch orelse @import("builtin").cpu.arch;

    kernel_target.query = switch (kernel_target.query.cpu_arch.?) {
        .x86_64 => .{
            .cpu_arch = .x86_64,
            .os_tag = .freestanding,
            .abi = .none,
            .cpu_features_add = std.Target.x86.featureSet(&.{.soft_float}),
            .cpu_features_sub = std.Target.x86.featureSet(&.{ .mmx, .sse, .sse2, .avx, .avx2 }),
        },

        else => @panic("Correct feature flags unimplemented for target arch..."),
    };

    const object_options: std.Build.ObjectOptions = .{
        .name = "pside_zig",
        .use_llvm = true,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/kernelspace/pside.zig"),
            .target = kernel_target,
            .optimize = optimize,
            .link_libc = false,
            .link_libcpp = false,
            .single_threaded = true,
            .strip = true,
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
                .{ .name = "command", .module = deps[0] },
            },
        }),
    };

    // Zls check without emitting object
    const check_obj = b.addObject(object_options);
    check_step.dependOn(&check_obj.step);

    return b.addObject(object_options);
}

fn createKernelModuleFiles(b: *std.Build, is_debug: bool, zig_kernel_obj: *std.Build.Step.Compile) *std.Build.Step.WriteFile {
    const cmd_name = std.mem.concat(b.allocator, u8, &.{ ".", zig_kernel_obj.out_filename, ".cmd" }) catch @panic("OOM");

    const write_files = b.addWriteFiles();
    _ = write_files.addCopyFile(zig_kernel_obj.getEmittedBin(), zig_kernel_obj.out_filename);
    _ = write_files.addCopyFile(b.path("src/kernelspace/bindings/bindings.c"), "bindings.c");
    _ = write_files.add(cmd_name, "");
    // We don't want users to run make in random folders, so we encapsulate the makefile in this build script
    _ = write_files.add("Makefile", b.fmt("" ++
        "obj-m += pside.o\n" ++
        "pside-objs := bindings.o {s}\n" ++
        "{s}" ++ // Debug definition for bindings
        "\n" ++
        "PWD := $(CURDIR)\n" ++
        "\n" ++
        "all:\n" ++
        "\t$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules\n" ++
        "\n" ++
        "clean:\n" ++
        "\t$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean\n", .{ zig_kernel_obj.out_filename, if (is_debug) "CFLAGS_bindings.o := -DDEBUG\n" else "" }));

    write_files.step.dependOn(&zig_kernel_obj.step);

    return write_files;
}

fn installKernelModuleFiles(b: *std.Build, kernel_module_files: *std.Build.Step.WriteFile) void {
    const install = b.addInstallDirectory(.{
        .source_dir = kernel_module_files.getDirectory(),
        .install_dir = .prefix,
        .install_subdir = "kernelspace",
    });

    install.step.dependOn(&kernel_module_files.step);
    b.getInstallStep().dependOn(&install.step);
}

fn installCompiledKernelModuleObject(b: *std.Build, kernel_module_files: *std.Build.Step.WriteFile) void {
    const compile = b.addSystemCommand(&.{"make"});
    compile.setCwd(kernel_module_files.getDirectory());
    compile.step.dependOn(&kernel_module_files.step);

    const source = kernel_module_files.getDirectory().join(b.allocator, "pside.ko") catch @panic("OOM");
    const dest = brk: {
        const release = std.posix.uname().release;
        const release_end = std.mem.findScalar(u8, &release, 0) orelse release.len;
        break :brk std.mem.concat(b.allocator, u8, &.{ "lib/modules/", release[0..release_end], "/extra/pside.ko" }) catch @panic("OOM");
    };
    const install = b.addInstallFile(source, dest);
    install.step.dependOn(&compile.step);

    b.getInstallStep().dependOn(&install.step);
}
