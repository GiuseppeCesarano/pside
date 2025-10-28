const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .whitelist = &.{.{ .os_tag = .linux }} });
    const optimize = b.standardOptimizeOption(.{});

    const kernel_module_files = createKernelModuleFiles(b, createZigKernelObj(b, target));

    const is_build_standalone = b.option(bool, "standalone-build", "Create a self-contained build folder that can be used" ++
        "to compile the kernel module on another system without requiring the Zig compiler.") orelse false;
    if (is_build_standalone) {
        installKernelModuleFiles(b, kernel_module_files);
    } else {
        installCompiledKernelModuleObject(b, kernel_module_files);
    }

    const executable = b.addExecutable(.{
        .name = "pside",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(executable);
}

fn createZigKernelObj(b: *std.Build, target: std.Build.ResolvedTarget) *std.Build.Step.Compile {
    var kernel_target = target;
    kernel_target.result.os.tag = .freestanding;

    return b.addObject(.{
        .name = "pside_zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/kernel_module/pside.zig"),
            .target = kernel_target,
            .optimize = .ReleaseSmall,
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
        }),
    });
}

fn createKernelModuleFiles(b: *std.Build, zig_kernel_obj: *std.Build.Step.Compile) *std.Build.Step.WriteFile {
    const cmd_name = std.mem.concat(b.allocator, u8, &.{ ".", zig_kernel_obj.out_filename, ".cmd" }) catch @panic("OOM");

    const write_files = b.addWriteFiles();
    _ = write_files.addCopyFile(zig_kernel_obj.getEmittedBin(), zig_kernel_obj.out_filename);
    _ = write_files.addCopyFile(b.path("src/kernel_module/boot.c"), "boot.c");
    _ = write_files.add(cmd_name, "");
    // We don't want users to run make in random folders, so we encapsulate the makefile in this build script
    _ = write_files.add("Makefile", "" ++
        "obj-m += pside.o\n" ++
        "pside-objs := boot.o pside_zig.o\n" ++
        "\n" ++
        "PWD := $(CURDIR)\n" ++
        "\n" ++
        "all:\n" ++
        "\t$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules\n" ++
        "\n" ++
        "clean:\n" ++
        "\t$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean\n");

    write_files.step.dependOn(&zig_kernel_obj.step);

    return write_files;
}

fn installKernelModuleFiles(b: *std.Build, kernel_module_files: *std.Build.Step.WriteFile) void {
    const install = b.addInstallDirectory(.{
        .source_dir = kernel_module_files.getDirectory(),
        .install_dir = .prefix,
        .install_subdir = "kernel_module",
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
        const kernel_version = release[0..std.mem.indexOfScalar(u8, &release, 0).?];
        break :brk std.mem.concat(b.allocator, u8, &.{ "lib/modules/", kernel_version, "/extra/pside.ko" }) catch @panic("OOM");
    };
    const install = b.addInstallFile(source, dest);
    install.step.dependOn(&compile.step);

    b.getInstallStep().dependOn(&install.step);
}
