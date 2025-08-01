const std = @import("std");

pub fn build(b: *std.Build) void {
    // const target = b.standardTargetOptions(.{});
    // const optimize = b.standardOptimizeOption(.{});

    const bpf_gen = buildBpfGen(b);

    b.installArtifact(bpf_gen);
}

fn buildBpfGen(b: *std.Build) *std.Build.Step.Compile {
    const libz_dep = b.dependency("libz", .{
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    });
    const libelf_dep = b.dependency("libelf", .{
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    });
    const libbpf = b.dependency("libbpf", .{});
    const bpf = b.addLibrary(.{
        .name = "bpf",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .ReleaseFast,
            .link_libc = true,
            .sanitize_c = .off,
        }),
    });
    bpf.root_module.addIncludePath(libbpf.path("src"));
    bpf.root_module.addIncludePath(libbpf.path("include"));
    bpf.root_module.addIncludePath(libbpf.path("include/uapi"));
    bpf.root_module.addCSourceFiles(.{
        .root = libbpf.path("src"),
        .files = &.{
            "bpf.c",
            "btf.c",
            "libbpf.c",
            "libbpf_errno.c",
            "netlink.c",
            "nlattr.c",
            "str_error.c",
            "libbpf_probes.c",
            "bpf_prog_linfo.c",
            "btf_dump.c",
            "hashmap.c",
            "ringbuf.c",
            "strset.c",
            "linker.c",
            "gen_loader.c",
            "relo_core.c",
            "usdt.c",
            "zip.c",
            "elf.c",
            "features.c",
            "btf_iter.c",
            "btf_relocate.c",
        },
        .flags = &.{
            "-D_LARGEFILE64_SOURCE",
            "-D_FILE_OFFSET_BITS=64",
        },
    });
    bpf.linkLibrary(libz_dep.artifact("z"));
    bpf.linkLibrary(libelf_dep.artifact("elf"));

    const BpfGen = b.addExecutable(.{
        .name = "BpfGen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/BpfGen/BpfGen.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    BpfGen.linkLibrary(bpf);
    BpfGen.root_module.addIncludePath(libbpf.path("src"));

    return BpfGen;
}
