const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const UserProgram = @import("UserProgram.zig");
const builtin = @import("builtin");
const arch = builtin.cpu.arch;

const SpawnError = error{ ChildDead, UnexpectedSignal, NoSudoUserID, NoSudoGroupID, CouldNotSetGroups };
const UserRegs = switch (arch) {
    .x86_64 => extern struct {
        r15: c_ulong,
        r14: c_ulong,
        r13: c_ulong,
        r12: c_ulong,
        rbp: c_ulong,
        rbx: c_ulong,
        r11: c_ulong,
        r10: c_ulong,
        r9: c_ulong,
        r8: c_ulong,
        rax: c_ulong,
        rcx: c_ulong,
        rdx: c_ulong,
        rsi: c_ulong,
        rdi: c_ulong,
        orig_rax: c_ulong,
        rip: c_ulong,
        cs: c_ulong,
        eflags: c_ulong,
        rsp: c_ulong,
        ss: c_ulong,
        fs_base: c_ulong,
        gs_base: c_ulong,
        ds: c_ulong,
        es: c_ulong,
        fs: c_ulong,
        gs: c_ulong,

        pub fn ip(this: @This()) c_ulong {
            return this.rip;
        }

        pub fn setIp(this: *@This(), new_ip: c_ulong) void {
            this.rip = new_ip;
        }

        pub fn ret(this: @This()) c_ulong {
            return this.rax;
        }

        pub fn prep_syscall(this: *@This(), syscall_id: linux.SYS, args: anytype) void {
            const fields = [_]usize{
                @offsetOf(@This(), "rdi"),
                @offsetOf(@This(), "rsi"),
                @offsetOf(@This(), "rdx"),
                @offsetOf(@This(), "r10"),
                @offsetOf(@This(), "r8"),
                @offsetOf(@This(), "r9"),
            };
            const len = @min(args.len, fields.len);

            this.rax = @intFromEnum(syscall_id);
            inline for (args, fields[0..len]) |arg, field| {
                const field_ptr: *c_long = @ptrFromInt(@as(usize, @intFromPtr(this)) + field);
                field_ptr.* = arg;
            }
        }
    },

    else => @compileError("UserRegs unsupported for current arch"),
};

const syscall_bytes = switch (arch) {
    .x86, .x86_16, .x86_64 => @as(usize, 0x50f),
    else => @compileError("syscall unsupported for current arch"),
};

const interrupt_bytes = switch (arch) {
    .x86, .x86_16, .x86_64 => @as(usize, 0xcc),
    else => @compileError("interrupt unsupported for current arch"),
};

pid: linux.pid_t,
elf_entrypoint: usize,
old_entry_ins: usize,

pub fn spawn(tracee_exe: UserProgram, io: std.Io) !@This() {
    const child_pid = try posix.fork();
    if (child_pid == 0) childStart(tracee_exe) catch std.process.exit(1);

    var child_status = posix.waitpid(child_pid, 0).status;

    if (!linux.W.IFSTOPPED(child_status) or linux.W.STOPSIG(child_status) != @intFromEnum(linux.SIG.STOP))
        return SpawnError.ChildDead;

    try posix.ptrace(linux.PTRACE.SETOPTIONS, child_pid, 0, linux.PTRACE.O.EXITKILL | linux.PTRACE.O.TRACEEXEC);
    try posix.ptrace(linux.PTRACE.CONT, child_pid, 0, 0);

    child_status = posix.waitpid(child_pid, 0).status;

    if (!linux.W.IFSTOPPED(child_status) or
        linux.W.STOPSIG(child_status) != @intFromEnum(linux.SIG.TRAP) or
        (child_status >> 16) != linux.PTRACE.EVENT.EXEC)
        return SpawnError.UnexpectedSignal;

    const elf_entrypoint = try elfEntrypoint(child_pid, io);
    const old_ins = oi: {
        var ins: usize = undefined;
        try posix.ptrace(linux.PTRACE.PEEKTEXT, child_pid, elf_entrypoint, @intFromPtr(&ins));
        break :oi ins;
    };

    try posix.ptrace(linux.PTRACE.POKETEXT, child_pid, elf_entrypoint, interrupt_bytes);
    try posix.ptrace(linux.PTRACE.CONT, child_pid, 0, 0);
    _ = posix.waitpid(child_pid, 0);

    return .{ .pid = child_pid, .elf_entrypoint = elf_entrypoint, .old_entry_ins = old_ins };
}

fn childStart(tracee_exe: UserProgram) !void {
    if (!tracee_exe.is_sudo) {
        const gid = try std.fmt.parseInt(u32, posix.getenv("SUDO_GID") orelse return SpawnError.NoSudoGroupID, 10);
        const uid = try std.fmt.parseInt(u32, posix.getenv("SUDO_UID") orelse return SpawnError.NoSudoUserID, 10);
        if (std.posix.errno(linux.setgroups(1, &.{gid})) != .SUCCESS) return SpawnError.CouldNotSetGroups;
        try posix.setgid(gid);
        try posix.setuid(uid);
    }

    try posix.ptrace(linux.PTRACE.TRACEME, 0, 0, 0);
    try posix.raise(.STOP);

    return posix.execveZ(tracee_exe.path, tracee_exe.args, tracee_exe.enviroment_map);
}

fn elfEntrypoint(child_pid: linux.pid_t, io: std.Io) !usize {
    const max_pid_chard = comptime std.math.log10(@as(usize, std.math.maxInt(linux.pid_t)));
    const fmt = "/proc/{}/auxv";

    var buff: [fmt.len - 2 + max_pid_chard]u8 = undefined;
    const auxv_path = std.fmt.bufPrint(&buff, fmt, .{child_pid}) catch unreachable;

    const auxv = try std.Io.Dir.openFileAbsolute(io, auxv_path, .{});
    defer auxv.close(io);
    var reader = auxv.reader(io, &buff);

    while (try reader.interface.takeInt(usize, builtin.cpu.arch.endian()) != std.elf.AT_ENTRY) {
        if (try reader.interface.discardShort(@sizeOf(usize)) < @sizeOf(usize)) return std.Io.Reader.Error.EndOfStream;
    }

    return try reader.interface.takeInt(usize, builtin.cpu.arch.endian());
}

pub fn start(this: @This()) !void {
    try posix.ptrace(linux.PTRACE.POKETEXT, this.pid, this.elf_entrypoint, this.old_entry_ins);
    try posix.ptrace(linux.PTRACE.CONT, this.pid, 0, 0);
}

pub fn wait(this: @This()) posix.rusage {
    var ru: posix.rusage = undefined;
    _ = posix.wait4(this.pid, 0, &ru);

    return ru;
}

pub fn syscall(this: @This(), syscall_id: linux.SYS, args: anytype) !c_ulong {
    var regs: UserRegs = undefined;
    try posix.ptrace(linux.PTRACE.GETREGS, this.pid, 0, @intFromPtr(&regs));

    const machine_ward_alignment = std.mem.Alignment.fromByteUnits(@sizeOf(usize));
    const ip = machine_ward_alignment.backward(regs.ip());

    const old_ins = i: {
        var ins: usize = undefined;
        try posix.ptrace(linux.PTRACE.PEEKTEXT, this.pid, ip, @intFromPtr(&ins));
        break :i ins;
    };

    try posix.ptrace(linux.PTRACE.POKETEXT, this.pid, ip, syscall_bytes);
    const syscall_regs = sr: {
        var s_regs = regs;
        s_regs.setIp(ip);
        s_regs.prep_syscall(syscall_id, args);
        break :sr s_regs;
    };
    try posix.ptrace(linux.PTRACE.SETREGS, this.pid, 0, @intFromPtr(&syscall_regs));
    try posix.ptrace(linux.PTRACE.SINGLESTEP, this.pid, 0, 0);

    _ = posix.waitpid(this.pid, 0);

    const ret_regs = rr: {
        var r: UserRegs = undefined;
        try posix.ptrace(linux.PTRACE.GETREGS, this.pid, 0, @intFromPtr(&r));
        break :rr r;
    };

    const restore_regs = rr: {
        var r = regs;
        r.rip = ip;
        break :rr r;
    };
    try posix.ptrace(linux.PTRACE.SETREGS, this.pid, 0, @intFromPtr(&restore_regs));
    try posix.ptrace(linux.PTRACE.POKETEXT, this.pid, ip, old_ins);

    return ret_regs.rax;
}
