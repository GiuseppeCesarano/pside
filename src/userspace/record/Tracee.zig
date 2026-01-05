const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const UserProgram = @import("UserProgram.zig");
const arch = @import("builtin").cpu.arch;

const SpawnError = error{ ChildDead, ParentDead, UnexpectedSignal, NoSudoUserID, NoSudoGroupID, CouldNotSetGroups };

pid: linux.pid_t,
elf_entrypoint: usize,
old_entry_ins: usize,

pub fn spawn(tracee_exe: UserProgram, io: std.Io) !@This() {
    const child_pid = try posix.fork();
    if (child_pid == 0) childStart(tracee_exe) catch std.process.exit(1);
    try ptrace.waitFor(child_pid, .stop);

    try ptrace.setOptions(child_pid, &.{linux.PTRACE.O.TRACEEXEC});
    try ptrace.cont(child_pid);
    try ptrace.waitFor(child_pid, .exec);

    const elf_entrypoint = try elfEntrypoint(child_pid, io);
    const old_ins = try ptrace.peekWord(.text, child_pid, elf_entrypoint);
    try ptrace.poke(.text, child_pid, elf_entrypoint, interrupt_bytes);

    try ptrace.cont(child_pid);
    try ptrace.waitTrapUntillIpReaches(child_pid, elf_entrypoint);

    return .{ .pid = child_pid, .elf_entrypoint = elf_entrypoint, .old_entry_ins = old_ins };
}

fn childStart(tracee_exe: UserProgram) !void {
    _ = try posix.prctl(linux.PR.SET_PDEATHSIG, .{@as(usize, @intFromEnum(linux.SIG.KILL))});
    if (posix.getppid() == 1) return SpawnError.ParentDead;

    if (!tracee_exe.is_sudo) {
        const gid = try std.fmt.parseInt(u32, posix.getenv("SUDO_GID") orelse return SpawnError.NoSudoGroupID, 10);
        const uid = try std.fmt.parseInt(u32, posix.getenv("SUDO_UID") orelse return SpawnError.NoSudoUserID, 10);
        if (std.posix.errno(linux.setgroups(1, &.{gid})) != .SUCCESS) return SpawnError.CouldNotSetGroups;
        try posix.setgid(gid);
        try posix.setuid(uid);
    }

    try ptrace.traceMe();
    try posix.raise(.STOP);

    return posix.execveZ(tracee_exe.path, tracee_exe.args, tracee_exe.enviroment_map);
}

fn elfEntrypoint(child_pid: linux.pid_t, io: std.Io) !usize {
    const max_pid_chars = comptime std.math.log10(@as(usize, std.math.maxInt(linux.pid_t)));
    const fmt = "/proc/{}/auxv";

    var buff: [fmt.len - 2 + max_pid_chars]u8 = undefined;
    const auxv_path = std.fmt.bufPrint(&buff, fmt, .{child_pid}) catch unreachable;

    const auxv = try std.Io.Dir.openFileAbsolute(io, auxv_path, .{});
    defer auxv.close(io);
    var reader = auxv.reader(io, &buff);

    while (try reader.interface.takeInt(usize, arch.endian()) != std.elf.AT_ENTRY) {
        if (try reader.interface.discardShort(@sizeOf(usize)) < @sizeOf(usize)) return std.Io.Reader.Error.EndOfStream;
    }

    return try reader.interface.takeInt(usize, arch.endian());
}

pub fn start(this: @This()) !void {
    try ptrace.poke(.text, this.pid, this.elf_entrypoint, std.mem.asBytes(&this.old_entry_ins));
    try ptrace.detach(this.pid);
}

pub fn wait(this: @This()) posix.rusage {
    var ru: posix.rusage = undefined;
    _ = posix.wait4(this.pid, 0, &ru);

    return ru;
}

pub fn syscall(this: @This(), syscall_id: linux.SYS, args: anytype) !c_ulong {
    const regs: UserRegs = try ptrace.getRegs(this.pid);

    const machine_word_alignment = std.mem.Alignment.fromByteUnits(@sizeOf(usize));
    const ip = machine_word_alignment.backward(regs.ip());

    const old_ins = try ptrace.peekWord(.text, this.pid, ip);

    try ptrace.poke(.text, this.pid, ip, syscall_bytes);
    var tmp_regs = regs;
    tmp_regs.setIp(ip);
    tmp_regs.prep_syscall(syscall_id, args);
    try ptrace.setRegs(this.pid, tmp_regs);
    try ptrace.singleStep(this.pid);

    try ptrace.waitTrapUntillIpReaches(this.pid, ip + 1);

    const ret = (try ptrace.getRegs(this.pid)).ret();

    tmp_regs = regs;
    tmp_regs.setIp(ip);
    try ptrace.setRegs(this.pid, tmp_regs);
    try ptrace.poke(.text, this.pid, ip, std.mem.asBytes(&old_ins));

    return ret;
}

const ptrace = struct {
    pub const Location = enum { text, data, user };

    fn traceMe() !void {
        try posix.ptrace(linux.PTRACE.TRACEME, 0, 0, 0);
    }

    fn detach(pid: linux.pid_t) !void {
        try posix.ptrace(linux.PTRACE.DETACH, pid, 0, 0);
    }

    fn setOptions(pid: linux.pid_t, comptime options: []const comptime_int) !void {
        comptime var options_val: usize = 0;
        comptime for (options) |o| {
            options_val |= o;
        };

        try posix.ptrace(linux.PTRACE.SETOPTIONS, pid, 0, options_val);
    }

    fn waitFor(pid: linux.pid_t, target: enum { exec, trap, stop }) !void {
        while (true) {
            const status = posix.waitpid(pid, 0).status;

            if (linux.W.IFEXITED(status)) return error.ChildExited;
            if (linux.W.IFSIGNALED(status)) return error.ChildKilled;

            if (linux.W.IFSTOPPED(status)) {
                const sig = linux.W.STOPSIG(status);
                const event = status >> 16;

                switch (target) {
                    .exec => if (sig == @intFromEnum(linux.SIG.TRAP) and event == linux.PTRACE.EVENT.EXEC) return,
                    .trap => if (sig == @intFromEnum(linux.SIG.TRAP) and event == 0) return,
                    .stop => if (sig == @intFromEnum(linux.SIG.STOP) and event == 0) return,
                }

                const signal_to_forward: u32 = if (sig == @intFromEnum(linux.SIG.TRAP) or sig == @intFromEnum(linux.SIG.STOP)) 0 else sig;

                try posix.ptrace(linux.PTRACE.CONT, pid, 0, signal_to_forward);
            }
        }
    }

    fn waitTrapUntillIpReaches(pid: linux.pid_t, addr: usize) !void {
        try waitFor(pid, .trap);
        while ((try getRegs(pid)).ip() < addr) {
            try waitFor(pid, .trap);
        }
    }

    fn cont(pid: linux.pid_t) !void {
        try posix.ptrace(linux.PTRACE.CONT, pid, 0, 0);
    }

    fn singleStep(pid: linux.pid_t) !void {
        try posix.ptrace(linux.PTRACE.SINGLESTEP, pid, 0, 0);
    }

    fn getRegs(pid: linux.pid_t) !UserRegs {
        var regs: UserRegs = undefined;
        try posix.ptrace(linux.PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
        return regs;
    }

    fn setRegs(pid: linux.pid_t, regs: UserRegs) !void {
        try posix.ptrace(linux.PTRACE.SETREGS, pid, 0, @intFromPtr(&regs));
    }

    fn poke(comptime location: Location, pid: linux.pid_t, addr: usize, data: []const u8) !void {
        std.debug.assert(addr % @sizeOf(usize) == 0);

        const command = comptime switch (location) {
            .text => linux.PTRACE.POKETEXT,
            .data => linux.PTRACE.POKEDATA,
            .user => linux.PTRACE.POKEUSER,
        };

        var reader: std.Io.Reader = .fixed(data);

        var i: usize = addr;
        while (reader.peekArray(@sizeOf(usize))) |bytes| : (i += @sizeOf(usize)) {
            try posix.ptrace(command, pid, i, std.mem.bytesAsValue(usize, bytes).*);
            reader.toss(@sizeOf(usize));
        } else |err| switch (err) {
            std.Io.Reader.Error.EndOfStream => {
                const len = reader.bufferedLen();
                if (len == 0) return;

                var bytes: usize = 0;
                const bytes_slice = std.mem.asBytes(&bytes);
                const read = reader.readSliceShort(bytes_slice[0..len]) catch unreachable;
                std.debug.assert(read == len);

                const old = try peekWord(location, pid, i);
                @memcpy(bytes_slice[len..], std.mem.asBytes(&old)[len..]);

                try posix.ptrace(command, pid, i, bytes);
            },
            else => unreachable,
        }
    }

    fn peekWord(comptime location: Location, pid: linux.pid_t, addr: usize) !usize {
        std.debug.assert(addr % @sizeOf(usize) == 0);

        const command = comptime switch (location) {
            .text => linux.PTRACE.PEEKTEXT,
            .data => linux.PTRACE.PEEKDATA,
            .user => linux.PTRACE.PEEKUSER,
        };

        var data: usize = undefined;
        try posix.ptrace(command, pid, addr, @intFromPtr(&data));

        return data;
    }
};

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

const syscall_bytes: []const u8 = switch (arch) {
    .x86, .x86_16, .x86_64 => &.{ 0x0f, 0x05 },
    else => @compileError("syscall unsupported for current arch"),
};

const interrupt_bytes: []const u8 = switch (arch) {
    .x86, .x86_16, .x86_64 => &.{0xcc},
    else => @compileError("interrupt unsupported for current arch"),
};
