const std = @import("std");
const linux = std.os.linux;

const safety = @import("safety");
const UserIds = @import("UserIds");

const Program = @import("Program.zig");

const TracedProcess = @This();
const arch_specific = switch (@import("builtin").cpu.arch) {
    .x86_64 => @import("traced/x86_64.zig"),

    else => @compileError("Only x86_64 supported right now"),
};

const UserRegs = arch_specific.UserRegs;
const ForkError = error{ SystemResources, Unexpected };

const ChildStartError = error{
    AccessDenied,
    FileBusy,
    FileNotFound,
    FileSystem,
    InvalidExe,
    IsDir,
    NameTooLong,
    NotDir,
    ParentDead,
    PermissionDenied,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    Unexpected,
} || std.posix.PrctlError || std.posix.RaiseError || UserIds.GetError || UserIds.DropError || ptrace.PtraceError;

pub const SpawnError = error{
    CouldNotFork,
    ChildDied,
    ChildNotTraceable,
    CouldNotReadEntrypoint,
    Unexpected,
};

pub const StartError = error{ ChildDied, ChildNotTraceable, Unexpected };
pub const WaitError = error{WaitFailed};
pub const PatchError = error{ ChildDied, ChildNotTraceable, CouldNotMapInChild, Unexpected };

const Lifecycle = enum { attached, detached, reaped };

pid: linux.pid_t,
elf_entrypoint: usize,
old_entry_ins: usize,
state: safety.State(Lifecycle),

pub fn spawn(tracee_exe: Program, io: std.Io) SpawnError!TracedProcess {
    return spawnTraced(tracee_exe, io) catch |err| switch (err) {
        ForkError.SystemResources => SpawnError.CouldNotFork,
        ptrace.WaitForError.ChildExited, ptrace.WaitForError.ChildKilled => SpawnError.ChildDied,
        std.Io.Reader.Error.EndOfStream, std.Io.Reader.Error.ReadFailed => SpawnError.CouldNotReadEntrypoint,
        else => traceFailure(err),
    };
}

fn traceFailure(err: anyerror) StartError {
    return switch (err) {
        ptrace.PtraceError.ProcessNotFound => StartError.ChildDied,
        ptrace.PtraceError.PermissionDenied, ptrace.PtraceError.DeviceBusy, ptrace.PtraceError.InputOutput => StartError.ChildNotTraceable,
        else => StartError.Unexpected,
    };
}

fn spawnTraced(tracee_exe: Program, io: std.Io) !TracedProcess {
    const fork_rc = linux.fork();
    const child_pid: linux.pid_t = switch (linux.errno(fork_rc)) {
        .SUCCESS => @intCast(fork_rc),
        .AGAIN => return ForkError.SystemResources,
        .NOMEM => return ForkError.SystemResources,
        else => return ForkError.Unexpected,
    };

    if (child_pid == 0) childStart(tracee_exe) catch std.process.exit(1);

    try ptrace.waitFor(child_pid, .stop);

    try ptrace.setOptions(child_pid, &.{linux.PTRACE.O.TRACEEXEC});
    try ptrace.cont(child_pid);
    try ptrace.waitFor(child_pid, .exec);

    const elf_entrypoint = try elfRuntimeEntrypoint(child_pid, io);
    const old_ins = try ptrace.peekWord(.text, child_pid, elf_entrypoint);
    try ptrace.poke(.text, child_pid, elf_entrypoint, arch_specific.interrupt);

    try ptrace.cont(child_pid);
    try ptrace.waitTrapUntilIpReaches(child_pid, elf_entrypoint);

    return .{ .pid = child_pid, .elf_entrypoint = elf_entrypoint, .old_entry_ins = old_ins, .state = .init(.attached) };
}

fn childStart(tracee_exe: Program) ChildStartError!void {
    _ = try std.posix.prctl(.SET_PDEATHSIG, .{@backingInt(linux.SIG.KILL)});

    if (linux.getppid() == 1) return ChildStartError.ParentDead;

    if (!tracee_exe.is_sudo and linux.geteuid() == 0) {
        if (try UserIds.sudoCallerFromEnviron(tracee_exe.enviroment_map)) |calling_user|
            try calling_user.setCurrentProcessIds();
    }

    try ptrace.traceMe();
    try std.posix.raise(.STOP);

    switch (linux.errno(linux.execve(tracee_exe.path, tracee_exe.args, tracee_exe.enviroment_map.block.slice))) {
        .SUCCESS => unreachable,
        .FAULT => unreachable,
        .@"2BIG" => return ChildStartError.SystemResources,
        .MFILE => return ChildStartError.ProcessFdQuotaExceeded,
        .NAMETOOLONG => return ChildStartError.NameTooLong,
        .NFILE => return ChildStartError.SystemFdQuotaExceeded,
        .NOMEM => return ChildStartError.SystemResources,
        .ACCES => return ChildStartError.AccessDenied,
        .PERM => return ChildStartError.PermissionDenied,
        .INVAL => return ChildStartError.InvalidExe,
        .NOEXEC => return ChildStartError.InvalidExe,
        .IO => return ChildStartError.FileSystem,
        .LOOP => return ChildStartError.FileSystem,
        .ISDIR => return ChildStartError.IsDir,
        .NOENT => return ChildStartError.FileNotFound,
        .NOTDIR => return ChildStartError.NotDir,
        .TXTBSY => return ChildStartError.FileBusy,
        .LIBBAD => return ChildStartError.InvalidExe,
        else => return ChildStartError.Unexpected,
    }
}

fn elfRuntimeEntrypoint(child_pid: linux.pid_t, io: std.Io) !usize {
    const max_pid_chars = comptime std.math.log10_int(@as(usize, std.math.maxInt(linux.pid_t)));
    const fmt = "/proc/{}/auxv";

    var buff: [fmt.len - 2 + max_pid_chars]u8 = undefined;
    const auxv_path = std.fmt.bufPrint(&buff, fmt, .{child_pid}) catch unreachable;

    const auxv = try std.Io.Dir.openFileAbsolute(io, auxv_path, .{});
    defer auxv.close(io);
    var reader = auxv.reader(io, &buff);

    while (try reader.interface.takeInt(usize, .native) != std.elf.AT.ENTRY) {
        if (try reader.interface.discardShort(@sizeOf(usize)) < @sizeOf(usize)) return std.Io.Reader.Error.EndOfStream;
    }

    return reader.interface.takeInt(usize, .native);
}

pub fn start(this: *TracedProcess) StartError!void {
    this.state.assertIs(.attached);

    this.startTraced() catch |err| return traceFailure(err);

    this.state.transition(.detached);
}

fn startTraced(this: TracedProcess) !void {
    var regs = try ptrace.getRegs(this.pid);
    regs.setIp(this.elf_entrypoint);
    try ptrace.setRegs(this.pid, regs);

    try ptrace.poke(.text, this.pid, this.elf_entrypoint, std.mem.asBytes(&this.old_entry_ins));
    try ptrace.detach(this.pid);
}

pub fn wait(this: *TracedProcess) WaitError!void {
    this.state.assertIs(.detached);

    var status: i32 = undefined;
    if (linux.errno(linux.waitpid(this.pid, &status, 0)) != .SUCCESS) return WaitError.WaitFailed;

    this.state.transition(.reaped);
}

pub fn patchProgressPoint(this: TracedProcess, addr: usize, ctl_fd: linux.fd_t) PatchError!void {
    this.state.assertIs(.attached);

    return this.patchTraced(addr, ctl_fd) catch |err| switch (err) {
        MmapError.OutOfMemory, MmapError.AccessDenied, MmapError.MappingAlreadyExists, MmapError.MemoryMappingNotSupported, MmapError.LockedMemoryLimitExceeded => PatchError.CouldNotMapInChild,
        else => traceFailure(err),
    };
}

fn patchTraced(this: TracedProcess, addr: usize, ctl_fd: linux.fd_t) !void {
    const final_addr = addr +% this.elf_entrypoint;
    const code_page = try this.mmap(null, std.heap.pageSize(), @bitCast(linux.PROT{ .EXEC = true, .READ = true, .WRITE = true }), .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);

    // The child inherited the ctl fd (the same file description as the parent's
    // session), so mmapping it at offset 0 maps this recording's own per-session
    // progress page, no need to open /dev/pside_progress by path anymore.
    const chardev_page = try this.mmap(null, std.heap.pageSize(), @bitCast(linux.PROT{ .READ = true, .WRITE = true }), .{ .TYPE = .SHARED }, ctl_fd, 0);

    const trampoline = arch_specific.trampoline.get(@intFromPtr(code_page.ptr));
    try ptrace.poke(.text, this.pid, final_addr, &trampoline);

    const payload = arch_specific.payload.get(@intFromPtr(chardev_page.ptr), final_addr + arch_specific.trampoline.len);
    try ptrace.poke(.data, this.pid, @intFromPtr(code_page.ptr), &payload);
}

const MmapError = error{
    AccessDenied,
    LockedMemoryLimitExceeded,
    MappingAlreadyExists,
    MemoryMappingNotSupported,
    OutOfMemory,
    PermissionDenied,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    Unexpected,
} || ptrace.WaitForError;

fn mmap(
    this: TracedProcess,
    ptr: ?[*]align(std.heap.page_size_min) u8,
    length: usize,
    prot: u32,
    flags: linux.MAP,
    fd: linux.fd_t,
    offset: u64,
) MmapError![]align(std.heap.page_size_min) u8 {
    const addr: usize = @intFromPtr(ptr);
    const rc = try this.syscall(.mmap, .{
        addr,
        length,
        prot,
        @as(u32, @bitCast(flags)),
        @as(usize, @bitCast(@as(isize, fd))),
        offset,
    });

    return switch (linux.errno(rc)) {
        .SUCCESS => @as([*]align(std.heap.page_size_min) u8, @ptrFromInt(rc))[0..length],
        .TXTBSY => return MmapError.AccessDenied,
        .ACCES => return MmapError.AccessDenied,
        .PERM => return MmapError.PermissionDenied,
        .AGAIN => return MmapError.LockedMemoryLimitExceeded,
        .BADF => unreachable,
        .OVERFLOW => unreachable,
        .NODEV => return MmapError.MemoryMappingNotSupported,
        .INVAL => unreachable,
        .MFILE => return MmapError.ProcessFdQuotaExceeded,
        .NFILE => return MmapError.SystemFdQuotaExceeded,
        .NOMEM => return MmapError.OutOfMemory,
        .EXIST => return MmapError.MappingAlreadyExists,
        else => return MmapError.Unexpected,
    };
}

pub fn syscall(this: TracedProcess, syscall_id: linux.SYS, args: anytype) ptrace.WaitForError!usize {
    this.state.assertIs(.attached);

    const saved_regs = try ptrace.getRegs(this.pid);
    const ip = saved_regs.ip();
    const old_ins = try ptrace.peekWord(.text, this.pid, ip);

    try ptrace.poke(.text, this.pid, ip, arch_specific.syscall);

    var tmp_regs = saved_regs;
    tmp_regs.prepSyscall(syscall_id, args);
    try ptrace.setRegs(this.pid, tmp_regs);

    try ptrace.singleStep(this.pid);
    try ptrace.waitTrapUntilIpReaches(this.pid, ip + 1);

    const final_regs = try ptrace.getRegs(this.pid);
    const ret = final_regs.ret();

    try ptrace.setRegs(this.pid, saved_regs);
    try ptrace.poke(.text, this.pid, ip, std.mem.asBytes(&old_ins));

    return ret;
}

const ptrace = struct {
    pub const Location = enum { text, data };
    const machine_word_alignment = std.mem.Alignment.fromByteUnits(@sizeOf(usize));

    pub const PtraceError = error{
        DeviceBusy,
        InputOutput,
        PermissionDenied,
        ProcessNotFound,
        Unexpected,
    };

    fn ptraceSysCall(request: u32, pid: linux.pid_t, addr: usize, data: usize) PtraceError!void {
        return switch (linux.errno(linux.ptrace(request, pid, addr, data, 0))) {
            .SUCCESS => {},
            .SRCH => PtraceError.ProcessNotFound,
            .FAULT => unreachable,
            .INVAL => unreachable,
            .IO => PtraceError.InputOutput,
            .PERM => PtraceError.PermissionDenied,
            .BUSY => PtraceError.DeviceBusy,
            else => PtraceError.Unexpected,
        };
    }

    pub const WaitForError = error{
        WaitPidFailed,
        ChildExited,
        ChildKilled,
    } || PtraceError;

    fn traceMe() PtraceError!void {
        try ptraceSysCall(linux.PTRACE.TRACEME, 0, 0, 0);
    }

    fn detach(pid: linux.pid_t) PtraceError!void {
        try ptraceSysCall(linux.PTRACE.DETACH, pid, 0, 0);
    }

    fn setOptions(pid: linux.pid_t, comptime options: []const comptime_int) PtraceError!void {
        comptime var options_val: usize = 0;
        comptime for (options) |o| {
            options_val |= o;
        };

        try ptraceSysCall(linux.PTRACE.SETOPTIONS, pid, 0, options_val);
    }

    fn waitFor(pid: linux.pid_t, target: enum { exec, trap, stop }) WaitForError!void {
        while (true) {
            var status: u32 = undefined;
            if (linux.errno(linux.waitpid(pid, @ptrCast(&status), 0)) != .SUCCESS) return WaitForError.WaitPidFailed;

            if (linux.W.IFEXITED(status)) return WaitForError.ChildExited;
            if (linux.W.IFSIGNALED(status)) return WaitForError.ChildKilled;

            if (linux.W.IFSTOPPED(status)) {
                const sig = linux.W.STOPSIG(status);
                const event = status >> 16;

                switch (target) {
                    .exec => if (sig == linux.SIG.TRAP and event == linux.PTRACE.EVENT.EXEC) return,
                    .trap => if (sig == linux.SIG.TRAP and event == 0) return,
                    .stop => if (sig == linux.SIG.STOP and event == 0) return,
                }

                const signal_to_forward: u32 = if (sig == linux.SIG.TRAP or sig == linux.SIG.STOP) 0 else @backingInt(sig);

                try ptraceSysCall(linux.PTRACE.CONT, pid, 0, signal_to_forward);
            }
        }
    }

    fn waitTrapUntilIpReaches(pid: linux.pid_t, addr: usize) WaitForError!void {
        try waitFor(pid, .trap);
        while ((try getRegs(pid)).ip() < addr) {
            try waitFor(pid, .trap);
        }
    }

    fn cont(pid: linux.pid_t) PtraceError!void {
        try ptraceSysCall(linux.PTRACE.CONT, pid, 0, 0);
    }

    fn singleStep(pid: linux.pid_t) PtraceError!void {
        try ptraceSysCall(linux.PTRACE.SINGLESTEP, pid, 0, 0);
    }

    fn getRegs(pid: linux.pid_t) PtraceError!UserRegs {
        var regs: UserRegs = undefined;
        try ptraceSysCall(linux.PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
        return regs;
    }

    fn setRegs(pid: linux.pid_t, regs: UserRegs) PtraceError!void {
        try ptraceSysCall(linux.PTRACE.SETREGS, pid, 0, @intFromPtr(&regs));
    }

    fn poke(comptime location: Location, pid: linux.pid_t, addr: usize, data: []const u8) PtraceError!void {
        const command = comptime switch (location) {
            .text => linux.PTRACE.POKETEXT,
            .data => linux.PTRACE.POKEDATA,
        };

        var reader: std.Io.Reader = .fixed(data);
        var i: usize = addr;

        if (!machine_word_alignment.check(i)) {
            const aligned_addr = machine_word_alignment.backward(i);
            const offset = i - aligned_addr;

            const space_left_in_word = @sizeOf(usize) - offset;
            const copy_len = @min(space_left_in_word, data.len);

            var word = try peekWord(location, pid, aligned_addr);
            @memcpy(std.mem.asBytes(&word)[offset .. offset + copy_len], data[0..copy_len]);

            try ptraceSysCall(command, pid, aligned_addr, word);

            i += copy_len;
            reader.toss(copy_len);
        }

        while (reader.peekArray(@sizeOf(usize))) |bytes| : (i += @sizeOf(usize)) {
            try ptraceSysCall(command, pid, i, std.mem.bytesToValue(usize, bytes));
            reader.toss(@sizeOf(usize));
        } else |err| switch (err) {
            std.Io.Reader.Error.EndOfStream => {
                const len = reader.bufferedLen();
                if (len == 0) return;

                var bytes: [@sizeOf(usize)]u8 = undefined;
                const read = reader.readSliceShort(bytes[0..len]) catch unreachable;
                std.debug.assert(read == len);

                const old = try peekWord(location, pid, i);
                @memcpy(bytes[len..], std.mem.asBytes(&old)[len..]);

                try ptraceSysCall(command, pid, i, std.mem.bytesToValue(usize, &bytes));
            },
            else => unreachable,
        }
    }

    fn peekWord(comptime location: Location, pid: linux.pid_t, addr: usize) PtraceError!usize {
        const command = comptime switch (location) {
            .text => linux.PTRACE.PEEKTEXT,
            .data => linux.PTRACE.PEEKDATA,
        };

        const previus_aligned = machine_word_alignment.backward(addr);

        var data: [2]usize = undefined;

        try ptraceSysCall(command, pid, previus_aligned, @intFromPtr(&data[0]));
        try ptraceSysCall(command, pid, previus_aligned + @sizeOf(usize), @intFromPtr(&data[1]));

        const diff = addr - previus_aligned;
        return std.mem.bytesToValue(usize, std.mem.asBytes(&data)[diff .. diff + @sizeOf(usize)]);
    }
};
