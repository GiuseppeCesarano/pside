const TracedProcess = @This();
const std = @import("std");
const linux = std.os.linux;
const Program = @import("Program.zig");

const chardev_path = @import("KernelInterface.zig").chardev_path;
const arch_specific = switch (@import("builtin").cpu.arch) {
    .x86_64 => @import("traced/x86_64.zig"),

    else => @compileError("Only x86_64 supported right now"),
};

const UserRegs = arch_specific.UserRegs;
const SpawnError = error{ ChildDead, ParentDead, UnexpectedSignal, NoSudoUserID, NoSudoGroupID, CouldNotSetGroups };

pid: linux.pid_t,
elf_entrypoint: usize,
old_entry_ins: usize,

pub fn spawn(tracee_exe: Program, io: std.Io) !TracedProcess {
    const rc = linux.fork();
    const child_pid: linux.pid_t = switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AGAIN => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
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
    try ptrace.waitTrapUntillIpReaches(child_pid, elf_entrypoint);

    return .{ .pid = child_pid, .elf_entrypoint = elf_entrypoint, .old_entry_ins = old_ins };
}

fn childStart(tracee_exe: Program) !void {
    switch (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(linux.SIG.KILL), 0, 0, 0))) {
        .SUCCESS => {},
        .ACCES => return error.AccessDenied,
        .BADF => return error.InvalidFileDescriptor,
        .FAULT => return error.InvalidAddress,
        .INVAL => unreachable,
        .NODEV, .NXIO => return error.UnsupportedFeature,
        .OPNOTSUPP => return error.OperationUnsupported,
        .PERM, .BUSY => return error.PermissionDenied,
        .RANGE => unreachable,
        else => return error.Unexpected,
    }

    if (linux.getppid() == 1) return SpawnError.ParentDead;

    if (!tracee_exe.is_sudo) {
        const env = tracee_exe.enviroment_map;
        const gid = try std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse return SpawnError.NoSudoGroupID, 10);
        const uid = try std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse return SpawnError.NoSudoUserID, 10);

        if (linux.errno(linux.setgroups(1, &.{gid})) != .SUCCESS) return SpawnError.CouldNotSetGroups;

        switch (linux.errno(linux.setgid(gid))) {
            .SUCCESS => {},
            .AGAIN => return error.ResourceLimitReached,
            .INVAL => return error.InvalidUserId,
            .PERM => return error.PermissionDenied,
            else => return error.Unexpected,
        }

        switch (linux.errno(linux.setuid(uid))) {
            .SUCCESS => {},
            .INVAL => return error.InvalidUserId,
            .PERM => return error.PermissionDenied,
            else => return error.Unexpected,
        }
    }

    try ptrace.traceMe();
    try raise(.STOP);

    switch (linux.errno(linux.execve(tracee_exe.path, tracee_exe.args, tracee_exe.enviroment_map.block.slice))) {
        .SUCCESS => unreachable,
        .FAULT => unreachable,
        .@"2BIG" => return error.SystemResources,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .INVAL => return error.InvalidExe,
        .NOEXEC => return error.InvalidExe,
        .IO => return error.FileSystem,
        .LOOP => return error.FileSystem,
        .ISDIR => return error.IsDir,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .TXTBSY => return error.FileBusy,
        .LIBBAD => return error.InvalidExe,
        else => return error.Unexpected,
    }
}

fn raise(sig: linux.SIG) !void {
    const filled = linux.sigfillset();
    var orig: linux.sigset_t = undefined;
    _ = linux.sigprocmask(linux.SIG.BLOCK, &filled, &orig);
    const rc = linux.tkill(linux.gettid(), sig);
    _ = linux.sigprocmask(linux.SIG.SETMASK, &orig, null);

    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => error.Unexpected,
    };
}

fn elfRuntimeEntrypoint(child_pid: linux.pid_t, io: std.Io) !usize {
    const max_pid_chars = comptime std.math.log10(@as(usize, std.math.maxInt(linux.pid_t)));
    const fmt = "/proc/{}/auxv";

    var buff: [fmt.len - 2 + max_pid_chars]u8 = undefined;
    const auxv_path = std.fmt.bufPrint(&buff, fmt, .{child_pid}) catch unreachable;

    const auxv = try std.Io.Dir.openFileAbsolute(io, auxv_path, .{});
    defer auxv.close(io);
    var reader = auxv.reader(io, &buff);

    while (try reader.interface.takeInt(usize, .native) != std.elf.AT_ENTRY) {
        if (try reader.interface.discardShort(@sizeOf(usize)) < @sizeOf(usize)) return std.Io.Reader.Error.EndOfStream;
    }

    return try reader.interface.takeInt(usize, .native);
}

pub fn start(this: TracedProcess) !void {
    var regs = try ptrace.getRegs(this.pid);
    regs.setIp(this.elf_entrypoint);
    try ptrace.setRegs(this.pid, regs);

    try ptrace.poke(.text, this.pid, this.elf_entrypoint, std.mem.asBytes(&this.old_entry_ins));
    try ptrace.detach(this.pid);
}

pub fn kill(this: TracedProcess) !void {
    return switch (linux.errno(linux.kill(this.pid, .KILL))) {
        .SUCCESS => {},
        .PERM => error.PermissionDenied,
        .SRCH => error.ProcessNotFound,
        else => error.Unexpected,
    };
}

pub fn wait(this: TracedProcess) !u32 {
    var status: u32 = undefined;
    if (linux.errno(linux.waitpid(this.pid, &status, 0)) != .SUCCESS) return error.WaitPidError;

    return status;
}

pub fn patchProgressPoint(this: TracedProcess, addr: usize) !void {
    const final_addr = addr +% this.elf_entrypoint;
    const code_page = try this.mmap(null, std.heap.pageSize(), @bitCast(linux.PROT{ .EXEC = true, .READ = true, .WRITE = true }), .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);

    // We use the code_page to temporally store the path on the child memory
    const path = chardev_path.ptr[0 .. chardev_path.len + 1]; // Include the null terminator
    try ptrace.poke(.data, this.pid, @intFromPtr(code_page.ptr), path);

    const chardev_fd = try this.open(code_page.ptr, .{ .ACCMODE = .RDWR }, 0);
    const chardev_page = try this.mmap(null, std.heap.pageSize(), @bitCast(linux.PROT{ .READ = true, .WRITE = true }), .{ .TYPE = .SHARED }, chardev_fd, 0);

    const trampoline = arch_specific.trampoline.get(@intFromPtr(code_page.ptr));
    try ptrace.poke(.text, this.pid, final_addr, &trampoline);

    const payload = arch_specific.payload.get(@intFromPtr(chardev_page.ptr), final_addr + arch_specific.trampoline.len);
    try ptrace.poke(.data, this.pid, @intFromPtr(code_page.ptr), &payload);
}

pub fn open(
    this: TracedProcess,
    file_path: *anyopaque,
    flags: linux.O,
    perm: linux.mode_t,
) !linux.fd_t {
    while (true) {
        const rc = try this.syscall(
            .open,
            .{ @as(u64, @intFromPtr(file_path)), @as(u32, @bitCast(flags)), perm },
        );

        return switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .INTR => continue,

            .INVAL => error.BadPathName,
            .ACCES => error.AccessDenied,
            .FBIG => error.FileTooBig,
            .OVERFLOW => error.FileTooBig,
            .ISDIR => error.IsDir,
            .LOOP => error.SymLinkLoop,
            .MFILE => error.ProcessFdQuotaExceeded,
            .NAMETOOLONG => error.NameTooLong,
            .NFILE => error.SystemFdQuotaExceeded,
            .NODEV => error.NoDevice,
            .NOENT => error.FileNotFound,
            .SRCH => error.FileNotFound,
            .NOMEM => error.SystemResources,
            .NOSPC => error.NoSpaceLeft,
            .NOTDIR => error.NotDir,
            .PERM => error.PermissionDenied,
            .EXIST => error.PathAlreadyExists,
            .BUSY => error.DeviceBusy,
            .ILSEQ => error.BadPathName,
            else => error.Unexpected,
        };
    }
}

fn mmap(
    this: TracedProcess,
    ptr: ?[*]align(std.heap.page_size_min) u8,
    length: usize,
    prot: u32,
    flags: linux.MAP,
    fd: linux.fd_t,
    offset: u64,
) ![]align(std.heap.page_size_min) u8 {
    const addr: usize = @intFromPtr(ptr);
    const rc = try this.syscall(.mmap, .{
        addr,
        length,
        prot,
        @as(u32, @bitCast(flags)),
        @as(usize, @bitCast(@as(isize, fd))),
        @as(u64, @bitCast(offset)) / std.heap.pageSize(),
    });

    const err = linux.errno(rc);
    if (err == .SUCCESS) return @as([*]align(std.heap.page_size_min) u8, @ptrFromInt(rc))[0..length];

    switch (err) {
        .SUCCESS => unreachable,
        .TXTBSY => return error.AccessDenied,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .AGAIN => return error.LockedMemoryLimitExceeded,
        .BADF => unreachable,
        .OVERFLOW => unreachable,
        .NODEV => return error.MemoryMappingNotSupported,
        .INVAL => unreachable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.OutOfMemory,
        .EXIST => return error.MappingAlreadyExists,
        else => return error.Unexpected,
    }
}

pub fn syscall(this: TracedProcess, syscall_id: linux.SYS, args: anytype) !usize {
    const saved_regs = try ptrace.getRegs(this.pid);
    const ip = saved_regs.ip();
    const old_ins = try ptrace.peekWord(.text, this.pid, ip);

    try ptrace.poke(.text, this.pid, ip, arch_specific.syscall);

    var tmp_regs = saved_regs;
    tmp_regs.prep_syscall(syscall_id, args);
    try ptrace.setRegs(this.pid, tmp_regs);

    try ptrace.singleStep(this.pid);
    try ptrace.waitTrapUntillIpReaches(this.pid, ip + 1);

    const final_regs = try ptrace.getRegs(this.pid);
    const ret = final_regs.ret();

    try ptrace.setRegs(this.pid, saved_regs);
    try ptrace.poke(.text, this.pid, ip, std.mem.asBytes(&old_ins));

    return ret;
}

const ptrace = struct {
    pub const Location = enum { text, data, user };
    const machine_word_alignment = std.mem.Alignment.fromByteUnits(@sizeOf(usize));

    pub const PtraceError = error{
        DeadLock,
        DeviceBusy,
        InputOutput,
        NameTooLong,
        OperationUnsupported,
        OutOfMemory,
        ProcessNotFound,
        PermissionDenied,
    } || error{Unexpected};

    fn ptraceSysCall(request: u32, pid: linux.pid_t, addr: usize, data: usize) PtraceError!void {
        return switch (linux.errno(linux.ptrace(request, pid, addr, data, 0))) {
            .SUCCESS => {},
            .SRCH => PtraceError.ProcessNotFound,
            .FAULT => unreachable,
            .INVAL => unreachable,
            .IO => PtraceError.InputOutput,
            .PERM => PtraceError.PermissionDenied,
            .BUSY => PtraceError.DeviceBusy,
            else => error.Unexpected,
        };
    }

    fn traceMe() !void {
        try ptraceSysCall(linux.PTRACE.TRACEME, 0, 0, 0);
    }

    fn detach(pid: linux.pid_t) !void {
        try ptraceSysCall(linux.PTRACE.DETACH, pid, 0, 0);
    }

    fn setOptions(pid: linux.pid_t, comptime options: []const comptime_int) !void {
        comptime var options_val: usize = 0;
        comptime for (options) |o| {
            options_val |= o;
        };

        try ptraceSysCall(linux.PTRACE.SETOPTIONS, pid, 0, options_val);
    }

    fn waitFor(pid: linux.pid_t, target: enum { exec, trap, stop }) !void {
        while (true) {
            var status: u32 = undefined;
            if (linux.errno(linux.waitpid(pid, &status, 0)) != .SUCCESS) return error.WaitPidError;

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

                try ptraceSysCall(linux.PTRACE.CONT, pid, 0, signal_to_forward);
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
        try ptraceSysCall(linux.PTRACE.CONT, pid, 0, 0);
    }

    fn singleStep(pid: linux.pid_t) !void {
        try ptraceSysCall(linux.PTRACE.SINGLESTEP, pid, 0, 0);
    }

    fn getRegs(pid: linux.pid_t) !UserRegs {
        var regs: UserRegs = undefined;
        try ptraceSysCall(linux.PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
        return regs;
    }

    fn setRegs(pid: linux.pid_t, regs: UserRegs) !void {
        try ptraceSysCall(linux.PTRACE.SETREGS, pid, 0, @intFromPtr(&regs));
    }

    fn poke(comptime location: Location, pid: linux.pid_t, addr: usize, data: []const u8) !void {
        const command = comptime switch (location) {
            .text => linux.PTRACE.POKETEXT,
            .data => linux.PTRACE.POKEDATA,
            .user => linux.PTRACE.POKEUSER,
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

    fn peekWord(comptime location: Location, pid: linux.pid_t, addr: usize) !usize {
        const command = comptime switch (location) {
            .text => linux.PTRACE.PEEKTEXT,
            .data => linux.PTRACE.PEEKDATA,
            .user => linux.PTRACE.PEEKUSER,
        };

        const previus_aligned = machine_word_alignment.backward(addr);

        var data: [2]usize = undefined;

        try ptraceSysCall(command, pid, previus_aligned, @intFromPtr(&data[0]));
        try ptraceSysCall(command, pid, previus_aligned + @sizeOf(usize), @intFromPtr(&data[1]));

        const diff = addr - previus_aligned;
        return std.mem.bytesToValue(usize, std.mem.asBytes(&data)[diff .. diff + @sizeOf(usize)]);
    }
};
