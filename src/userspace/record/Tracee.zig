const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const UserProgram = @import("UserProgram.zig");

const chardev_path = @import("PsideKernelModule.zig").chardev_path;
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
        const env = tracee_exe.enviroment_map;
        const gid = try std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse return SpawnError.NoSudoGroupID, 10);
        const uid = try std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse return SpawnError.NoSudoUserID, 10);
        if (std.posix.errno(linux.setgroups(1, &.{gid})) != .SUCCESS) return SpawnError.CouldNotSetGroups;
        try posix.setgid(gid);
        try posix.setuid(uid);
    }

    try ptrace.traceMe();
    try posix.raise(.STOP);

    _ = linux.execve(tracee_exe.path, tracee_exe.args, tracee_exe.enviroment_map.block.ptr);
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
    var regs = try ptrace.getRegs(this.pid);
    regs.setIp(this.elf_entrypoint);
    try ptrace.setRegs(this.pid, regs);

    try ptrace.poke(.text, this.pid, this.elf_entrypoint, std.mem.asBytes(&this.old_entry_ins));
    try ptrace.detach(this.pid);
}

pub fn wait(this: @This()) !u32 {
    var status: u32 = undefined;
    if (posix.errno(linux.waitpid(this.pid, &status, 0)) != .SUCCESS) return error.WaitPidError;

    return status;
}

pub fn patchProgressPoint(this: @This(), name: []const u8) !void {
    _ = name;

    const code_page = try this.mmap(null, std.heap.pageSize(), linux.PROT.EXEC | linux.PROT.READ | linux.PROT.WRITE, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);

    // We use the code_page to temporally store the path on the child memory
    const path = chardev_path.ptr[0 .. chardev_path.len + 1]; // Include the null terminator
    try ptrace.poke(.data, this.pid, @intFromPtr(code_page.ptr), path);

    const chardev_fd = try this.open(code_page.ptr, .{ .ACCMODE = .RDWR }, 0);
    const chardev_page = try this.mmap(null, std.heap.pageSize(), linux.PROT.READ | linux.PROT.WRITE, .{ .TYPE = .SHARED }, chardev_fd, 0);

    _ = chardev_page;

    // var regs = try ptrace.getRegs(this.pid);

    // const patch_ip = std.mem.alignBackward(usize, regs.ip(), 8);

    // const return_addr = patch_ip + 12;

    // var payload_bytes = [_]u8{
    //     // Part A: The Atomic Write
    //     0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, <chardev_ptr>
    //     0x48, 0xc7, 0x00, 0x45, 0x00, 0x00, 0x00, // movq [rax], 69

    //     0x48, 0xb8,            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, <return_addr>
    //     0xff, 0xe0, // jmp rax
    // };

    // @memcpy(payload_bytes[2..10], std.mem.asBytes(&chardev_page.ptr));
    // @memcpy(payload_bytes[19..27], std.mem.asBytes(&return_addr));

    // const payload_addr = std.mem.alignForward(usize, @intFromPtr(code_page.ptr) + 64, 8);
    // try ptrace.poke(.data, this.pid, payload_addr, &payload_bytes);

    // var trampoline = [_]u8{
    //     0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, <payload_addr>
    //     0xff, 0xe0, // jmp rax
    //     0x90, 0x90,
    //     0x90, 0x90, // Padding
    // };
    // @memcpy(trampoline[2..10], std.mem.asBytes(&payload_addr));

    // try ptrace.poke(.text, this.pid, patch_ip, &trampoline);

    // regs.setIp(patch_ip);
    // try ptrace.setRegs(this.pid, regs);
}

pub fn open(
    this: @This(),
    file_path: *anyopaque,
    flags: posix.O,
    perm: posix.mode_t,
) !posix.fd_t {
    while (true) {
        const rc = try this.syscall(
            .open,
            .{ @as(u64, @intFromPtr(file_path)), @as(u32, @bitCast(flags)), perm },
        );

        const OE = posix.OpenError;
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,

            .INVAL => return OE.BadPathName,
            .ACCES => return OE.AccessDenied,
            .FBIG => return OE.FileTooBig,
            .OVERFLOW => return OE.FileTooBig,
            .ISDIR => return OE.IsDir,
            .LOOP => return OE.SymLinkLoop,
            .MFILE => return OE.ProcessFdQuotaExceeded,
            .NAMETOOLONG => return OE.NameTooLong,
            .NFILE => return OE.SystemFdQuotaExceeded,
            .NODEV => return OE.NoDevice,
            .NOENT => return OE.FileNotFound,
            .SRCH => return OE.FileNotFound,
            .NOMEM => return OE.SystemResources,
            .NOSPC => return OE.NoSpaceLeft,
            .NOTDIR => return OE.NotDir,
            .PERM => return OE.PermissionDenied,
            .EXIST => return OE.PathAlreadyExists,
            .BUSY => return OE.DeviceBusy,
            .ILSEQ => return OE.BadPathName,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn mmap(
    this: @This(),
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

    const err = posix.errno(rc);
    if (err == .SUCCESS) return @as([*]align(std.heap.page_size_min) u8, @ptrFromInt(rc))[0..length];

    const MME = posix.MMapError;
    switch (err) {
        .SUCCESS => unreachable,
        .TXTBSY => return MME.AccessDenied,
        .ACCES => return MME.AccessDenied,
        .PERM => return MME.PermissionDenied,
        .AGAIN => return MME.LockedMemoryLimitExceeded,
        .BADF => unreachable,
        .OVERFLOW => unreachable,
        .NODEV => return MME.MemoryMappingNotSupported,
        .INVAL => unreachable,
        .MFILE => return MME.ProcessFdQuotaExceeded,
        .NFILE => return MME.SystemFdQuotaExceeded,
        .NOMEM => return MME.OutOfMemory,
        .EXIST => return MME.MappingAlreadyExists,
        else => return posix.unexpectedErrno(err),
    }
}

pub fn syscall(this: @This(), syscall_id: linux.SYS, args: anytype) !usize {
    const saved_regs = try ptrace.getRegs(this.pid);
    const ip = saved_regs.ip();
    const old_ins = try ptrace.peekWord(.text, this.pid, ip);

    try ptrace.poke(.text, this.pid, ip, syscall_bytes);

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
            var status: u32 = undefined;
            if (posix.errno(linux.waitpid(pid, &status, 0)) != .SUCCESS) return error.WaitPidError;

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

            try posix.ptrace(command, pid, aligned_addr, word);

            i += copy_len;
            reader.toss(copy_len);
        }

        while (reader.peekArray(@sizeOf(usize))) |bytes| : (i += @sizeOf(usize)) {
            try posix.ptrace(command, pid, i, std.mem.bytesToValue(usize, bytes));
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

                try posix.ptrace(command, pid, i, std.mem.bytesToValue(usize, &bytes));
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

        try posix.ptrace(command, pid, previus_aligned, @intFromPtr(&data[0]));
        try posix.ptrace(command, pid, previus_aligned + @sizeOf(usize), @intFromPtr(&data[1]));

        const diff = addr - previus_aligned;
        return std.mem.bytesToValue(usize, std.mem.asBytes(&data)[diff .. diff + @sizeOf(usize)]);
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
            std.debug.assert(args.len <= fields.len);
            const len = @min(args.len, fields.len);

            this.rax = @intFromEnum(syscall_id);
            inline for (args, fields[0..len]) |arg, field| {
                const field_ptr: *usize = @ptrFromInt(@as(usize, @intFromPtr(this)) + field);
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

// const increment_atomic_bytes
