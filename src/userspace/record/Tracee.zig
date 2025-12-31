const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pid: linux.pid_t,

const SpawnError = error{ ChildDead, UnexpectedSignal, NoSudoUserID, NoSudoGroupID };

pub fn spawn(tracee_exe: [][]const u8) !@This() {
    const child_pid = try posix.fork();
    if (child_pid == 0) childStart(tracee_exe) catch std.process.exit(1);

    _, var child_status = posix.waitpid(child_pid, 0);

    if (!linux.W.IFSTOPPED(child_status) or linux.W.STOPSIG(child_status) != @intFromEnum(linux.SIG.STOP))
        return SpawnError.ChildDead;

    try posix.ptrace(linux.PTRACE.SETOPTIONS, child_pid, 0, linux.PTRACE.O.EXITKILL | linux.PTRACE.O.TRACEEXEC);
    try posix.ptrace(linux.PTRACE.CONT, child_pid, 0, 0);

    _, child_status = posix.waitpid(child_pid, 0);

    if (!linux.W.IFSTOPPED(child_status) or
        linux.W.STOPSIG(child_status) != @intFromEnum(linux.SIG.TRAP) or
        (child_status >> 16) != linux.PTRACE.EVENT.EXEC)
        return SpawnError.UnexpectedSignal;

    return .{ .pid = child_pid };
}

fn childStart(tracee_exe: [][]const u8) !void {
    const gid = std.fmt.parseInt(u32, posix.getenv("SUDO_GID") orelse return SpawnError.NoSudoGroupID, 10);
    const uid = std.fmt.parseInt(u32, posix.getenv("SUDO_UID") orelse return SpawnError.NoSudoUserID, 10);
    try posix.setgid(gid);
    try posix.setuid(uid);

    try posix.ptrace(linux.PTRACE.TRACEME, 0, 0);
    try posix.raise(.STOP);

    comptime if (@import("builtin").output_mode != .Exe)
        @compileError("childStart needs environ which is setted up in zig start up code.");

    //TODO: execve

    _ = tracee_exe;
}

pub fn start(this: @This()) !void {
    try posix.ptrace(linux.PTRACE.CONT, this.pid, 0, 0);
}

pub fn wait(this: @This()) posix.rusage {
    var ru: posix.rusage = undefined;
    posix.wait4(this.pid, 0, &ru);
}
