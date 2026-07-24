const std = @import("std");
const linux = std.os.linux;

/// The uid/gid that invoked us through sudo, or null when not run via sudo.
/// Used to hand freshly created files and device nodes back to the real user.
pub fn get(env: std.process.Environ) !?[2]u32 {
    const gid = try std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse return null, 10);
    const uid = try std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse return null, 10);

    return .{ uid, gid };
}

pub const DropError = error{
    NoSudoUserID,
    NoSudoGroupID,
    CouldNotSetGroups,
    ResourceLimitReached,
    InvalidUserId,
    PermissionDenied,
    Unexpected,
};

/// When running as root through sudo, drop to the invoking user so spawned
/// work runs with the same identity as the target program. A no-op otherwise.
pub fn dropToCallingUser(env: std.process.Environ) DropError!void {
    if (linux.geteuid() != 0) return;

    const gid = std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse return DropError.NoSudoGroupID, 10) catch return DropError.NoSudoGroupID;
    const uid = std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse return DropError.NoSudoUserID, 10) catch return DropError.NoSudoUserID;

    if (linux.errno(linux.setgroups(1, &.{gid})) != .SUCCESS) return DropError.CouldNotSetGroups;

    switch (linux.errno(linux.setgid(gid))) {
        .SUCCESS => {},
        .AGAIN => return DropError.ResourceLimitReached,
        .INVAL => return DropError.InvalidUserId,
        .PERM => return DropError.PermissionDenied,
        else => return DropError.Unexpected,
    }

    switch (linux.errno(linux.setuid(uid))) {
        .SUCCESS => {},
        .INVAL => return DropError.InvalidUserId,
        .PERM => return DropError.PermissionDenied,
        else => return DropError.Unexpected,
    }
}
