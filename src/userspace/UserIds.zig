const std = @import("std");
const linux = std.os.linux;

const UserIds = @This();

gid: u32,
uid: u32,

pub const GetError = error{
    MalformedSudoIds,
};

pub fn sudoCallerFromEnviron(env: std.process.Environ) GetError!?UserIds {
    const gid = std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse return null, 10) catch return GetError.MalformedSudoIds;
    const uid = std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse return null, 10) catch return GetError.MalformedSudoIds;

    return .{ .uid = uid, .gid = gid };
}

pub const DropError = error{
    CouldNotSetGroups,
    ResourceLimitReached,
    InvalidUserId,
    PermissionDenied,
    Unexpected,
};

pub fn setCurrentProcessIds(this: *const UserIds) DropError!void {
    if (linux.errno(linux.setgroups(1, &.{this.gid})) != .SUCCESS) return DropError.CouldNotSetGroups;

    switch (linux.errno(linux.setgid(this.gid))) {
        .SUCCESS => {},
        .AGAIN => return DropError.ResourceLimitReached,
        .INVAL => return DropError.InvalidUserId,
        .PERM => return DropError.PermissionDenied,
        else => return DropError.Unexpected,
    }

    switch (linux.errno(linux.setuid(this.uid))) {
        .SUCCESS => {},
        .INVAL => return DropError.InvalidUserId,
        .PERM => return DropError.PermissionDenied,
        else => return DropError.Unexpected,
    }
}
