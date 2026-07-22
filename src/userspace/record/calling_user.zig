const std = @import("std");

/// The uid/gid that invoked us through sudo, or null when not run via sudo.
/// Used to hand freshly created files and device nodes back to the real user.
pub fn get(env: std.process.Environ) !?[2]u32 {
    const gid = try std.fmt.parseInt(u32, env.getPosix("SUDO_GID") orelse return null, 10);
    const uid = try std.fmt.parseInt(u32, env.getPosix("SUDO_UID") orelse return null, 10);

    return .{ uid, gid };
}
