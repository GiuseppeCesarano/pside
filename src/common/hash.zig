const std = @import("std");

pub fn computeHashfromFile(io: std.Io, path: []const u8) [32]u8 {
    //TODO: actually implement
    _ = io;
    _ = path;
    return @splat('0');
}
