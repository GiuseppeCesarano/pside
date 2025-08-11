const std = @import("std");
const Elf = @import("BpfGen/Elf.zig");

pub fn main() !void {
    const f = @embedFile("bpf.o");
    var elf = try Elf.init(f[0..]);
    var it = elf.iterateSectionHeader();

    var i: usize = 0;
    while (try it.next()) |sh| {
        i = i + 1;
        std.debug.print("{s}\n", .{sh.getName()});
    }
    std.debug.print("{}\n", .{i});
}
