pub inline fn throughputPoint(comptime name: []const u8) void {
    if (name.len == 0) @compileError("PSIDE point needs a name");

    asm volatile (
        \\   .p2align 4
        \\ 1:
        \\   .byte 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
        \\   .byte 0x0f, 0x1f, 0x40, 0x00
        \\   .pushsection .pside_throughput, "R", @progbits
        \\   .quad 1b
    ++ "\n" ++ " .asciz \"" ++ name ++ "\"\n" ++
        \\   .popsection
    ::: .{ .rax = true });
}
