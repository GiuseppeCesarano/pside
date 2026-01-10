pub inline fn throughputPoint(comptime name: []const u8) void {
    if (name.len >= 256) @compileError("PSIDE point name exceeds 255 characters");

    asm volatile (
        \\   .p2align 4
        \\ 1:
        \\   .byte 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
        \\   .byte 0x0f, 0x1f, 0x40, 0x00
        \\   .pushsection .pside_throughput, "R", @progbits
        \\   .align 8
        \\   .quad 1b
    ++ "\n" ++ " .asciz \"" ++ name ++ "\"\n" ++
        \\   .popsection
    ::: .{ .rax = true });
}
