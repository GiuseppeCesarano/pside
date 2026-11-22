const std = @import("std");
const testing = std.testing;

pub const syscall_instruction = [_]u8{ 0x0f, 0x05 };

pub const call_window_len = 6;

const direct_call_opcode = 0xe8;
const direct_call_len = 5;
const indirect_call_opcode = 0xff;
const modrm_reg_mask = 0x38;
const modrm_reg_call = 2 << 3;
const indirect_call_lens = [_]usize{ 2, 3, 6 };

pub fn endsWithCall(code: *const [call_window_len]u8) bool {
    if (code[call_window_len - direct_call_len] == direct_call_opcode) return true;

    inline for (indirect_call_lens) |len| {
        const start = call_window_len - len;
        if (code[start] == indirect_call_opcode and
            code[start + 1] & modrm_reg_mask == modrm_reg_call) return true;
    }
    return false;
}

test "direct call rel32" {
    try testing.expect(endsWithCall(&.{ 0x90, 0xe8, 0x10, 0x20, 0x30, 0x40 }));
}

test "indirect call through register" {
    try testing.expect(endsWithCall(&.{ 0x90, 0x90, 0x90, 0x90, 0xff, 0xd0 }));
    try testing.expect(endsWithCall(&.{ 0x90, 0x90, 0x90, 0x41, 0xff, 0xd3 }));
}

test "indirect call through memory with disp8" {
    try testing.expect(endsWithCall(&.{ 0x90, 0x90, 0x90, 0xff, 0x50, 0x08 }));
}

test "indirect call through rip relative disp32" {
    try testing.expect(endsWithCall(&.{ 0xff, 0x15, 0x10, 0x20, 0x30, 0x40 }));
}

test "indirect jmp is not a call" {
    try testing.expect(!endsWithCall(&.{ 0x90, 0x90, 0x90, 0x90, 0xff, 0xe0 }));
    try testing.expect(!endsWithCall(&.{ 0x90, 0x90, 0x90, 0xff, 0x60, 0x08 }));
}

test "plain code is not a call" {
    try testing.expect(!endsWithCall(&.{ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }));
}
