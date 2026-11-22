const native = switch (@import("builtin").cpu.arch) {
    .x86_64 => @import("arch/x86_64.zig"),
    else => @compileError("TODO: support other archs"),
};

pub const syscall_instruction = native.syscall_instruction;
pub const call_window_len = native.call_window_len;
pub const endsWithCall = native.endsWithCall;
