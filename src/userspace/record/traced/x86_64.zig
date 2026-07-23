const std = @import("std");

pub const syscall: []const u8 = &.{ 0x0f, 0x05 }; // syscall
pub const interrupt: []const u8 = &.{0xcc}; // int3

pub const payload = struct {
    const bytes = [_]u8{
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, <ptr>
        0xf0, 0x48, 0xff, 0x00, // inc qword ptr [rax].
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, <ret>
        0xff, 0xe0, // jmp rax
    };

    pub const len = bytes.len;

    pub fn get(inc_addr: usize, ret_addr: usize) [len]u8 {
        var b = bytes;

        @memcpy(b[2..10], std.mem.asBytes(&inc_addr));
        @memcpy(b[16..24], std.mem.asBytes(&ret_addr));

        return b;
    }
};

pub const trampoline = struct {
    const bytes = [_]u8{
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, <payload_addr>
        0xff, 0xe0, // jmp rax
    };

    pub const len = bytes.len;

    pub fn get(dest_addr: usize) [len]u8 {
        var b = bytes;
        @memcpy(b[2..10], std.mem.asBytes(&dest_addr));

        return b;
    }
};

pub const UserRegs = struct {
    r15: c_ulong,
    r14: c_ulong,
    r13: c_ulong,
    r12: c_ulong,
    rbp: c_ulong,
    rbx: c_ulong,
    r11: c_ulong,
    r10: c_ulong,
    r9: c_ulong,
    r8: c_ulong,
    rax: c_ulong,
    rcx: c_ulong,
    rdx: c_ulong,
    rsi: c_ulong,
    rdi: c_ulong,
    orig_rax: c_ulong,
    rip: c_ulong,
    cs: c_ulong,
    eflags: c_ulong,
    rsp: c_ulong,
    ss: c_ulong,
    fs_base: c_ulong,
    gs_base: c_ulong,
    ds: c_ulong,
    es: c_ulong,
    fs: c_ulong,
    gs: c_ulong,

    pub fn ip(this: UserRegs) c_ulong {
        return this.rip;
    }

    pub fn setIp(this: *UserRegs, new_ip: c_ulong) void {
        this.rip = new_ip;
    }

    pub fn ret(this: UserRegs) c_ulong {
        return this.rax;
    }

    pub fn prep_syscall(this: *UserRegs, syscall_id: std.os.linux.SYS, args: anytype) void {
        const fields = [_]usize{
            @offsetOf(UserRegs, "rdi"),
            @offsetOf(UserRegs, "rsi"),
            @offsetOf(UserRegs, "rdx"),
            @offsetOf(UserRegs, "r10"),
            @offsetOf(UserRegs, "r8"),
            @offsetOf(UserRegs, "r9"),
        };
        std.debug.assert(args.len <= fields.len);
        const len = @min(args.len, fields.len);

        this.rax = @backingInt(syscall_id);
        inline for (args, fields[0..len]) |arg, field| {
            const field_ptr: *usize = @ptrFromInt(@as(usize, @intFromPtr(this)) + field);
            field_ptr.* = arg;
        }
    }
};

const testing = std.testing;

test "payload: immediates land at the patched offsets" {
    const inc_addr: usize = 0x1122334455667788;
    const ret_addr: usize = 0x99aabbccddeeff00;
    const p = payload.get(inc_addr, ret_addr);

    try testing.expectEqual(26, payload.len);
    try testing.expectEqualSlices(u8, &.{ 0x48, 0xb8 }, p[0..2]);
    try testing.expectEqual(inc_addr, std.mem.readInt(usize, p[2..10], .little));
    try testing.expectEqualSlices(u8, &.{ 0xf0, 0x48, 0xff, 0x00 }, p[10..14]);
    try testing.expectEqualSlices(u8, &.{ 0x48, 0xb8 }, p[14..16]);
    try testing.expectEqual(ret_addr, std.mem.readInt(usize, p[16..24], .little));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xe0 }, p[24..26]);
}

test "trampoline: destination lands at the patched offset" {
    const dest: usize = 0x0102030405060708;
    const t = trampoline.get(dest);

    try testing.expectEqual(12, trampoline.len);
    try testing.expectEqualSlices(u8, &.{ 0x48, 0xb8 }, t[0..2]);
    try testing.expectEqual(dest, std.mem.readInt(usize, t[2..10], .little));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xe0 }, t[10..12]);
}

test "UserRegs: prep_syscall fills id and argument registers" {
    var regs: UserRegs = std.mem.zeroes(UserRegs);

    regs.prep_syscall(.openat, .{ 1, 2, 3, 4, 5, 6 });

    try testing.expectEqual(@backingInt(std.os.linux.SYS.openat), regs.rax);
    try testing.expectEqual(1, regs.rdi);
    try testing.expectEqual(2, regs.rsi);
    try testing.expectEqual(3, regs.rdx);
    try testing.expectEqual(4, regs.r10);
    try testing.expectEqual(5, regs.r8);
    try testing.expectEqual(6, regs.r9);
}
