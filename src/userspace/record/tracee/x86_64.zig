const std = @import("std");

pub const syscall: []const u8 = &.{ 0x0f, 0x05 }; // syscall
pub const interrupt: []const u8 = &.{0xcc}; // int3

pub const payload = struct {
    const bytes = [_]u8{
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, <ptr>
        0x48, 0xc7, 0x00, 0x45, 0x00, 0x00, 0x00, //  movq [rax], 69
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, <ret>
        0xff, 0xe0, // jmp rax
    };

    pub const len = bytes.len;

    pub fn get(inc_addr: usize, ret_addr: usize) [len]u8 {
        var b = bytes;

        @memcpy(b[2..10], std.mem.asBytes(&inc_addr));
        @memcpy(b[19..27], std.mem.asBytes(&ret_addr));

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

    pub fn ip(this: @This()) c_ulong {
        return this.rip;
    }

    pub fn setIp(this: *@This(), new_ip: c_ulong) void {
        this.rip = new_ip;
    }

    pub fn ret(this: @This()) c_ulong {
        return this.rax;
    }

    pub fn prep_syscall(this: *@This(), syscall_id: std.os.linux.SYS, args: anytype) void {
        const fields = [_]usize{
            @offsetOf(@This(), "rdi"),
            @offsetOf(@This(), "rsi"),
            @offsetOf(@This(), "rdx"),
            @offsetOf(@This(), "r10"),
            @offsetOf(@This(), "r8"),
            @offsetOf(@This(), "r9"),
        };
        std.debug.assert(args.len <= fields.len);
        const len = @min(args.len, fields.len);

        this.rax = @intFromEnum(syscall_id);
        inline for (args, fields[0..len]) |arg, field| {
            const field_ptr: *usize = @ptrFromInt(@as(usize, @intFromPtr(this)) + field);
            field_ptr.* = arg;
        }
    }
};
