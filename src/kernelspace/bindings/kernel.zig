// TODO: this file should be replaced when we have full support
// for translate-c in zig

const std = @import("std");
const is_target_kernel = @import("builtin").target.os.tag == .freestanding;

// We test the custom allocator replacing kernel calls with malloc and free
const c = if (!is_target_kernel) @cImport({
    @cInclude("stdlib.h");
}) else {};

pub const mem = struct {
    extern fn c_copy_to_user(*anyopaque, *const anyopaque, usize) usize;
    pub fn copyBytesToUser(to: *anyopaque, from: []const u8) usize {
        return c_copy_to_user(to, from.ptr, from.len);
    }

    extern fn c_copy_from_user(*anyopaque, *const anyopaque, usize) usize;
    pub fn copyBytesFromUser(to: []u8, from: []const u8) []const u8 {
        const len = @min(to.len, from.len);
        return to[0 .. len - c_copy_from_user(to.ptr, from.ptr, len)];
    }
};

pub const heap = struct {
    pub fn KAllocator(cmalloc: fn (c_ulong) callconv(.c) ?*anyopaque) type {
        return struct {
            extern fn c_kfree(*anyopaque) void;
            const cfree = if (is_target_kernel) c_kfree else c.free;

            const Metadata = u16;

            const vtable: std.mem.Allocator.VTable = .{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            };

            fn alloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
                std.debug.assert(len > 0);
                const alignment_bytes = alignment.toByteUnits();
                std.debug.assert(alignment_bytes < std.math.maxInt(Metadata));

                // We will overallocate for the maximum alignment padding
                // which is the alignement_bytes - 1 + @SizeOf(metadata)
                // to save how many bytes we skipped.
                //
                // The metadata will be the value preceding the returned ptr
                const unaligned_address = @intFromPtr(cmalloc(@intCast(len + alignment_bytes + @sizeOf(Metadata) - 1)) orelse return null);

                // If the address is already aligned alignForward
                // will not advance and we will not have space for
                // our metadata byte so we need to advance by one
                const aligned_address = alignment.forward(unaligned_address + @sizeOf(Metadata));

                const ptr: [*]align(1) Metadata = @ptrFromInt(aligned_address);
                (ptr - 1)[0] = @truncate(aligned_address - unaligned_address);

                return @ptrCast(ptr);
            }

            fn resize(_: *anyopaque, buf: []u8, _: std.mem.Alignment, new_len: usize, _: usize) bool {
                // We don't have any facility that forces in place resizing
                // so this operation can only succeed if the new len is less
                // than the old one.
                return new_len <= buf.len;
            }

            fn remap(context: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, return_address: usize) ?[*]u8 {
                // krealloc could potentially return an allocation that
                // doesn't respect the alginment required so is not
                // suitable to achive the remap implementation
                return if (resize(context, buf, alignment, new_len, return_address)) buf.ptr else null;
            }

            fn free(_: *anyopaque, buf: []u8, _: std.mem.Alignment, _: usize) void {
                const buf_ptr: [*]u8 = @ptrCast(buf.ptr);

                const metadata_ptr: [*]align(1) Metadata = @ptrCast(buf_ptr);
                const skipped_bytes = (metadata_ptr - 1)[0];

                cfree(@ptrCast(buf_ptr - skipped_bytes));
            }
        };
    }

    // This allocator doesn't support alignments requiroments > 255 bytes.
    extern fn c_kmalloc(c_ulong) ?*anyopaque;
    pub const allocator: std.mem.Allocator = .{
        .ptr = undefined,
        .vtable = &KAllocator(if (is_target_kernel) c_kmalloc else c.malloc).vtable,
    };

    extern fn c_kmalloc_atomic(c_ulong) ?*anyopaque;
    pub const atomic_allocator: std.mem.Allocator = .{
        .ptr = undefined,
        .vtable = &KAllocator(c_kmalloc_atomic).vtable,
    };
};

pub fn LogWithName(comptime module_name: []const u8) type {
    return struct {
        extern fn c_pr_err([*:0]const u8) void;
        extern fn c_pr_warn([*:0]const u8) void;
        extern fn c_pr_info([*:0]const u8) void;
        extern fn c_pr_debug([*:0]const u8) void;

        pub fn logFn(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime fmt: []const u8, args: anytype) void {
            var buf: [128]u8 = undefined;
            const scope_name = if (scope == .default) module_name else @tagName(scope);
            const scoped_fmt = scope_name ++ ": " ++ fmt ++ "\n";
            const string = if (@inComptime())
                std.fmt.comptimePrint(scoped_fmt, args)
            else
                std.fmt.bufPrintSentinel(&buf, scoped_fmt, args, 0) catch scope_name ++ " PRINT FAILED: No space left in formatting buffer\n";

            switch (level) {
                .err => c_pr_err(string),
                .warn => c_pr_warn(string),
                .info => c_pr_info(string),
                .debug => c_pr_debug(string),
            }
        }
    };
}

pub const time = struct {
    pub const delay = struct {
        extern fn c_ndelay(c_ulong) void;
        pub fn ns(nsec: usize) void {
            if (nsec == 0) return;

            c_ndelay(@intCast(@mod(nsec, 1000)));
            us(@divFloor(nsec, 1000));
        }

        extern fn c_udelay(c_ulong) void;
        pub fn us(usec: usize) void {
            if (usec == 0) return;

            c_udelay(@intCast(@mod(usec, 1000)));
            ms(@divFloor(usec, 1000));
        }

        extern fn c_mdelay(c_ulong) void;
        pub fn ms(msec: usize) void {
            if (msec == 0) return;
            c_mdelay(@intCast(msec));
        }
    };

    pub const now = struct {
        extern fn c_ktime_get_ns() u64;
        pub fn ns() u64 {
            return c_ktime_get_ns();
        }

        pub fn us() u64 {
            return @divTrunc(ns(), 1000);
        }

        pub fn ms() u64 {
            return @divTrunc(us(), 1000);
        }

        pub fn s() u64 {
            return @divTrunc(ms(), 1000);
        }
    };
};

pub const current_task = struct {
    extern fn c_tid() std.os.linux.pid_t;
    pub fn tid() std.os.linux.pid_t {
        return c_tid();
    }

    extern fn c_pid() std.os.linux.pid_t;
    pub fn pid() std.os.linux.pid_t {
        return c_pid();
    }
};

pub const Path = extern struct {
    pub const OpenError = error{
        NoEntity,
        ComponentNotDir,
        OutOfMemory,
        Invalid,
        Unknown,
    };

    mount: *anyopaque,
    dentry: *anyopaque,

    extern fn c_kern_path([*:0]const u8, *i32) @This();
    pub fn init(path: [:0]const u8) OpenError!@This() {
        var err: i32 = undefined;
        const ret = c_kern_path(path.ptr, &err);
        return switch (std.os.linux.errno(@intCast(err))) {
            .SUCCESS => ret,

            .NOENT => OpenError.NoEntity,
            .NOTDIR => OpenError.ComponentNotDir,
            .NOMEM => OpenError.OutOfMemory,
            .INVAL => OpenError.Invalid,
            else => OpenError.Unknown,
        };
    }

    extern fn c_path_put(*@This()) void;
    pub fn deinit(this: *@This()) void {
        return c_path_put(this);
    }

    extern fn c_d_inode(*anyopaque) *anyopaque;
    pub fn inode(this: *@This()) *anyopaque {
        return c_d_inode(this.dentry);
    }
};

pub const probe = struct {
    pub const PtRegs = anyopaque;
    pub const FtraceRegs = opaque {
        extern fn c_ftrace_regs_get_instruction_pointer(*@This()) c_ulong;
        pub fn getInstructionPointer(this: *@This()) c_ulong {
            return c_ftrace_regs_get_instruction_pointer(this);
        }

        extern fn c_ftrace_regs_get_argument(*@This(), c_uint) c_ulong;
        pub fn getArgument(this: *@This(), n: c_uint) c_ulong {
            return c_ftrace_regs_get_argument(this, n);
        }

        extern fn c_ftrace_regs_get_stack_pointer(*@This()) c_ulong;
        pub fn getStackPointer(this: *@This()) c_ulong {
            return c_ftrace_regs_get_stack_pointer(this);
        }

        extern fn c_ftrace_regs_get_return_value(*@This()) c_ulong;
        pub fn getReturnValue(this: *@This()) c_ulong {
            return c_ftrace_regs_get_return_value(this);
        }

        extern fn c_ftrace_regs_set_return_value(*@This(), c_ulong) void;
        pub fn setReturnValue(this: *@This(), ret: c_ulong) void {
            c_ftrace_regs_set_return_value(this, ret);
        }

        extern fn c_ftrace_regs_get_frame_pointer(*@This()) c_ulong;
        pub fn getFramePointer(this: *@This()) c_ulong {
            return c_ftrace_regs_get_frame_pointer(this);
        }
    };

    pub const RegistrationError = error{
        NoEntity,
        Again,
        Exist,
        Access,
        OutOfMemory,
        Fault,
        InvalidArgument,
        Unexpected,
    };

    pub fn checkRegistration(val: anytype) RegistrationError!@TypeOf(val) {
        const casted: u64 = if (@typeInfo(@TypeOf(val)) == .pointer) @intFromPtr(val) else @intCast(@abs(val));
        return switch (std.os.linux.errno(casted)) {
            .SUCCESS => val,

            .NOENT => RegistrationError.NoEntity,
            .AGAIN => RegistrationError.Again,
            .EXIST => RegistrationError.Exist,
            .ACCES => RegistrationError.Access,
            .NOMEM => RegistrationError.OutOfMemory,
            .FAULT => RegistrationError.Fault,
            .INVAL => RegistrationError.InvalidArgument,
            else => RegistrationError.Unexpected,
        };
    }

    pub const U = struct {
        // This struct is the Consumer struct in c land
        pub const Callbacks = extern struct {
            pub const PreHandler = ?*const fn (*@This(), *PtRegs, *u64) callconv(.c) c_int;
            pub const PostHandler = ?*const fn (*@This(), *PtRegs, c_ulong, *u64) callconv(.c) c_int;
            pub const Filter = ?*const fn (*@This(), *anyopaque) callconv(.c) bool;

            pre_handler: PreHandler = null,
            post_handler: PostHandler = null,
            filter: Filter = null,
            list_head: [2]usize = undefined,
            id: u64 = undefined,
        };

        path: Path,
        callbacks: Callbacks,
        offset: u64,
        handle: *anyopaque = undefined,

        pub fn init(path: [:0]const u8, callbacks: Callbacks, offset: u64) Path.OpenError!@This() {
            return .{ .path = try .init(path), .callbacks = callbacks, .offset = offset };
        }

        extern fn c_uprobe_register(*anyopaque, u64, *Callbacks) *anyopaque;
        pub fn register(this: *@This()) RegistrationError!void {
            this.handle = try checkRegistration(c_uprobe_register(this.path.inode(), this.offset, &this.callbacks));
        }

        extern fn c_uprobe_unregister(*anyopaque, *Callbacks) void;
        pub fn unregister(this: *@This()) void {
            c_uprobe_unregister(this.handle, &this.callbacks);
        }

        pub fn deinit(this: *@This()) void {
            this.path.deinit();
        }
    };

    pub const F = extern struct {
        pub const Callbacks = extern struct {
            pub const PreHandler = ?*const fn (*F, c_ulong, c_ulong, *FtraceRegs, ?*anyopaque) callconv(.c) c_int;
            pub const PostHandler = ?*const fn (*F, c_ulong, c_ulong, *FtraceRegs, ?*anyopaque) callconv(.c) void;

            pre_handler: PreHandler = null,
            post_handler: PostHandler = null,
        };

        nmissed: c_ulong = 0,
        flags: c_uint = 0,
        entry_data_size: usize = 0,
        callbacks: Callbacks,
        hlist_array: ?*anyopaque = null,

        extern fn c_register_fprobe(*@This(), ?[*]const u8, ?[*]const u8) c_int;
        pub fn register(this: *@This(), filter: [:0]const u8, notfilter: ?[:0]const u8) RegistrationError!void {
            _ = try checkRegistration(c_register_fprobe(this, filter.ptr, if (notfilter) |n| n.ptr else null));
        }

        extern fn c_unregister_fprobe(*@This()) void;
        pub fn unregister(this: *@This()) void {
            _ = c_unregister_fprobe(this);
        }

        extern fn c_disable_fprobe(*@This()) void;
        pub fn disable(this: *@This()) void {
            c_disable_fprobe(this);
        }

        extern fn c_enable_fprobe(*@This()) void;
        pub fn enable(this: *@This()) void {
            c_enable_fprobe(this);
        }
    };
};

pub const CharDevice = struct {
    _: [400]u8 = undefined,
    pub const ReadHandler = ?*const fn (*anyopaque, [*]u8, usize, *i64) callconv(.c) isize;
    pub const WriteHandler = ?*const fn (*anyopaque, [*]const u8, usize, *i64) callconv(.c) isize;

    extern fn c_chardev_register(*@This(), [*:0]const u8, ReadHandler, WriteHandler) c_int;
    pub fn create(this: *@This(), file_name: [:0]const u8, read_handler: ReadHandler, write_handler: WriteHandler) void {
        _ = c_chardev_register(this, file_name.ptr, read_handler, write_handler);
    }

    extern fn c_chardev_unregister(*@This()) void;
    pub fn remove(this: *@This()) void {
        c_chardev_unregister(this);
    }
};

test "Allocator" {
    try std.heap.testAllocator(heap.allocator);
    try std.heap.testAllocatorAligned(heap.allocator);
    try std.heap.testAllocatorAlignedShrink(heap.allocator);
    try std.heap.testAllocatorLargeAlignment(heap.allocator);
}
