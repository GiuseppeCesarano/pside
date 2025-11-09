const std = @import("std");
//TODO: check some of those c functions actually return an error
//as integer, we should implement error checking and error types.

pub const mem = struct {
    extern fn c_copy_to_user(*anyopaque, *const anyopaque, usize) usize;
    pub fn copyBytesToUser(to: *anyopaque, from: []const u8) usize {
        return c_copy_to_user(to, from.ptr, from.len);
    }

    extern fn c_copy_from_user(*anyopaque, *const anyopaque, usize) usize;
    pub fn copyBytesFromUser(to: []u8, from: *anyopaque) usize {
        return c_copy_from_user(to.ptr, from, to.len);
    }
};

pub const heap = struct {
    const KAllocator = struct {
        extern fn c_kmalloc(c_ulong) ?*anyopaque;
        extern fn c_kfree(*anyopaque) void;

        const vtable: std.mem.Allocator.VTable = .{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        };

        fn alloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
            std.debug.assert(len > 0);
            const alignment_bytes = alignment.toByteUnits();

            // We will overallocate for the maximum alignment padding
            // + 1 byte of metadata to save how many bytes we skipped
            //
            // The metadata will be the byte preceding the returned ptr
            const unaligned_address = @intFromPtr(c_kmalloc(@intCast(len + alignment_bytes)) orelse return null);
            // If the address is already aligned alignForward
            // will not advance and we will not have space for
            // our metadata byte so we need to advance by one
            const aligned_address = std.mem.alignForward(usize, unaligned_address + 1, alignment_bytes);

            const ptr: [*]u8 = @ptrFromInt(aligned_address);
            (ptr - 1)[0] = @truncate(aligned_address - unaligned_address);

            return ptr;
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
            const skipped_bytes = (buf_ptr - 1)[0];

            c_kfree(@ptrCast(buf_ptr - skipped_bytes));
        }
    };

    pub const allocator: std.mem.Allocator = .{
        .ptr = undefined,
        .vtable = &KAllocator.vtable,
    };
};

pub fn LogWithName(comptime module_name: []const u8) type {
    return struct {
        extern fn c_pr_err([*:0]const u8) void;
        extern fn c_pr_warn([*:0]const u8) void;
        extern fn c_pr_info([*:0]const u8) void;
        extern fn c_pr_debug([*:0]const u8) void;

        pub fn logFn(comptime level: std.log.Level, comptime scope: @Type(.enum_literal), comptime fmt: []const u8, args: anytype) void {
            var buf: [64]u8 = undefined;
            const scoped_fmt = (if (scope == .default) module_name else @tagName(scope)) ++ ": " ++ fmt;
            const string = if (@inComptime())
                std.fmt.comptimePrint(scoped_fmt, args)
            else
                std.fmt.bufPrintSentinel(&buf, scoped_fmt, args, 0) catch "PRINT FAILED: No space left in formatting buffer\n";

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
            c_udelay(nsec);
        }

        extern fn c_udelay(c_ulong) void;
        pub fn us(usec: usize) void {
            c_udelay(usec);
        }

        extern fn c_mdelay(c_ulong) void;
        pub fn ms(msec: usize) void {
            c_udelay(msec);
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
    mount: *anyopaque,
    dentry: *anyopaque,

    extern fn c_kern_path([*:0]const u8) @This();
    pub fn init(path: [:0]const u8) @This() {
        return c_kern_path(path);
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

// TODO: This struct is very brittle since it directly
// interfaces with the unstable kernel ABI.
//
// For now, Zig's translate-c cannot process kernel headers,
// but as soon as it does, we should replace this with a
// type translated directly from the Linux headers.
// moreover this is only valid for x86_64
pub const probe = struct {
    pub const PtRegs = anyopaque;
    pub const U = struct {
        pub const Consumer = extern struct {
            pub const PreHandler = ?*const fn (*@This(), *PtRegs, *u64) callconv(.c) c_int;
            pub const PostHandler = ?*const fn (*@This(), *PtRegs, c_ulong, *u64) callconv(.c) c_int;
            pub const Filter = ?*const fn (*@This(), *anyopaque) bool;

            pre_handler: PreHandler = null,
            post_handler: PostHandler = null,
            filter: Filter = null,
            list_head: [2]usize = undefined,
            id: u64 = undefined,
        };

        path: Path,
        consumer: Consumer,
        offset: u64,
        handle: *anyopaque = undefined,

        pub fn init(path: [:0]const u8, consumer: Consumer, offset: u64) @This() {
            return .{ .path = .init(path), .consumer = consumer, .offset = offset };
        }

        extern fn c_uprobe_register(*anyopaque, u64, *Consumer) *anyopaque;
        pub fn register(this: *@This()) void {
            this.handle = c_uprobe_register(this.path.inode(), this.offset, &this.consumer);
        }

        extern fn c_uprobe_unregister(*anyopaque, *Consumer) void;
        pub fn unregister(this: *@This()) void {
            c_uprobe_unregister(this.handle, &this.consumer);
        }

        pub fn deinit(this: *@This()) void {
            this.path.deinit();
        }
    };

    pub const K = extern struct {
        // kprobes don't really have a consumer struct
        // but i've added one for simmery with uprobes
        // Simply moving Handlers here.
        pub const Consumer = extern struct {
            pub const PreHandler = ?*const fn (*K, *PtRegs) callconv(.c) c_int;
            pub const PostHandler = ?*const fn (*K, *PtRegs, c_ulong) callconv(.c) c_int;

            pre_handler: PreHandler = null,
            post_handler: PostHandler = null,
        };

        _hlist_list: [4]usize = undefined, // skip hlist and list fields
        nmissed: c_ulong = undefined,
        addr: *c_int = undefined,
        symbol_name: [*:0]const u8,
        offset: c_uint = undefined,
        consumer: Consumer,
        opcode: u8 = undefined,
        asin: [32]u8 = undefined,
        falgs: u32 = 0,
        _padding: [4]u8 = undefined,

        pub fn init(symbol_name: [:0]const u8, consumer: Consumer) @This() {
            return .{ .symbol_name = symbol_name, .consumer = consumer };
        }

        pub fn deinit(_: @This()) @This() {} // Just for simmetry with probe.U

        extern fn c_register_kprobe(*@This()) c_int;
        pub fn register(this: *@This()) i32 {
            return c_register_kprobe(this);
        }

        extern fn c_unregister_kprobe(*@This()) void;
        pub fn unregister(this: *@This()) void {
            c_unregister_kprobe(this);
        }
    };
};

pub const Chardev = extern struct {
    // TODO: actually match the struct and add init/deinit
    // We're going to fake the struct since we will just giving
    // the correct ammount of bytes since only the c bindings
    // will access those fields.
    _: [400]u8 = undefined,
    pub const ReadHandler = ?*const fn (*anyopaque, [*]u8, usize, *i64) callconv(.c) isize;
    pub const WriteHandler = ?*const fn (*anyopaque, [*]const u8, usize, *i64) callconv(.c) isize;

    extern fn c_chardev_register(*@This(), [*:0]const u8, ReadHandler, WriteHandler) c_int;
    pub fn register(this: *@This(), file_name: [:0]const u8, read_handler: ReadHandler, write_handler: WriteHandler) void {
        _ = c_chardev_register(this, file_name.ptr, read_handler, write_handler);
    }

    extern fn c_chardev_unregister(*@This()) void;
    pub fn unregister(this: *@This()) void {
        c_chardev_unregister(this);
    }
};
