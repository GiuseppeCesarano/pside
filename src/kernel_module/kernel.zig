const std = @import("std");

const KAllocator = struct {
    extern fn __kmalloc_noprof(c_ulong, c_int) ?*anyopaque;
    extern fn kfree(*anyopaque) void;

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
        const unaligned_address = @intFromPtr(__kmalloc_noprof(@intCast(len + alignment_bytes), 0xC1) orelse return null);
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

        kfree(@ptrCast(buf_ptr - skipped_bytes));
    }
};

pub const allocator: std.mem.Allocator = .{
    .ptr = undefined,
    .vtable = &KAllocator.vtable,
};
