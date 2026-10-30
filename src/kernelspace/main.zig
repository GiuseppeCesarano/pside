const std = @import("std");

const communications = @import("communications");
const name = communications.name;
const kernel = @import("kernel");
const allocator = kernel.heap.allocator;
const atomic_allocator = kernel.heap.atomic_allocator;
pub const std_options_debug_io = kernel.io;

const Engine = @import("causal/Engine.zig");
const VmaRanges = @import("process/VmaRanges.zig");

export const description linksection(".modinfo") = "description=Pside causal profiler's kernel module".*;
export const license linksection(".modinfo") = "license=GPL v2".*;

pub const std_options: std.Options = .{
    .logFn = kernel.logWithName(name),
    .page_size_min = 4096,
};

pub const panic = std.debug.FullPanic(kernel.debug.panic);

pub const debug = struct {
    pub const SelfInfo = kernel.debug.SelfInfo;
    pub const getDebugInfoAllocator = kernel.debug.getDebugInfoAllocator;
    pub const printLineFromFile = kernel.debug.printLineFromFile;
};

var ctl: kernel.Chardev = undefined;
var kernel_io: kernel.Io = undefined;

export fn init_module() linksection(".init.text") c_int {
    kernel.Task.resolveWorkAdd() catch return 1;
    kernel.tracepoint.init();

    kernel_io.init(allocator, atomic_allocator, 1) catch return 1;

    ctl.register(name, ioctlHandler) catch {
        kernel_io.deinit();
        return 1;
    };
    std.log.debug("chardev created at: " ++ communications.control_device_path, .{});

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    ctl.unregister();
    kernel_io.deinit();
}

export fn pside_engine_release(ptr: *anyopaque) void {
    const engine: *Engine = @ptrCast(@alignCast(ptr));
    engine.deinit(kernel_io.io());
    allocator.destroy(engine);
}

fn ioctlHandler(filp_ptr: *anyopaque, command: c_uint, arg: c_ulong) callconv(.c) c_long {
    const filp: *kernel.File = @ptrCast(filp_ptr);

    const in: *const communications.Data = @ptrFromInt(arg);
    var data: communications.Data = undefined;
    const copied = kernel.copyFromUser(std.mem.asBytes(&data), std.mem.asBytes(in));
    if (copied.len != @sizeOf(communications.Data)) return code(.FAULT);

    filp.sessionLock();
    defer filp.sessionUnlock();

    switch (@as(communications.Commands, @fromBackingInt(@intCast(command)))) {
        .attach_profiler => {
            if (filp.sessionGetEngine() != null) return code(.BUSY);

            const engine = allocator.create(Engine) catch return code(.NOMEM);
            engine.* = Engine.init(allocator, atomic_allocator, filp.sessionProgressPage()) catch {
                allocator.destroy(engine);
                return code(.NOMEM);
            };
            filp.sessionSetEngine(engine);

            const len = data.attach.vma_name_len;
            data.attach.vma_name[len] = 0;
            const raw = data.attach.vma_name[0..len :0];

            engine.attach(kernel_io.io(), data.attach.pid, raw, data.attach.attribute_kernel_samples) catch |err| {
                releaseEngine(filp, engine);

                return switch (err) {
                    VmaRanges.SnapshotError.NoMatchingVma => code(.NOENT),
                    else => code(.IO),
                };
            };
        },

        .start_profiler => {
            const engine: *Engine = @ptrCast(@alignCast(filp.sessionGetEngine() orelse return code(.NXIO)));
            if (engine.isProfiling()) return code(.BUSY);

            engine.start(kernel_io.io(), data.start.output_fd) catch {
                releaseEngine(filp, engine);
                return code(.IO);
            };
        },

        .stop_profiler => if (filp.sessionGetEngine()) |ptr| releaseEngine(filp, @ptrCast(@alignCast(ptr))),

        else => return code(.INVAL),
    }

    return code(.SUCCESS);
}

fn releaseEngine(filp: *kernel.File, engine: *Engine) void {
    engine.deinit(kernel_io.io());
    allocator.destroy(engine);
    filp.sessionSetEngine(null);
}

fn code(return_code: std.os.linux.E) c_long {
    return -@as(c_long, @intCast(@backingInt(return_code)));
}
