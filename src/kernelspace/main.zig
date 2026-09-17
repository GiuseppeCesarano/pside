const std = @import("std");

const communications = @import("communications");
const name = communications.name;
const kernel = @import("kernel");

const Engine = @import("causal/Engine.zig");
const VmaRanges = @import("process/VmaRanges.zig");

comptime {
    _ = @import("soft_float.zig");
}

export const description linksection(".modinfo") = "description=Pside causal profiler's kernel module".*;
export const license linksection(".modinfo") = "license=GPL".*;

pub const std_options: std.Options = .{
    .logFn = kernel.logWithName(name),
    .page_size_min = 4096,
};

var ctl: kernel.CharDevice = undefined;

export fn init_module() linksection(".init.text") c_int {
    kernel.Task.resolveAddWork() catch return 1;
    kernel.tracepoint.init();

    ctl.create(name, ioctlHandler) catch return 1;
    std.log.debug("chardev created at: " ++ communications.control_device_path, .{});

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    ctl.remove();
}

export fn pside_engine_release(ptr: *anyopaque) void {
    const engine: *Engine = @ptrCast(@alignCast(ptr));
    engine.deinit();
    kernel.heap.allocator.destroy(engine);
}

fn ioctlHandler(filp_ptr: *anyopaque, command: c_uint, arg: c_ulong) callconv(.c) c_long {
    const filp: *kernel.File = @ptrCast(filp_ptr);

    const in: *const communications.Data = @ptrFromInt(arg);
    var data: communications.Data = undefined;
    const copied = kernel.mem.copyBytesFromUser(std.mem.asBytes(&data), std.mem.asBytes(in));
    if (copied.len != @sizeOf(communications.Data)) return code(.FAULT);

    filp.lock();
    defer filp.unlock();

    switch (@as(communications.Commands, @fromBackingInt(@intCast(command)))) {
        .attach_profiler => {
            if (filp.getEngine() != null) return code(.BUSY);

            const engine = kernel.heap.allocator.create(Engine) catch return code(.NOMEM);
            engine.* = Engine.init(filp.progressPage()) catch {
                kernel.heap.allocator.destroy(engine);
                return code(.NOMEM);
            };
            filp.setEngine(engine);

            const len = data.attach.vma_name_len;
            data.attach.vma_name[len] = 0;
            const raw = data.attach.vma_name[0..len :0];

            engine.attach(data.attach.pid, raw, data.attach.attribute_kernel_samples) catch |err| {
                releaseEngine(filp, engine);

                return switch (err) {
                    VmaRanges.SnapshotError.NoMatchingVma => code(.NOENT),
                    else => code(.IO),
                };
            };
        },

        .start_profiler => {
            const engine: *Engine = @ptrCast(@alignCast(filp.getEngine() orelse return code(.NXIO)));
            if (engine.isProfiling()) return code(.BUSY);

            engine.start(data.start.output_fd) catch {
                releaseEngine(filp, engine);
                return code(.IO);
            };
        },

        .stop_profiler => if (filp.getEngine()) |ptr| releaseEngine(filp, @ptrCast(@alignCast(ptr))),

        else => return code(.INVAL),
    }

    return code(.SUCCESS);
}

fn releaseEngine(filp: *kernel.File, engine: *Engine) void {
    engine.deinit();
    kernel.heap.allocator.destroy(engine);
    filp.setEngine(null);
}

fn code(return_code: std.os.linux.E) c_long {
    return -@as(c_long, @intCast(@backingInt(return_code)));
}
