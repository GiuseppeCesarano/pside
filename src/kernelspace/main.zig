const std = @import("std");

const communications = @import("communications");
const kernel = @import("kernel");

const Engine = @import("causal/Engine.zig");

const name = "pside";

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
    std.log.debug("chardev created at: /dev/" ++ name, .{});

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

    switch (@as(communications.Commands, @enumFromInt(command))) {
        .start_profiler => {
            if (filp.getEngine() != null) return code(.BUSY);

            const engine = kernel.heap.allocator.create(Engine) catch return code(.NOMEM);
            engine.* = Engine.init(filp.progressPage()) catch {
                kernel.heap.allocator.destroy(engine);
                return code(.NOMEM);
            };
            filp.setEngine(engine);

            const len = data.start.vma_name_len;
            data.start.vma_name[len] = 0;
            const raw = data.start.vma_name[0..len :0];

            engine.profilePid(data.start.pid, data.start.output_fd, raw, data.start.attribute_kernel_samples) catch {
                engine.deinit();
                kernel.heap.allocator.destroy(engine);
                filp.setEngine(null);
                return code(.IO);
            };
        },

        .stop_profiler => if (filp.getEngine()) |ptr| {
            const engine: *Engine = @ptrCast(@alignCast(ptr));
            engine.deinit();
            kernel.heap.allocator.destroy(engine);
            filp.setEngine(null);
        },

        else => return code(.INVAL),
    }

    return code(.SUCCESS);
}

fn code(return_code: std.os.linux.E) c_long {
    return -@as(c_long, @intCast(@intFromEnum(return_code)));
}
