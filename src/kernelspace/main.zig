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
var progress: kernel.CharDevice = undefined;
var engine: ?Engine = null;

export fn init_module() linksection(".init.text") c_int {
    progress.create(name ++ "_progress", null) catch return 1;
    const progress_points_ptr: *std.atomic.Value(usize) = @ptrCast(@alignCast(progress.shared_buffer()));
    progress_points_ptr.* = .init(0);
    std.log.debug("chardev created at: /dev/" ++ name, .{});

    ctl.create(name, ioctlHandler) catch {
        progress.remove();
        return 1;
    };

    return 0;
}

export fn cleanup_module() linksection(".exit.text") void {
    if (engine) |*e| e.deinit();
    progress.remove();
    ctl.remove();
}

fn ioctlHandler(_: *anyopaque, command: c_uint, arg: c_ulong) callconv(.c) c_long {
    const in: *const communications.Data = @ptrFromInt(arg);
    var data: communications.Data = undefined;
    const copied = kernel.mem.copyBytesFromUser(std.mem.asBytes(&data), std.mem.asBytes(in));
    if (copied.len != @sizeOf(communications.Data)) return code(.FAULT);

    switch (@as(communications.Commands, @enumFromInt(command))) {
        .start_profiler => {
            if (engine != null) return code(.BUSY);

            const progress_points_ptr: *std.atomic.Value(usize) = @ptrCast(@alignCast(progress.shared_buffer()));
            engine = Engine.init(progress_points_ptr) catch return code(.NOMEM);

            const len = data.start.vma_name_len;
            data.start.vma_name[len] = 0;
            const raw = data.start.vma_name[0..len :0];

            engine.?.profilePid(data.start.pid, data.start.output_fd, raw) catch {
                engine.?.deinit();
                engine = null;
                return code(.IO);
            };
        },

        .stop_profiler => if (engine) |*e| {
            e.deinit();
            engine = null;
        },

        else => return code(.INVAL),
    }

    return code(.SUCCESS);
}

fn code(return_code: std.os.linux.E) c_long {
    return -@as(c_long, @intCast(@intFromEnum(return_code)));
}
