const std = @import("std");

const communications = @import("communications");
const kernel = @import("kernel");
const Engine = @import("Engine");

const name = communications.name;
const allocator = kernel.heap.allocator;
const atomic_allocator = kernel.heap.atomic_allocator;

export const description linksection(".modinfo") = "description=Pside causal profiler's kernel module".*;
export const license linksection(".modinfo") = "license=GPL v2".*;

var debug_io: kernel.Io.Debug = undefined;
var kernel_io: kernel.Io = undefined;
var ctl: kernel.Chardev = undefined;

export fn init_module() linksection(".init.text") c_int {
    init() catch |err| return switch (err) {
        std.mem.Allocator.Error.OutOfMemory => code(.NOMEM),
        kernel.Chardev.RegisterError.Busy => code(.BUSY),
        else => code(.IO),
    };
    return code(.SUCCESS);
}

fn init() !void {
    try debug_io.init(allocator, atomic_allocator);
    errdefer debug_io.deinit();

    try kernel.Task.resolveWorkAdd();
    kernel.tracepoint.init();

    try kernel_io.init(allocator, atomic_allocator, 8);
    errdefer kernel_io.deinit();

    try ctl.register(name, ioctlHandler);
    std.log.debug("chardev created at: " ++ communications.control_device_path, .{});
}

fn ioctlHandler(filp_ptr: *anyopaque, command: c_uint, arg: c_ulong) callconv(.c) c_long {
    const filp: *kernel.File = @ptrCast(filp_ptr);

    var data: communications.Data = undefined;
    const copied = kernel.copyFromUser(std.mem.asBytes(&data), arg);
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
                    Engine.AttachError.NoMatchingVma => code(.NOENT),
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

export fn cleanup_module() linksection(".exit.text") void {
    ctl.unregister();
    kernel_io.deinit();
    debug_io.deinit();
}

export fn pside_engine_release(ptr: *anyopaque) void {
    destroyEngine(@ptrCast(@alignCast(ptr)));
}

fn releaseEngine(filp: *kernel.File, engine: *Engine) void {
    destroyEngine(engine);
    filp.sessionSetEngine(null);
}

fn destroyEngine(engine: *Engine) void {
    engine.deinit(kernel_io.io());
    allocator.destroy(engine);
}

fn code(return_code: std.os.linux.E) c_int {
    return -@as(c_int, @intCast(@backingInt(return_code)));
}

pub const std_options: std.Options = .{
    .logFn = kernel.logWithName(name),
};

pub const std_options_debug_io = debug_io.io();

pub const panic = std.debug.FullPanic(kernel.debug.panic);

pub const debug = struct {
    pub const SelfInfo = kernel.debug.SelfInfo;
    pub const getDebugInfoAllocator = kernel.debug.getDebugInfoAllocator;
    pub const printLineFromFile = kernel.debug.printLineFromFile;
};
