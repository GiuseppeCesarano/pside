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

    try ctl.register(name, ioctlHandler, releaseHandler);
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
            if (sessionEngine(filp) != null) return code(.BUSY);

            const engine = allocator.create(Engine) catch return code(.NOMEM);
            engine.* = Engine.init(allocator, atomic_allocator, filp.sessionProgressPage()) catch {
                allocator.destroy(engine);
                return code(.NOMEM);
            };

            const len = data.attach.vma_name_len;
            data.attach.vma_name[len] = 0;
            const raw = data.attach.vma_name[0..len :0];

            engine.attach(kernel_io.io(), data.attach.pid, raw, data.attach.attribute_kernel_samples) catch |err| {
                destroyEngine(engine);

                return switch (err) {
                    Engine.AttachError.NoMatchingVma => code(.NOENT),
                    else => code(.IO),
                };
            };
            filp.sessionSetEngine(engine);
        },

        .start_profiler => {
            const engine = sessionEngine(filp) orelse return code(.NXIO);
            if (engine.isProfiling()) return code(.BUSY);

            engine.start(kernel_io.io(), data.start.output_fd) catch return code(.IO);
        },

        .stop_profiler => if (takeEngine(filp)) |engine| destroyEngine(engine),

        else => return code(.INVAL),
    }

    return code(.SUCCESS);
}

export fn cleanup_module() linksection(".exit.text") void {
    ctl.unregister();
    kernel_io.deinit();
    debug_io.deinit();
}

fn releaseHandler(filp_ptr: *anyopaque) callconv(.c) void {
    if (takeEngine(@ptrCast(filp_ptr))) |engine| destroyEngine(engine);
}

fn sessionEngine(filp: *kernel.File) ?*Engine {
    return @ptrCast(@alignCast(filp.sessionGetEngine()));
}

fn takeEngine(filp: *kernel.File) ?*Engine {
    const engine = sessionEngine(filp);
    filp.sessionSetEngine(null);
    return engine;
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
