const std = @import("std");

const communications = @import("communications");
const name = communications.name;
const Engine = @import("Engine");
const kernel = @import("kernel");
const allocator = kernel.heap.allocator;
const atomic_allocator = kernel.heap.atomic_allocator;
const large_allocator = kernel.heap.large_allocator;
const LineMap = @import("LineMap");

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
            const line_map = sessionLineMap(filp) orelse return code(.NODATA);

            const engine = allocator.create(Engine) catch return code(.NOMEM);
            engine.* = Engine.init(allocator, atomic_allocator, filp.sessionProgressPage()) catch {
                allocator.destroy(engine);
                return code(.NOMEM);
            };

            const len = data.attach.vma_name_len;
            data.attach.vma_name[len] = 0;
            const raw = data.attach.vma_name[0..len :0];

            engine.attach(kernel_io.io(), data.attach.pid, raw, line_map) catch |err| {
                destroyEngine(engine);

                return switch (err) {
                    Engine.AttachError.NoMatchingVma => code(.NOENT),
                    Engine.AttachError.MultiThreadedTarget => code(.OPNOTSUPP),
                    Engine.AttachError.TaskNotFound => code(.SRCH),
                    Engine.AttachError.OutOfMemory => code(.NOMEM),
                    Engine.AttachError.Failed => code(.NOLINK),
                    Engine.AttachError.InvalidConfiguration,
                    Engine.AttachError.CpuOffline,
                    Engine.AttachError.HardwareBusy,
                    Engine.AttachError.NotSupported,
                    Engine.AttachError.HardwareNotFound,
                    Engine.AttachError.InvalidAttributeSize,
                    Engine.AttachError.Unexpected,
                    => code(.IO),
                };
            };
            filp.sessionSetEngine(engine);
        },

        .load_line_map => {
            if (sessionEngine(filp) != null) return code(.BUSY);

            const line_map = allocator.create(LineMap) catch return code(.NOMEM);
            line_map.* = copyLineMap(data.line_map) catch |err| {
                allocator.destroy(line_map);
                return switch (err) {
                    CopyLineMapError.OutOfMemory => code(.NOMEM),
                    CopyLineMapError.Unreadable => code(.FAULT),
                    CopyLineMapError.Malformed => code(.BADMSG),
                };
            };

            if (takeLineMap(filp)) |old| destroyLineMap(old);
            filp.sessionSetLineMap(line_map);
        },

        .start_profiler => {
            const engine = sessionEngine(filp) orelse return code(.NXIO);
            if (engine.isProfiling()) return code(.BUSY);

            const output = kernel_io.adoptFile(data.start.output_fd) catch |err| return switch (err) {
                kernel.Io.AdoptFileError.BadFileDescriptor => code(.BADF),
                kernel.Io.AdoptFileError.ProcessFdQuotaExceeded => code(.MFILE),
            };
            engine.start(kernel_io.io(), output) catch return code(.IO);
        },

        .stop_profiler => if (takeEngine(filp)) |engine| {
            defer destroyEngine(engine);

            engine.stop(kernel_io.io()) catch |err| return switch (err) {
                Engine.StopError.OutOfMemory => code(.NOMEM),
                Engine.StopError.NoSpace => code(.NOSPC),
                Engine.StopError.WriteFailed => code(.PIPE),
                Engine.StopError.KprobeLeakFailed,
                Engine.StopError.BadConfig,
                Engine.StopError.TooLateShuttingDown,
                Engine.StopError.Unknown,
                => code(.TIME),
            };
        },

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
    const filp: *kernel.File = @ptrCast(filp_ptr);
    defer if (takeLineMap(filp)) |line_map| destroyLineMap(line_map);

    const engine = takeEngine(filp) orelse return;
    defer destroyEngine(engine);

    engine.stop(kernel_io.io()) catch |err|
        std.log.err("Profiling stopped early: {s}", .{@errorName(err)});
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
    engine.deinit();
    allocator.destroy(engine);
}

fn sessionLineMap(filp: *kernel.File) ?*LineMap {
    return @ptrCast(@alignCast(filp.sessionGetLineMap()));
}

fn takeLineMap(filp: *kernel.File) ?*LineMap {
    const line_map = sessionLineMap(filp);
    filp.sessionSetLineMap(null);
    return line_map;
}

fn destroyLineMap(line_map: *LineMap) void {
    line_map.deinit(large_allocator);
    allocator.destroy(line_map);
}

const CopyLineMapError = error{ OutOfMemory, Unreadable, Malformed };

fn copyLineMap(source: communications.LineMapSource) CopyLineMapError!LineMap {
    const bytes = std.math.mul(usize, source.len, @sizeOf(usize) + @sizeOf(LineMap.Site)) catch return CopyLineMapError.Malformed;
    if (source.len == 0 or bytes > std.math.maxInt(c_int)) return CopyLineMapError.Malformed;

    var line_map: LineMap = .empty;
    errdefer line_map.deinit(large_allocator);
    try line_map.data.setCapacity(large_allocator, source.len);
    line_map.data.len = source.len;

    const slices = line_map.data.slice();
    const starts = std.mem.sliceAsBytes(slices.items(.start));
    const sites = std.mem.sliceAsBytes(slices.items(.site));

    if (kernel.copyFromUser(starts, source.starts).len != starts.len) return CopyLineMapError.Unreadable;
    if (kernel.copyFromUser(sites, source.sites).len != sites.len) return CopyLineMapError.Unreadable;

    if (!line_map.isWellFormed()) return CopyLineMapError.Malformed;
    return line_map;
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
