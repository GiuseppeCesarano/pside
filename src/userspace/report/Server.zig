const std = @import("std");
const http = std.http;
const net = std.Io.net;
const Io = std.Io;

const OutputFileParserResult = @import("OutputFileParserResult");

const DebugInfo = @import("DebugInfo.zig");
const Statistics = @import("Statistics.zig");

const Server = @This();

pub const Point = struct {
    speedup: f64,
    median: f64,
    ci_low: f64,
    ci_high: f64,
    singleton: bool,
};

pub const IpSeries = struct {
    location: DebugInfo.Location,
    points: []Point,

    pub fn deinit(this: IpSeries, allocator: std.mem.Allocator) void {
        this.location.deinit(allocator);
        allocator.free(this.points);
    }
};

server: net.Server,
should_shut_down: std.atomic.Value(bool),
share_path: []const u8,
results: *const OutputFileParserResult,
prng: std.Random.DefaultPrng,
debug_info: DebugInfo,

pub fn init(allocator: std.mem.Allocator, io: Io, results: *const OutputFileParserResult) !Server {
    var net_server = try (try net.IpAddress.parse("::1", 0)).listen(io, .{ .reuse_address = true });
    errdefer net_server.deinit(io);

    const share_path = try resolveSharePath(allocator, io);
    errdefer allocator.free(share_path);

    var seed: u64 = undefined;
    std.Io.random(io, std.mem.asBytes(&seed));

    return .{
        .server = net_server,
        .should_shut_down = undefined,
        .share_path = share_path,
        .results = results,
        .prng = std.Random.DefaultPrng.init(seed),
        .debug_info = try DebugInfo.load(allocator, io, results.binary_path),
    };
}

pub fn deinit(this: *Server, allocator: std.mem.Allocator, io: Io) void {
    this.stop(io);
    this.server.deinit(io);
    allocator.free(this.share_path);
}

pub fn port(this: Server) u16 {
    return this.server.socket.address.getPort();
}

pub fn openInBrowser(this: *const Server, io: Io) void {
    const partial_url = "http://[::1]:";
    const max_port: u16 = std.math.maxInt(u16);
    var buf: [partial_url.len + std.math.log10_int(max_port) + 1]u8 = undefined;

    const full_url = std.fmt.bufPrint(&buf, partial_url ++ "{}", .{this.port()}) catch unreachable;

    _ = std.process.spawn(io, .{
        .argv = &.{ "xdg-open", full_url },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch {};
}

pub fn run(this: *Server, allocator: std.mem.Allocator, io: Io) !void {
    const page_size = std.heap.defaultQueryPageSize();

    this.should_shut_down.store(false, .monotonic);
    while (!this.should_shut_down.load(.monotonic)) {
        const recv_buffer = try allocator.alloc(u8, page_size);
        defer allocator.free(recv_buffer);

        const send_buffer = try allocator.alloc(u8, page_size);
        defer allocator.free(send_buffer);

        var stream = try this.server.accept(io);
        defer stream.close(io);

        if (this.should_shut_down.load(.acquire)) break;

        var reader = stream.reader(io, recv_buffer);
        var writer = stream.writer(io, send_buffer);
        var http_server = http.Server.init(&reader.interface, &writer.interface);

        while (http_server.reader.state == .ready) {
            var request = http_server.receiveHead() catch |err| switch (err) {
                error.HttpConnectionClosing => break,
                else => |e| return e,
            };
            this.handleRequest(allocator, io, &request) catch |err| {
                std.log.err("handleRequest: {s}", .{@errorName(err)});
            };
        }
    }
}

pub fn stop(this: *Server, io: Io) void {
    if (this.should_shut_down.swap(true, .monotonic)) return;
    var stream = this.server.socket.address.connect(io, .{ .mode = .stream }) catch
        @panic("Server shutdown failed");
    stream.close(io);
}

fn handleRequest(this: *Server, allocator: std.mem.Allocator, io: Io, request: *http.Server.Request) !void {
    const target = request.head.target;
    std.log.debug("{s} {s}", .{ @tagName(request.head.method), target });

    if (std.mem.eql(u8, target, "/")) {
        try this.serveFile(allocator, io, request, "index.html", "text/html");
    } else if (std.mem.eql(u8, target, "/uplot.min.js")) {
        try this.serveFile(allocator, io, request, "uplot.min.js", "application/javascript");
    } else if (std.mem.eql(u8, target, "/uplot.min.css")) {
        try this.serveFile(allocator, io, request, "uplot.min.css", "text/css");
    } else if (std.mem.eql(u8, target, "/api/sections")) {
        try this.serveSections(allocator, request);
    } else if (std.mem.startsWith(u8, target, "/api/section?vma=")) {
        try this.serveSection(allocator, request, target["/api/section?vma=".len..]);
    } else {
        try request.respond("", .{ .status = .not_found });
    }
}

fn serveSections(this: *const Server, allocator: std.mem.Allocator, request: *http.Server.Request) !void {
    const SectionInfo = struct {
        vma: []const u8,
        ip_count: usize,
        sample_count: usize,
        binary_path: []const u8,
    };

    var list: std.ArrayListUnmanaged(SectionInfo) = .empty;
    defer list.deinit(allocator);

    var it = this.results.throughput_map.iterator();
    while (it.next()) |entry| {
        var sample_count: usize = 0;
        var ip_it = entry.value_ptr.iterator();
        while (ip_it.next()) |ip_entry| sample_count += ip_entry.value_ptr.items.len;
        try list.append(allocator, .{
            .vma = entry.key_ptr.*,
            .ip_count = entry.value_ptr.count(),
            .sample_count = sample_count,
            .binary_path = this.results.binary_path,
        });
    }

    const body = try std.json.Stringify.valueAlloc(allocator, list.items, .{});
    defer allocator.free(body);

    try request.respond(body, .{
        .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
    });
}

fn serveSection(this: *Server, allocator: std.mem.Allocator, request: *http.Server.Request, vma: []const u8) !void {
    const ip_map = this.results.throughput_map.getPtr(vma) orelse {
        try request.respond("", .{ .status = .not_found });
        return;
    };

    const series = try Statistics.computeSection(allocator, ip_map, this.prng.random(), &this.debug_info);
    defer {
        for (series) |s| s.deinit(allocator);
        allocator.free(series);
    }

    const body = try std.json.Stringify.valueAlloc(allocator, .{ .series = series }, .{});
    defer allocator.free(body);

    try request.respond(body, .{
        .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
    });
}

fn serveFile(
    this: *const Server,
    allocator: std.mem.Allocator,
    io: Io,
    request: *http.Server.Request,
    filename: []const u8,
    content_type: []const u8,
) !void {
    const path = try std.fs.path.join(allocator, &.{ this.share_path, filename });
    defer allocator.free(path);

    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const file = std.Io.Dir.openFileAbsolute(io, path_z, .{}) catch |err| {
        std.log.err("could not open {s}: {s}", .{ path, @errorName(err) });
        try request.respond("", .{ .status = .not_found });
        return;
    };
    defer file.close(io);

    var reader = file.reader(io, &.{});

    const body = try reader.interface.allocRemaining(allocator, .unlimited);
    defer allocator.free(body);

    try request.respond(body, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = content_type },
        },
    });
}

fn resolveSharePath(allocator: std.mem.Allocator, io: Io) ![]const u8 {
    const bin_dir = try std.process.executableDirPathAlloc(io, allocator);
    defer allocator.free(bin_dir);
    const prefix = std.fs.path.dirname(bin_dir) orelse return error.empty;

    const suffix = if (std.mem.endsWith(u8, prefix, "usr/share"))
        "pside"
    else if (std.mem.endsWith(u8, prefix, "usr"))
        "share/pside"
    else
        "usr/share/pside";

    return std.fs.path.join(allocator, &.{ prefix, suffix });
}
