const std = @import("std");
const http = std.http;
const net = std.Io.net;
const Io = std.Io;

const safety = @import("safety");

const Profile = @import("Profile.zig");

const Server = @This();

const Connections = enum { drained, serving };

server: net.Server,
should_shut_down: std.atomic.Value(bool),
share_path: []const u8,
profile: *const Profile,
connections: Io.Group,
state: safety.State(Connections),

pub fn init(allocator: std.mem.Allocator, io: Io, profile: *const Profile) !Server {
    var net_server = try (try net.IpAddress.parse("::1", 0)).listen(io, .{ .reuse_address = true });
    errdefer net_server.deinit(io);

    const share_path = try resolveSharePath(allocator, io);
    errdefer allocator.free(share_path);

    return .{
        .server = net_server,
        .should_shut_down = .init(false),
        .share_path = share_path,
        .profile = profile,
        .connections = .init,
        .state = .init(.drained),
    };
}

pub fn deinit(this: *Server, allocator: std.mem.Allocator, io: Io) void {
    this.state.assertIs(.drained);

    this.stop(io);
    this.server.deinit(io);
    allocator.free(this.share_path);

    this.* = undefined;
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
    this.state.assertIs(.drained);

    while (!this.should_shut_down.load(.monotonic)) {
        var stream = try this.server.accept(io);

        if (this.should_shut_down.load(.acquire)) {
            stream.close(io);
            break;
        }

        this.connections.concurrent(io, handleConnection, .{ this, allocator, io, stream }) catch |err| {
            std.log.err("could not spawn connection handler: {s}", .{@errorName(err)});
            stream.close(io);
            continue;
        };

        this.state.transition(.serving);
    }

    this.connections.cancel(io);
    this.state.transition(.drained);
}

pub fn stop(this: *Server, io: Io) void {
    if (this.should_shut_down.swap(true, .monotonic)) return;
    var stream = this.server.socket.address.connect(io, .{ .mode = .stream }) catch @panic("Server shutdown failed");
    stream.close(io);
}

fn handleConnection(this: *Server, allocator: std.mem.Allocator, io: Io, stream_in: net.Stream) void {
    var stream = stream_in;
    defer stream.close(io);

    const page_size = std.heap.defaultQueryPageSize();

    const recv_buffer = allocator.alloc(u8, page_size) catch |err| {
        std.log.err("connection handler: {s}", .{@errorName(err)});
        return;
    };
    defer allocator.free(recv_buffer);

    const send_buffer = allocator.alloc(u8, page_size) catch |err| {
        std.log.err("connection handler: {s}", .{@errorName(err)});
        return;
    };
    defer allocator.free(send_buffer);

    var reader = stream.reader(io, recv_buffer);
    var writer = stream.writer(io, send_buffer);
    var http_server = http.Server.init(&reader.interface, &writer.interface);

    while (http_server.reader.state == .ready) {
        var request = http_server.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing => break,
            else => |e| {
                std.log.err("receiveHead: {s}", .{@errorName(e)});
                break;
            },
        };
        this.handleRequest(allocator, io, &request) catch |err| std.log.err("handleRequest: {s}", .{@errorName(err)});
    }
}

fn handleRequest(this: *Server, allocator: std.mem.Allocator, io: Io, request: *http.Server.Request) !void {
    const target = request.head.target;
    std.log.debug("{s} {s}", .{ @tagName(request.head.method), target });

    const static = [_]struct { route: []const u8, filename: []const u8, content_type: []const u8 }{
        .{ .route = "/", .filename = "index.html", .content_type = "text/html" },
        .{ .route = "/uplot.min.js", .filename = "uplot.min.js", .content_type = "application/javascript" },
        .{ .route = "/uplot.min.css", .filename = "uplot.min.css", .content_type = "text/css" },
    };

    // Paths stay encoded: the routes are fixed ASCII and `serveFile` takes its
    // filename from the table, never from the request.
    const query_start = std.mem.findScalar(u8, target, '?');
    const path = if (query_start) |at| target[0..at] else target;
    const query = if (query_start) |at| target[at + 1 ..] else "";

    for (static) |file| {
        if (std.mem.eql(u8, path, file.route))
            return this.serveFile(allocator, io, request, file.filename, file.content_type);
    }

    if (std.mem.eql(u8, path, "/api/vmas"))
        return this.serveVmas(allocator, request);

    if (std.mem.eql(u8, path, "/api/vma")) {
        const raw = queryValue(query, "name") orelse
            return request.respond("", .{ .status = .bad_request });

        const name = try percentDecodeAlloc(allocator, raw);
        defer allocator.free(name);

        return this.serveVma(allocator, request, name);
    }

    try request.respond("", .{ .status = .not_found });
}

// Splitting before decoding is what lets a value hold an encoded `&` or `=`.
fn queryValue(query: []const u8, key: []const u8) ?[]const u8 {
    var pairs = std.mem.splitScalar(u8, query, '&');
    return while (pairs.next()) |pair| {
        const equals = std.mem.findScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..equals], key)) break pair[equals + 1 ..];
    } else null;
}

// Malformed escapes pass through as written, as std and browsers both do; a
// name that fails to decode just will not match.
fn percentDecodeAlloc(allocator: std.mem.Allocator, raw: []const u8) std.mem.Allocator.Error![]u8 {
    const buffer = try allocator.alloc(u8, raw.len);
    errdefer allocator.free(buffer);

    // std writes the result to the tail of the buffer, so pull it forward.
    const decoded = std.Uri.percentDecodeBackwards(buffer, raw);
    std.mem.copyForwards(u8, buffer, decoded);

    return allocator.realloc(buffer, decoded.len);
}

fn serveVmas(this: *const Server, allocator: std.mem.Allocator, request: *http.Server.Request) !void {
    const VmaInfo = struct {
        name: []const u8,
        graph_count: usize,
    };

    var list: std.ArrayListUnmanaged(VmaInfo) = try .initCapacity(allocator, this.profile.vmas.len);
    defer list.deinit(allocator);

    for (this.profile.vmas) |vma| list.appendAssumeCapacity(.{
        .name = vma.name,
        .graph_count = vma.graphs.len,
    });

    const body = try std.json.Stringify.valueAlloc(allocator, list.items, .{});
    defer allocator.free(body);

    try request.respond(body, .{
        .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
    });
}

fn serveVma(this: *const Server, allocator: std.mem.Allocator, request: *http.Server.Request, name: []const u8) !void {
    const vma_ptr: *const Profile.Vma = for (this.profile.vmas) |*vma| {
        if (std.mem.eql(u8, vma.name, name)) break vma;
    } else {
        try request.respond("", .{ .status = .not_found });
        return;
    };

    const body = try std.json.Stringify.valueAlloc(allocator, vma_ptr.graphs, .{});
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

    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch |err| {
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

test "a query value is found by key and left encoded" {
    try std.testing.expectEqualStrings("x", queryValue("name=x", "name").?);
    try std.testing.expectEqualStrings("x", queryValue("a=1&name=x&b=2", "name").?);
    try std.testing.expectEqualStrings("", queryValue("name=", "name").?);

    try std.testing.expectEqualStrings("a%26b", queryValue("name=a%26b", "name").?);
    try std.testing.expectEqualStrings("a%3Db", queryValue("name=a%3Db", "name").?);

    try std.testing.expectEqual(null, queryValue("", "name"));
    try std.testing.expectEqual(null, queryValue("other=1", "name"));
    try std.testing.expectEqual(null, queryValue("name", "name"));
    try std.testing.expectEqual(null, queryValue("namespace=1", "name"));
}

test "percent decoding round trips what the browser sends" {
    const allocator = std.testing.allocator;

    const cases = [_]struct { encoded: []const u8, decoded: []const u8 }{
        .{ .encoded = "libstdc%2B%2B.so.6", .decoded = "libstdc++.so.6" },
        .{ .encoded = "my%20app", .decoded = "my app" },
        .{ .encoded = "a%26b", .decoded = "a&b" },
        .{ .encoded = "%41", .decoded = "A" },
        .{ .encoded = "libc.so.6", .decoded = "libc.so.6" },
        .{ .encoded = "", .decoded = "" },
        .{ .encoded = "%zz", .decoded = "%zz" },
        .{ .encoded = "trailing%", .decoded = "trailing%" },
        .{ .encoded = "%4", .decoded = "%4" },
    };

    for (cases) |case| {
        const got = try percentDecodeAlloc(allocator, case.encoded);
        defer allocator.free(got);

        try std.testing.expectEqualStrings(case.decoded, got);
    }
}
