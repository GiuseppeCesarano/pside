const std = @import("std");
const http = std.http;
const net = std.Io.net;
const Io = std.Io;

const Server = @This();

server: net.Server,
should_shut_down: std.atomic.Value(bool),

pub fn init(io: Io) !Server {
    var net_server = try (try net.IpAddress.parse("::1", 0)).listen(io, .{ .reuse_address = true });
    errdefer net_server.deinit(io);

    return .{
        .server = net_server,
        .should_shut_down = undefined,
    };
}

pub fn deinit(this: *Server, io: Io) void {
    this.stop(io);
    this.server.deinit(io);
}

pub fn port(self: Server) u16 {
    return self.server.socket.address.getPort();
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
    }) catch {}; // If spawing fails, user will read msg, and open the url by hand
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
            try handleRequest(&request);
        }
    }
}

pub fn stop(this: *Server, io: Io) void {
    if (this.should_shut_down.swap(true, .monotonic)) return;

    // Force last connection to unlock the .accept() call;
    var stream = this.server.socket.address.connect(io, .{ .mode = .stream }) catch
        @panic("Server shutdown failed");
    stream.close(io);
}

fn handleRequest(request: *http.Server.Request) !void {
    const target = request.head.target;
    std.log.debug("{s} {s}", .{ @tagName(request.head.method), target });

    if (std.mem.eql(u8, target, "/")) {
        try request.respond("Hello, World!\n", .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/plain" },
            },
        });
    } else if (std.mem.eql(u8, target, "/stream")) {
        var response = try request.respondStreaming(&.{}, .{});
        try response.writer.writeAll("chunk one\n");
        try response.flush();
        try response.writer.writeAll("chunk two\n");
        try response.end();
    } else {
        try request.respond("Not Found\n", .{ .status = .not_found });
    }
}
