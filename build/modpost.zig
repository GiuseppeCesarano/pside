const std = @import("std");
const elf = std.elf;

const module_name_len = 64 - @sizeOf(u64);

const Export = struct {
    crc: []const u8,
    module: []const u8,
    namespace: []const u8,
};

const Import = struct {
    name: []const u8,
    crc: []const u8,

    fn lessThan(_: void, a: Import, b: Import) bool {
        return std.mem.lessThan(u8, a.name, b.name);
    }
};

const UndefinedSymbol = struct {
    name: []const u8,
    weak: bool,
};

const ReadError = error{
    NotAnElfObject,
    MalformedElf,
    OutOfMemory,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 4) std.process.fatal("Usage: {s} <object> <Module.symvers> <output.mod.c>", .{args[0]});
    const object_path, const symvers_path, const output_path = args[1..4].*;

    const object = std.Io.Dir.cwd().readFileAlloc(io, object_path, allocator, .unlimited) catch |err|
        std.process.fatal("Could not read {s} ({s})", .{ object_path, @errorName(err) });
    const symvers = std.Io.Dir.cwd().readFileAlloc(io, symvers_path, allocator, .unlimited) catch |err|
        std.process.fatal("Could not read {s} ({s})", .{ symvers_path, @errorName(err) });

    const exports = try parseSymvers(allocator, symvers);
    const undefined_symbols = undefinedSymbols(allocator, object) catch |err|
        std.process.fatal("Could not read the symbol table of {s} ({s})", .{ object_path, @errorName(err) });

    var imports: std.ArrayList(Import) = .empty;
    var depends: std.StringArrayHashMapUnmanaged(void) = .empty;
    var namespaces: std.StringArrayHashMapUnmanaged(void) = .empty;
    var missing: std.ArrayList([]const u8) = .empty;

    if (exports.get("module_layout")) |layout| try imports.append(allocator, .{ .name = "module_layout", .crc = layout.crc });

    for (undefined_symbols) |symbol| {
        if (std.mem.eql(u8, symbol.name, "__this_module")) continue;

        const exported = exports.get(symbol.name) orelse {
            if (!symbol.weak) try missing.append(allocator, symbol.name);
            continue;
        };

        if (std.mem.cutPrefix(u8, exported.namespace, "module:")) |modules|
            std.process.fatal("Kernel symbol {s} is exported only to the modules {s}", .{ symbol.name, modules });

        if (exported.namespace.len != 0) try namespaces.put(allocator, exported.namespace, {});
        if (!std.mem.eql(u8, exported.module, "vmlinux")) try depends.put(allocator, std.Io.Dir.path.basename(exported.module), {});
        try imports.append(allocator, .{ .name = symbol.name, .crc = exported.crc });
    }

    if (missing.items.len != 0) {
        const scoped = struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        };

        std.mem.sortUnstable([]const u8, missing.items, {}, scoped.lessThan);
        std.process.fatal("The running kernel does not export symbols pside.ko needs: {s}", .{try std.mem.join(allocator, ", ", missing.items)});
    }

    std.mem.sortUnstable(Import, imports.items, {}, Import.lessThan);

    var output: std.Io.Writer.Allocating = .init(allocator);
    try writeModC(&output.writer, imports.items, depends.keys(), namespaces.keys());

    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = output_path, .data = output.written() }) catch |err|
        std.process.fatal("Could not write {s} ({s})", .{ output_path, @errorName(err) });
}

fn parseSymvers(allocator: std.mem.Allocator, symvers: []const u8) std.mem.Allocator.Error!std.StringHashMapUnmanaged(Export) {
    var exports: std.StringHashMapUnmanaged(Export) = .empty;

    var lines = std.mem.tokenizeScalar(u8, symvers, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, '\t');
        const crc = fields.next() orelse continue;
        const name = fields.next() orelse continue;
        const module = fields.next() orelse continue;
        _ = fields.next();
        const namespace = fields.next() orelse "";

        try exports.put(allocator, name, .{ .crc = crc, .module = module, .namespace = namespace });
    }

    return exports;
}

fn undefinedSymbols(allocator: std.mem.Allocator, object: []const u8) ReadError![]const UndefinedSymbol {
    const header = blk: {
        var reader: std.Io.Reader = .fixed(object);
        break :blk elf.Header.read(&reader) catch return ReadError.NotAnElfObject;
    };
    if (!header.is_64) return ReadError.NotAnElfObject;

    var symbols: std.ArrayList(UndefinedSymbol) = .empty;

    var section_header_iterator = header.iterateSectionHeadersBuffer(object);
    while (section_header_iterator.next() catch return ReadError.MalformedElf) |section| {
        if (section.sh_type != @backingInt(elf.SHT.SYMTAB)) continue;

        const string_table = sectionData(object, try sectionAt(header, object, section.sh_link)) orelse return ReadError.MalformedElf;
        const symbol_table = sectionData(object, section) orelse return ReadError.MalformedElf;
        if (symbol_table.len == 0 or symbol_table.len % @sizeOf(elf.Elf64.Sym) != 0) return ReadError.MalformedElf;

        for (std.mem.bytesAsSlice(elf.Elf64.Sym, symbol_table)[1..]) |symbol| {
            if (symbol.shndx != elf.SHN_UNDEF) continue;

            const weak = switch (symbol.info.bind) {
                .GLOBAL => false,
                .WEAK => true,
                else => continue,
            };

            if (symbol.name >= string_table.len) return ReadError.MalformedElf;
            const name = std.mem.sliceTo(string_table[symbol.name..], 0);
            if (name.len == 0) continue;

            try symbols.append(allocator, .{ .name = name, .weak = weak });
        }
    }

    return symbols.items;
}

fn sectionAt(header: elf.Header, object: []const u8, index: usize) ReadError!elf.Elf64_Shdr {
    var section_header_iterator = header.iterateSectionHeadersBuffer(object);
    var i: usize = 0;
    return while (section_header_iterator.next() catch return ReadError.MalformedElf) |section| : (i += 1) {
        if (i == index) break section;
    } else ReadError.MalformedElf;
}

fn sectionData(object: []const u8, section: elf.Elf64_Shdr) ?[]const u8 {
    const start = std.math.cast(usize, section.sh_offset) orelse return null;
    const size = std.math.cast(usize, section.sh_size) orelse return null;
    const end = std.math.add(usize, start, size) catch return null;

    return if (end <= object.len) object[start..end] else null;
}

fn writeModC(w: *std.Io.Writer, imports: []const Import, depends: []const []const u8, namespaces: []const []const u8) std.Io.Writer.Error!void {
    try w.writeAll(
        \\#include "kconfig_overrides.h"
        \\#include <linux/module.h>
        \\#define INCLUDE_VERMAGIC
        \\#include <linux/build-salt.h>
        \\#if __has_include(<linux/elfnote-lto.h>)
        \\#include <linux/elfnote-lto.h>
        \\#endif
        \\#include <linux/vermagic.h>
        \\#if defined(CONFIG_UNWINDER_ORC) && __has_include(<asm/orc_header.h>)
        \\#include <asm/orc_header.h>
        \\ORC_HEADER;
        \\#endif
        \\
        \\BUILD_SALT;
        \\#ifdef BUILD_LTO_INFO
        \\BUILD_LTO_INFO;
        \\#endif
        \\
        \\MODULE_INFO(vermagic, VERMAGIC_STRING);
        \\MODULE_INFO(name, KBUILD_MODNAME);
        \\#if defined(CONFIG_MITIGATION_RETPOLINE) || defined(CONFIG_RETPOLINE)
        \\MODULE_INFO(retpoline, "Y");
        \\#endif
        \\
        \\__visible struct module __this_module __section(".gnu.linkonce.this_module") = {
        \\    .name = KBUILD_MODNAME,
        \\    .init = init_module,
        \\#ifdef CONFIG_MODULE_UNLOAD
        \\    .exit = cleanup_module,
        \\#endif
        \\    .arch = MODULE_ARCH_INIT,
        \\};
        \\
        \\#ifdef CONFIG_MODVERSIONS
        \\#if defined(CONFIG_BASIC_MODVERSIONS) || !defined(CONFIG_EXTENDED_MODVERSIONS)
        \\static const struct modversion_info ____versions[] __used __section("__versions") = {
        \\
    );
    for (imports) |import| {
        if (import.name.len < module_name_len) {
            try w.print("    {{ {s}, \"{s}\" }},\n", .{ import.crc, import.name });
        } else {
            try w.print(
                \\#ifndef CONFIG_EXTENDED_MODVERSIONS
                \\#error "kernel symbol {s} is too long for symbol versions without CONFIG_EXTENDED_MODVERSIONS"
                \\#endif
                \\
            , .{import.name});
        }
    }
    try w.writeAll(
        \\};
        \\#endif
        \\#ifdef CONFIG_EXTENDED_MODVERSIONS
        \\static const u32 ____version_ext_crcs[] __used __section("__version_ext_crcs") = {
        \\
    );
    for (imports) |import| try w.print("    {s},\n", .{import.crc});
    try w.writeAll(
        \\};
        \\static const char ____version_ext_names[] __used __section("__version_ext_names") =
        \\
    );
    for (imports) |import| try w.print("    \"{s}\\0\"\n", .{import.name});
    if (imports.len == 0) try w.writeAll("    \"\"\n");
    try w.writeAll(
        \\    ;
        \\#endif
        \\#endif
        \\
        \\
    );

    try w.writeAll("MODULE_INFO(depends, \"");
    for (depends, 0..) |module, i| try w.print("{s}{s}", .{ if (i == 0) "" else ",", module });
    try w.writeAll("\");\n");
    for (namespaces) |namespace| try w.print("MODULE_INFO(import_ns, \"{s}\");\n", .{namespace});
}
