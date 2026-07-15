const std = @import("std");

const cli = @import("cli");
const record = @import("record").record;
const report = @import("report").report;

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.skip();

    try cli.execute(args, printHelp, .{
        record,
        report,
    }, .{init});
}

fn printHelp(_: cli.Options, _: std.process.Init) void {
    std.log.info(
        \\pside — a causal profiler for Linux
        \\
        \\  Causal profiling measures the actual impact of speeding up a code
        \\  location on overall program throughput, by virtually "optimizing"
        \\  one site at a time while the program runs.
        \\
        \\USAGE
        \\  sudo pside record [flags] <program> [args…]
        \\       pside report <file.pside>
        \\
        \\SUBCOMMANDS
        \\  record    Run <program> under the profiler and write the results to
        \\            <program>.pside. Loading the profiler needs a kernel
        \\            module, so record must be run as root (sudo).
        \\
        \\  report    Parse a .pside file and open an interactive web report
        \\            in your browser.
        \\            With -json, write the report as JSON instead.
        \\
        \\RECORD
        \\  <program> [args…]  The program to profile, followed by any arguments
        \\                     that do not start with '-'. To pass flags to the
        \\                     program, use -c instead (see below).
        \\  -c <cmd>           The whole command line as one quoted string, e.g.
        \\                     -c "./my_app --threads 8". Use this when the
        \\                     program takes its own flags.
        \\  -p <name>          Progress point to maximise, as passed to
        \\                     PSIDE_THROUGHPUT_POINT() in the source. Defaults
        \\                     to whichever progress point is found first.
        \\  -l <name>          VMA / section name to restrict profiling to.
        \\                     Defaults to the program name without its extension.
        \\  -n <count>         Number of runs to execute (default: 1). More runs
        \\                     give a cleaner, higher-confidence profile; further
        \\                     runs against the same .pside file are aggregated.
        \\
        \\REPORT
        \\  <file.pside>       A profile produced by `pside record`.
        \\  -json              Write the report as JSON to <file>.json instead
        \\                     of starting the web server.
        \\
        \\EXAMPLES
        \\  # Profile ./my_app over 20 runs, then view the results
        \\  sudo pside record ./my_app -n 20
        \\  pside report my_app.pside
        \\
        \\  # Pass arguments (including flags) to the profiled program with -c
        \\  sudo pside record -c "./my_app --threads 8" -n 20
        \\
        \\  # Restrict profiling to a specific shared-library section
        \\  sudo pside record ./my_app -l libfoo -n 10
        \\
    , .{});
}
