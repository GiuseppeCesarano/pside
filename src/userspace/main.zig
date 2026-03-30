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
        \\pside — causal profiler
        \\
        \\  Causal profiling measures the actual impact of speeding up a code
        \\  location on overall program throughput, by virtually "optimizing"
        \\  one site at a time while the program runs.
        \\
        \\USAGE
        \\  pside <subcommand> [flags] [-- program args…]
        \\
        \\SUBCOMMANDS
        \\  record    Run the target program under the profiler and write
        \\            results to a .pside file.  
        \\
        \\  report    Parse a .pside file and open an interactive web report
        \\            in your browser.
        \\
        \\RECORD FLAGS
        \\  -c <cmd>     Path to the program to profile.
        \\  -p <addr>    Address (or symbol) of the progress point —
        \\               the event whose throughput is being maximised.
        \\  -l <name>    VMA / section name to restrict profiling to.
        \\               Defaults to the binary name without extension.
        \\  -n <count>   Number of runs to execute (default: 1).
        \\               More runs → better confidence.
        \\
        \\REPORT ARGS
        \\  <file.pside>  Output file produced by `pside record`.
        \\
        \\EXAMPLES
        \\  # Profile my_app for 20 runs, then view results
        \\  sudo pside record -c ./my_app -n 20
        \\  pside report my_app.pside
        \\
        \\  # Restrict profiling to a specific shared library section
        \\  sudo pside record -c ./my_app -l libfoo -n 10
        \\
    , .{});
}
