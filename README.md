# Pside

Pside is a modern causal profiler built leveraging Linux tracepoints and advanced OS features, with a specific focus on the performance of the measurement engine.
While Pside’s measurement algorithm is not identical to [Coz](https://www.youtube.com/watch?v=jE0V-p1odPg), their talk remains the best resource for understanding the underlying principles of how such a profiler operates.

## Build

To use Pside, you will need the Zig master compiler, kernel headers, and the standard toolchain for building kernel modules. Once these requirements are satisfied, you can compile the profiler by running:

`zig build -Drelease`

**Note:** Since Pside relies on a kernel module, you must recompile the profiler if you upgrade your kernel.

## Usage

Using Pside is simple but requires binary instrumentation. Simply include [pside.h](./include/pside.h) in your program and define a throughput point using: 

`PSIDE_THROUGHPUT_POINT("custom_name")`

### Example 

We will use [toy.cpp](./examples/toy.cpp) as an example. Clone this repository, navigate to the examples folder, and run:

* `zig c++ toy.cpp -O3 -std=c++23 -o toy -g`
* `sudo ../zig-out/bin/pside record ./toy -n 10` (Adjust the path if a custom prefix was used during build)
* `../zig-out/bin/pside report toy.pside` 

The `report` command will display the results for the profiled file.

*TODO: Add picture*

The output will show a graph similar to the one above. Your initial results may be noisier; this highlights a peculiarity of causal profilers—they benefit significantly from increased sample sizes. 

To generate a cleaner profile, you can aggregate more data. If you have already performed 10 runs, you can add 50 more by running:
`sudo ../zig-out/bin/pside record ./toy -n 50`

Pside will automatically aggregate the new runs into the existing file.

**NOTE:** If you recompile your target binary, you should delete or rename the old profile file. Otherwise, Pside will aggregate the new runs with the old data, resulting in an incoherent profile. A feature to automatically detect binary changes is planned.

## Benchmarks 

Pside's architecture allows it to be much leaner than Coz on binaries with heavy thread interaction, while remaining slightly faster in other general use cases.

### CPU bound benchmark

```
❯ sudo hyperfine "../toy" "./zig-out/bin/pside record ../toy" "../coz/coz run --- ../toy" -m 5
Benchmark 1: ../toy
  Time (mean ± σ):      4.586 s ±  0.004 s    [User: 6.838 s, System: 0.018 s]
  Range (min … max):    4.582 s …  4.591 s    5 runs

Benchmark 2: ./zig-out/bin/pside record ../toy
  Time (mean ± σ):      4.778 s ±  0.011 s    [User: 6.903 s, System: 0.020 s]
  Range (min … max):    4.761 s …  4.789 s    5 runs

Benchmark 3: ../coz/coz run --- ../toy
  Time (mean ± σ):      5.236 s ±  0.014 s    [User: 6.954 s, System: 0.036 s]
  Range (min … max):    5.226 s …  5.259 s    5 runs

Summary
  ../toy ran
    1.04 ± 0.00 times faster than ./zig-out/bin/pside record ../toy
    1.14 ± 0.00 times faster than ../coz/coz run --- ../toy
```

### Thread interaction benchmark

```
❯ sudo hyperfine "../pc" "./zig-out/bin/pside record ../pc" "../coz/coz run --- ../pc" -m 5
Benchmark 1: ../pc
  Time (mean ± σ):     608.7 ms ±   6.4 ms    [User: 1658.3 ms, System: 2048.7 ms]
  Range (min … max):   601.9 ms … 618.4 ms    5 runs

Benchmark 2: ./zig-out/bin/pside record ../pc
  Time (mean ± σ):     799.7 ms ±  40.6 ms    [User: 1834.5 ms, System: 2484.8 ms]
  Range (min … max):   765.9 ms … 869.9 ms    5 runs

Benchmark 3: ../coz/coz run --- ../pc
  Time (mean ± σ):      6.253 s ±  0.909 s    [User: 6.823 s, System: 8.705 s]
  Range (min … max):    5.818 s …  7.879 s    5 runs

Summary
  ../pc ran
    1.31 ± 0.07 times faster than ./zig-out/bin/pside record ../pc
   10.27 ± 1.50 times faster than ../coz/coz run --- ../pc
```

## TODO

Pside is in alpha. Some features are missing, like:

* Latency points
* More descriptive errors
* Avoid manually writing structs in `kernel.zig` (needs translate-c support)

And more...
