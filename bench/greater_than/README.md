# greater_than benchmark

Benchmarks the `greater_than` FHE program across u8, u16, u32, and u64 bit widths. Measures four components, each iterated N times:

- key generation (`KeySet.generate()`)
- encryption (parameter building and ciphertext creation)
- execution (`program_runner` invocation via stdin/stdout)
- decryption (output reading and decryption)

## Running

From the repository root:

```sh
make bench
```

Or from this directory (requires `LLVM_DIR`, a release build of `program_runner`, and the `sunscreen_fhe` Python extension):

```sh
make && uv run python bench.py
```

## Example output

Here is some example output, run on a M2 Pro Macbook Pro.

```
keygen (10 iterations)...
  keygen                   time: [1001.5 ms  1036.2 ms  1085.3 ms]

--- u8: greater_than_u8(200, 100) ---
  200 > 100 = 1 (correct)
  u8 encrypt               time: [6.9 ms  7.0 ms  7.1 ms]
  u8 execute               time: [392.0 ms  403.3 ms  420.1 ms]
  u8 decrypt               time: [1.7 ms  1.7 ms  1.8 ms]

...

========================================================================
  summary (mean ms)
========================================================================
  width      keygen     encrypt     execute     decrypt
  -----  ----------  ----------  ----------  ----------
  u8      1036.2 ms      7.0 ms    403.3 ms      1.7 ms
  u16     1036.2 ms      6.9 ms    570.3 ms      1.7 ms
  u32     1036.2 ms      6.9 ms    889.6 ms      1.7 ms
  u64     1036.2 ms      6.9 ms   1593.2 ms      1.7 ms
```

## Adding a new benchmark

Create a new subdirectory under `bench/` with the same structure:

```
bench/
  new_benchmark/
    new_benchmark.c   -- FHE source
    bench.py          -- benchmark script
    Makefile          -- compile the ELF
    .gitignore        -- ignore compiled binary
    README.md         -- what it measures
```

Then add the subdirectory to the root `Makefile` `bench` target.
