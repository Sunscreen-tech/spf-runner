# Benchmarks

Performance benchmarks for FHE program execution via `program_runner`.

## Running

From the repository root:

```sh
# Run all benchmarks (builds dependencies first)
make bench
```

## Directory convention

Each benchmark lives in its own subdirectory with a consistent structure:

| File          | Purpose                        |
| ------------- | ------------------------------ |
| `*.c`         | FHE program source             |
| `Makefile`    | Compiles the ELF binary        |
| `bench.py`    | Benchmark script               |
| `.gitignore`  | Ignores compiled binary        |
| `README.md`   | Documents what is measured     |

## Available benchmarks

- [greater_than](greater_than/) -- compares two encrypted integers across u8/u16/u32/u64
