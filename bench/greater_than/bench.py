#!/usr/bin/env python3
"""Benchmark greater_than FHE programs across bit widths (8, 16, 32, 64).

Measures four components, each iterated N times:
  - key generation: KeySet.generate()
  - encryption: ParameterBuilder encrypt + build
  - execution: program_runner invocation (stdin/stdout)
  - decryption: read_outputs + decrypt

Run `make bench` from the repository root to build all dependencies and execute.
"""

import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from sunscreen_fhe import KeySet, ParameterBuilder, read_outputs

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
PROGRAM_RUNNER = REPO_ROOT / "target" / "release" / "program_runner"
ELF_PATH = SCRIPT_DIR / "greater_than"

N_ITERATIONS = 10

# Parasol represents bool as a single byte (0 or 1).
BOOL_BIT_WIDTH = 8

BIT_WIDTHS = [8, 16, 32, 64]

# Test values per bit width: (a, b) where a > b.
# Values are chosen in the upper half of each range to exercise full bit width.
TEST_VALUES: dict[int, tuple[int, int]] = {
    8: (200, 100),
    16: (40_000, 30_000),
    32: (3_000_000_000, 2_000_000_000),
    64: (1_000_000_000_000, 999_999_999_999),
}


class BenchmarkError(Exception):
    """Raised when a benchmark execution fails."""


@dataclass
class TimingResult:
    """Collected timing data for one benchmark component."""

    label: str
    times_s: list[float] = field(default_factory=list)

    @property
    def times_ms(self) -> list[float]:
        return [t * 1000 for t in self.times_s]

    @property
    def min_ms(self) -> float:
        return min(self.times_ms)

    @property
    def max_ms(self) -> float:
        return max(self.times_ms)

    @property
    def mean_ms(self) -> float:
        return statistics.mean(self.times_ms)

    def outliers(self) -> list[float]:
        """Return times (ms) outside 1.5 * IQR from Q1/Q3."""
        if not self.times_s:
            return []
        # Use IQR (interquartile range) for outlier detection: values outside
        # [Q1 - 1.5*IQR, Q3 + 1.5*IQR] are considered outliers.
        sorted_times = sorted(self.times_ms)
        quartiles = statistics.quantiles(sorted_times, n=4)
        q1, q3 = quartiles[0], quartiles[2]
        iqr = q3 - q1
        lower = q1 - 1.5 * iqr
        upper = q3 + 1.5 * iqr
        return [t for t in sorted_times if t < lower or t > upper]

    def report(self) -> None:
        """Print a single criterion-style line with optional outlier notice."""
        print(
            f"  {self.label:<24} time: "
            f"[{self.min_ms:.1f} ms  {self.mean_ms:.1f} ms  {self.max_ms:.1f} ms]"
        )
        outlier_list = self.outliers()
        if outlier_list:
            n = len(outlier_list)
            total = len(self.times_s)
            values = ", ".join(f"{v:.1f} ms" for v in outlier_list)
            print(
                f"  {'':24} found {n} outlier{'s' if n > 1 else ''} "
                f"among {total} measurements ({n / total:.0%}): {values}"
            )


@dataclass
class BenchmarkResult:
    """Timing results for a single bit width."""

    bit_width: int
    encrypt: TimingResult
    execute: TimingResult
    decrypt: TimingResult


def check_prerequisites() -> bool:
    """Verify that required binaries exist."""
    ok = True
    if not PROGRAM_RUNNER.exists():
        print(f"error: program_runner not found at {PROGRAM_RUNNER}", file=sys.stderr)
        print("  run: cargo build --release", file=sys.stderr)
        ok = False
    if not ELF_PATH.exists():
        print(f"error: greater_than ELF not found at {ELF_PATH}", file=sys.stderr)
        print("  run: make bench  (from repo root)", file=sys.stderr)
        ok = False
    return ok


def run_program_runner(
    func_name: str,
    key_path: Path,
    params_bytes: bytes,
) -> subprocess.CompletedProcess[bytes]:
    """Invoke program_runner, piping params via stdin and reading output from stdout."""
    cmd = [
        str(PROGRAM_RUNNER),
        "-e",
        str(ELF_PATH),
        "-f",
        func_name,
        "-k",
        str(key_path),
    ]
    return subprocess.run(cmd, input=params_bytes, capture_output=True, check=False)


def verify_correctness(
    func_name: str,
    key_path: Path,
    params_bytes: bytes,
    keys: KeySet,
    a: int,
    b: int,
) -> None:
    """Run program_runner once and verify that a > b produces the correct result.

    Raises:
        BenchmarkError: If execution fails or output is incorrect.
    """
    r = run_program_runner(func_name, key_path, params_bytes)
    if r.returncode != 0:
        raise BenchmarkError(f"correctness check failed: {r.stderr.decode()}")

    outputs = read_outputs(r.stdout)
    if len(outputs) != 1:
        raise BenchmarkError(f"expected 1 output, got {len(outputs)}")

    value = keys.decrypt(outputs[0], signed=False)
    expected = 1 if a > b else 0
    if value != expected:
        raise BenchmarkError(f"expected {expected} for {a} > {b}, got {value}")
    print(f"  {a} > {b} = {value} (correct)")


def time_keygen(n: int) -> TimingResult:
    """Time N iterations of key generation."""
    result = TimingResult(label="keygen")
    for _ in range(n):
        t0 = time.perf_counter()
        KeySet.generate()
        result.times_s.append(time.perf_counter() - t0)
    return result


def build_params(a: int, b: int, bit_width: int, public_key: bytes) -> bytes:
    """Build and serialize encrypted parameters for greater_than."""
    return (
        ParameterBuilder()
        .encrypt(a, bit_width, signed=False)
        .encrypt(b, bit_width, signed=False)
        .output(BOOL_BIT_WIDTH, 1)
        .build(public_key)
        .to_bytes()
    )


def time_encrypt(
    n: int, a: int, b: int, bit_width: int, public_key: bytes
) -> TimingResult:
    """Time N iterations of parameter encryption."""
    result = TimingResult(label=f"u{bit_width} encrypt")
    for _ in range(n):
        t0 = time.perf_counter()
        build_params(a, b, bit_width, public_key)
        result.times_s.append(time.perf_counter() - t0)
    return result


def time_execute(
    n: int, func_name: str, key_path: Path, params_bytes: bytes, bit_width: int
) -> tuple[TimingResult, list[bytes]]:
    """Time N iterations of program_runner execution.

    Returns the TimingResult and stdout bytes from each run (for decryption timing).

    Raises:
        BenchmarkError: If any iteration fails.
    """
    result = TimingResult(label=f"u{bit_width} execute")
    stdout_list: list[bytes] = []
    for i in range(n):
        t0 = time.perf_counter()
        r = run_program_runner(func_name, key_path, params_bytes)
        result.times_s.append(time.perf_counter() - t0)

        if r.returncode != 0:
            raise BenchmarkError(
                f"u{bit_width} execute iteration {i + 1} failed: {r.stderr.decode()}"
            )
        stdout_list.append(r.stdout)
    return result, stdout_list


def time_decrypt(
    n: int, stdout_list: list[bytes], keys: KeySet, bit_width: int
) -> TimingResult:
    """Time N iterations of output reading and decryption."""
    result = TimingResult(label=f"u{bit_width} decrypt")
    for i in range(n):
        stdout_data = stdout_list[i % len(stdout_list)]
        t0 = time.perf_counter()
        outputs = read_outputs(stdout_data)
        for out in outputs:
            keys.decrypt(out, signed=False)
        result.times_s.append(time.perf_counter() - t0)
    return result


def benchmark_bit_width(
    bit_width: int, keys: KeySet, key_path: Path
) -> BenchmarkResult:
    """Benchmark greater_than for a single bit width.

    Returns:
        BenchmarkResult with encrypt, execute, and decrypt timings.

    Raises:
        BenchmarkError: If correctness check or any benchmark iteration fails.
    """
    a, b = TEST_VALUES[bit_width]
    func_name = f"greater_than_u{bit_width}"

    print(f"\n--- u{bit_width}: {func_name}({a}, {b}) ---")

    # Build one set of params for correctness check and execution timing.
    params_bytes = build_params(a, b, bit_width, keys.public_key)

    # Correctness check (single run, not timed).
    verify_correctness(func_name, key_path, params_bytes, keys, a, b)

    # Encrypt timing.
    encrypt_result = time_encrypt(N_ITERATIONS, a, b, bit_width, keys.public_key)
    encrypt_result.report()

    # Execute timing.
    execute_result, stdout_list = time_execute(
        N_ITERATIONS, func_name, key_path, params_bytes, bit_width
    )
    execute_result.report()

    # Decrypt timing.
    decrypt_result = time_decrypt(N_ITERATIONS, stdout_list, keys, bit_width)
    decrypt_result.report()

    return BenchmarkResult(
        bit_width=bit_width,
        encrypt=encrypt_result,
        execute=execute_result,
        decrypt=decrypt_result,
    )


def print_summary(keygen: TimingResult, results: list[BenchmarkResult]) -> None:
    """Print a summary table with all component mean times."""
    print(f"\n{'=' * 72}")
    print("  summary (mean ms)")
    print(f"{'=' * 72}")
    hdr = f"  {'width':>5}  {'keygen':>10}  {'encrypt':>10}  {'execute':>10}  {'decrypt':>10}"
    print(hdr)
    print(
        f"  {'-----':>5}  {'----------':>10}  {'----------':>10}  {'----------':>10}  {'----------':>10}"
    )

    for r in results:
        print(
            f"  u{r.bit_width:<4}"
            f"  {keygen.mean_ms:7.1f} ms"
            f"  {r.encrypt.mean_ms:7.1f} ms"
            f"  {r.execute.mean_ms:7.1f} ms"
            f"  {r.decrypt.mean_ms:7.1f} ms"
        )


def main() -> int:
    if not check_prerequisites():
        return 1

    # Key generation timing.
    print(f"keygen ({N_ITERATIONS} iterations)...")
    keygen_result = time_keygen(N_ITERATIONS)
    keygen_result.report()

    # Generate a fresh keyset for the remaining benchmarks.
    keys = KeySet.generate()

    results: list[BenchmarkResult] = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        key_path = Path(tmp_dir) / "compute.key"
        key_path.write_bytes(keys.compute_key.to_bytes())

        try:
            for bw in BIT_WIDTHS:
                results.append(benchmark_bit_width(bw, keys, key_path))
        except BenchmarkError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    print_summary(keygen_result, results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
