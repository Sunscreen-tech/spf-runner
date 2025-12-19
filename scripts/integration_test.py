#!/usr/bin/env python3
"""Integration test: verify wheel + binary work together.

This script tests the "user experience" by:
1. Installing the sunscreen_fhe wheel (done before running this script)
2. Running the program_runner binary with encrypted inputs
3. Verifying the decrypted output matches expected result

Usage:
    python integration_test.py <program_runner_binary> <fhe_programs_elf>

Example:
    python integration_test.py ./program_runner-linux-x86_64 ./test_programs
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <program_runner_binary> <fhe_programs_elf>")
        return 1

    binary = Path(sys.argv[1])
    elf = Path(sys.argv[2])

    if not binary.exists():
        print(f"Error: binary not found: {binary}")
        return 1

    if not elf.exists():
        print(f"Error: ELF file not found: {elf}")
        return 1

    # Import sunscreen_fhe (should be installed via pip)
    try:
        from sunscreen_fhe import KeySet, ParameterBuilder, read_outputs
    except ImportError as e:
        print(f"Error: sunscreen_fhe not installed: {e}")
        return 1

    print("Generating keys...")
    keys = KeySet.generate()

    print("Building parameters: encrypt(1, 8) + encrypt(2, 8) -> output(8, 1)")
    params = (
        ParameterBuilder()
        .encrypt(1, 8, signed=False)
        .encrypt(2, 8, signed=False)
        .output(8, 1)
        .build(keys.public_key)
    )

    print(f"Running program_runner: {binary} -e {elf} -f add_u8 ...")
    with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as key_file:
        key_path = Path(key_file.name)
        key_file.write(keys.compute_key.to_bytes())

    try:
        result = subprocess.run(
            [str(binary), "-e", str(elf), "-f", "add_u8", "-k", str(key_path)],
            input=params.to_bytes(),
            capture_output=True,
            timeout=300,  # 5 minute timeout
        )
    except subprocess.TimeoutExpired:
        print("FAIL: program_runner timed out after 5 minutes")
        key_path.unlink(missing_ok=True)
        return 1
    finally:
        key_path.unlink(missing_ok=True)

    if result.returncode != 0:
        print(f"FAIL: program_runner exited with code {result.returncode}")
        print(f"stdout: {result.stdout.decode()}")
        print(f"stderr: {result.stderr.decode()}")
        return 1

    print("Reading and decrypting outputs...")
    outputs = read_outputs(result.stdout)

    if len(outputs) != 1:
        print(f"FAIL: expected 1 output, got {len(outputs)}")
        return 1

    value = keys.decrypt(outputs[0])
    expected = 3

    if value != expected:
        print(f"FAIL: expected {expected}, got {value}")
        return 1

    print(f"PASS: 1 + 2 = {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
