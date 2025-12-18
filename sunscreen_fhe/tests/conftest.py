"""Shared pytest fixtures and helper functions for sunscreen_fhe tests."""

from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Protocol

import pytest
from sunscreen_fhe import (
    Ciphertext,
    ComputeKey,
    KeySet,
    ParameterBuilder,
    Parameters,
    PublicKey,
    SecretKey,
    read_outputs,
)


class Serializable(Protocol):
    """Protocol for objects that can be serialized to bytes."""

    def to_bytes(self) -> bytes: ...


# Shared test data for parametrization across test files
# These values represent typical test cases for each bit width

VALID_BIT_WIDTHS = [8, 16, 32, 64]
INVALID_BIT_WIDTHS = [0, 1, 7, 15, 17, 33, 65, 128]
BIT_WIDTH_ERROR_MSG = "bit_width must be 8, 16, 32, or 64"

UNSIGNED_VALUES_BY_WIDTH = [
    (42, 8),
    (12345, 16),
    (1234567, 32),
    (123456789012, 64),
]

SIGNED_VALUES_BY_WIDTH = [
    (42, 8),
    (-50, 8),
    (-1000, 16),
    (-100000, 32),
    (-1234567890123, 64),
]

UNSIGNED_ARRAYS_BY_WIDTH = [
    ([1, 2, 3, 4, 5], 8),
    ([100, 200, 300], 16),
    ([1000000, 2000000], 32),
    ([10000000000, 20000000000], 64),
]

SIGNED_ARRAYS_BY_WIDTH = [
    ([-10, 0, 10], 8),
    ([-1000, 0, 1000], 16),
    ([-1000000, 0, 1000000], 32),
    ([-1000000000000, 0, 1000000000000], 64),
]


# Helper functions for DRY test patterns


def assert_serialization_roundtrip(
    obj: Serializable, from_bytes_fn: Callable[[bytes], Serializable]
) -> None:
    """Verify that an object can be serialized and deserialized correctly.

    Args:
        obj: Object with to_bytes() method
        from_bytes_fn: Function to deserialize bytes back to object
    """
    data = obj.to_bytes()
    assert isinstance(data, bytes)
    assert len(data) > 0

    obj2 = from_bytes_fn(data)
    assert obj2.to_bytes() == data


def assert_single_output(
    outputs: list, keyset: KeySet, expected: int, signed: bool = False
) -> None:
    """Assert that outputs contain exactly one value matching expected.

    Args:
        outputs: List of ciphertext outputs from read_outputs()
        keyset: KeySet for decryption
        expected: Expected decrypted value
        signed: Whether to use signed decryption
    """
    assert len(outputs) == 1, f"Expected 1 output, got {len(outputs)}"
    actual = keyset.decrypt(outputs[0], signed=signed)
    assert actual == expected, f"Expected {expected}, got {actual}"


def assert_multiple_outputs(
    outputs: list, keyset: KeySet, expected_values: list[int], signed: bool = False
) -> None:
    """Assert that outputs match expected values element-wise.

    Args:
        outputs: List of ciphertext outputs from read_outputs()
        keyset: KeySet for decryption
        expected_values: List of expected decrypted values
        signed: Whether to use signed decryption
    """
    assert len(outputs) == len(expected_values), (
        f"Expected {len(expected_values)} outputs, got {len(outputs)}"
    )
    actual = [keyset.decrypt(o, signed=signed) for o in outputs]
    assert actual == expected_values, f"Expected {expected_values}, got {actual}"


def build_binary_op_params(
    keyset: KeySet,
    a: int,
    b: int,
    output_bit_width: int,
    signed: bool,
    input_bit_width: int | None = None,
) -> Parameters:
    """Build parameters for a binary operation (two inputs, one output).

    Args:
        keyset: KeySet for encryption
        a: First input value
        b: Second input value
        output_bit_width: Bit width for output
        signed: Whether to use signed encryption
        input_bit_width: Bit width for inputs (defaults to output_bit_width)
    """
    if input_bit_width is None:
        input_bit_width = output_bit_width

    return (
        ParameterBuilder()
        .encrypt(a, input_bit_width, signed)
        .encrypt(b, input_bit_width, signed)
        .output(output_bit_width, 1)
        .build(keyset.public_key)
    )


def build_unary_op_params(
    keyset: KeySet,
    value: int,
    bit_width: int,
    signed: bool,
) -> Parameters:
    """Build parameters for a unary operation (one input, one output).

    Args:
        keyset: KeySet for encryption
        value: Input value
        bit_width: Bit width for both input and output
        signed: Whether to use signed encryption
    """
    return (
        ParameterBuilder()
        .encrypt(value, bit_width, signed)
        .output(bit_width, 1)
        .build(keyset.public_key)
    )


def encrypt_array(
    keyset: KeySet,
    values: list[int],
    bit_width: int,
    signed: bool,
) -> list[Ciphertext]:
    """Encrypt a list of values into ciphertexts.

    Args:
        keyset: KeySet for encryption
        values: List of values to encrypt
        bit_width: Bit width for all values
        signed: Whether to use signed encryption

    Returns:
        List of encrypted ciphertexts
    """
    return [keyset.encrypt(v, bit_width=bit_width, signed=signed) for v in values]


def build_mixed_op_params(
    keyset: KeySet,
    ct_value: int,
    pt_value: int,
    input_bit_width: int,
    output_bit_width: int,
    signed: bool,
) -> Parameters:
    """Build parameters for mixed ciphertext/plaintext operations.

    Args:
        keyset: KeySet for encryption
        ct_value: Ciphertext input value
        pt_value: Plaintext input value
        input_bit_width: Bit width for inputs
        output_bit_width: Bit width for output
        signed: Whether to use signed encryption
    """
    return (
        ParameterBuilder()
        .encrypt(ct_value, input_bit_width, signed)
        .plaintext(pt_value, input_bit_width, signed)
        .output(output_bit_width, 1)
        .build(keyset.public_key)
    )


def run_fhe_program(
    program_runner_bin: Path,
    elf_path: Path,
    func_name: str,
    keys: KeySet,
    params: Parameters,
) -> list[Ciphertext]:
    """Run an FHE program and return the output ciphertexts.

    Args:
        program_runner_bin: Path to the program_runner binary
        elf_path: Path to the ELF file containing the FHE program
        func_name: Name of the function to execute
        keys: KeySet containing the compute key
        params: Parameters for the program

    Returns:
        List of output ciphertexts
    """
    with tempfile.TemporaryDirectory() as job_dir:
        job_path = Path(job_dir)

        (job_path / "computation.key").write_bytes(keys.compute_key.to_bytes())

        # Run with params on stdin and output on stdout
        result = subprocess.run(
            [
                str(program_runner_bin),
                "-e",
                str(elf_path),
                "-f",
                func_name,
                "-k",
                str(job_path / "computation.key"),
            ],
            input=params.to_bytes(),
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"program_runner failed: {result.stderr.decode()}")

        # Output is versioned msgpack on stdout
        return read_outputs(result.stdout)


# Key fixtures


@pytest.fixture
def secret_key() -> SecretKey:
    """Generate a fresh SecretKey for testing."""
    return SecretKey.generate()


@pytest.fixture
def public_key(secret_key: SecretKey) -> PublicKey:
    """Generate a PublicKey from the secret_key fixture."""
    return PublicKey.from_secret_key(secret_key)


@pytest.fixture
def compute_key(secret_key: SecretKey) -> ComputeKey:
    """Generate a ComputeKey from the secret_key fixture."""
    return ComputeKey.from_secret_key(secret_key)


@pytest.fixture
def key_pair(secret_key: SecretKey, public_key: PublicKey) -> tuple[SecretKey, PublicKey]:
    """Provide a secret/public key pair for testing."""
    return secret_key, public_key


@pytest.fixture(scope="module")
def keyset() -> KeySet:
    """Generate a KeySet for testing, reused within each test module."""
    return KeySet.generate()


# File fixtures


@pytest.fixture
def temp_file() -> Iterator[Path]:
    """Provide a temporary file that gets cleaned up."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        path = Path(f.name)
    yield path
    path.unlink(missing_ok=True)


@pytest.fixture
def temp_dir() -> Iterator[Path]:
    """Provide a temporary directory that gets cleaned up."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# E2E fixtures


@pytest.fixture
def program_runner_bin() -> Path:
    """Path to the program_runner binary."""
    return Path(__file__).parent.parent.parent / "target" / "release" / "program_runner"


@pytest.fixture
def test_programs_elf() -> Path:
    """Path to the test_programs ELF file."""
    return Path(__file__).parent.parent.parent / "fhe-programs" / "compiled" / "test_programs"


@pytest.fixture
def require_binaries(program_runner_bin: Path, test_programs_elf: Path):
    """Skip test if required binaries are missing."""
    if not program_runner_bin.exists():
        pytest.skip("program_runner not built (run 'cargo build --release')")
    if not test_programs_elf.exists():
        pytest.skip(f"test_programs ELF not found at {test_programs_elf}")


@pytest.fixture
def fhe_runner(
    program_runner_bin: Path, test_programs_elf: Path
) -> Callable[[str, KeySet, Parameters], list[Ciphertext]]:
    """Factory fixture for running FHE programs with cleaner syntax.

    Usage:
        def test_something(fhe_runner, keyset):
            params = build_binary_op_params(keyset, 1, 2, 8)
            outputs = fhe_runner("add_u8", keyset, params)
    """

    def _run(
        func_name: str,
        keys: KeySet,
        params: Parameters,
    ) -> list[Ciphertext]:
        return run_fhe_program(program_runner_bin, test_programs_elf, func_name, keys, params)

    return _run
