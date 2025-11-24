"""End-to-end tests with program_runner binary."""

import pytest
from conftest import (
    assert_multiple_outputs,
    assert_single_output,
    build_binary_op_params,
    build_mixed_op_params,
    encrypt_array,
)
from tfhe_client import KeySet, ParameterBuilder


@pytest.mark.usefixtures("require_binaries")
class TestArithmetic:
    """Tests for basic arithmetic operations."""

    def test_add_u8_zero(self, fhe_runner, keyset):
        """Test u8 addition with zero: 0 + 0 = 0."""
        params = build_binary_op_params(keyset, 0, 0, output_bit_width=8, signed=False)
        outputs = fhe_runner("add_u8", keyset, params)
        assert_single_output(outputs, keyset, 0, signed=False)


@pytest.mark.usefixtures("require_binaries")
class TestSignedArithmetic:
    """Tests for signed integer operations."""

    def test_add_i8_positive(self, fhe_runner, keyset):
        """Test i8 addition with positive values: 50 + 30 = 80."""
        params = build_binary_op_params(keyset, 50, 30, output_bit_width=8, signed=True)
        outputs = fhe_runner("add_i8", keyset, params)
        assert_single_output(outputs, keyset, 80, signed=True)

    def test_add_i8_mixed(self, fhe_runner, keyset):
        """Test i8 addition with mixed signs: 100 + (-30) = 70."""
        params = build_binary_op_params(keyset, 100, -30, output_bit_width=8, signed=True)
        outputs = fhe_runner("add_i8", keyset, params)
        assert_single_output(outputs, keyset, 70, signed=True)


@pytest.mark.usefixtures("require_binaries")
class TestArrayOperations:
    """Tests for array operations."""

    def test_sum_array_u8(self, fhe_runner, keyset):
        """Test summing a 4-element array: [10, 20, 30, 40] = 100."""
        ciphertexts = encrypt_array(keyset, [10, 20, 30, 40], bit_width=8, signed=False)
        params = ParameterBuilder().ciphertext(ciphertexts).output(16, 1).build()

        outputs = fhe_runner("sum_array_u8", keyset, params)
        assert_single_output(outputs, keyset, 100, signed=False)

    def test_add_arrays_u8(self, fhe_runner, keyset):
        """Test element-wise array addition: [1,2,3,4] + [10,20,30,40] = [11,22,33,44]."""
        a = encrypt_array(keyset, [1, 2, 3, 4], bit_width=8, signed=False)
        b = encrypt_array(keyset, [10, 20, 30, 40], bit_width=8, signed=False)
        params = ParameterBuilder().ciphertext(a).ciphertext(b).output(8, 4).build()

        outputs = fhe_runner("add_arrays_u8", keyset, params)
        assert_multiple_outputs(outputs, keyset, [11, 22, 33, 44], signed=False)


@pytest.mark.usefixtures("require_binaries")
class TestMixedPlaintextCiphertext:
    """Tests for operations mixing plaintext and ciphertext."""

    def test_scale_u8(self, fhe_runner, keyset):
        """Test scaling ciphertext by plaintext: 25 * 10 = 250."""
        params = build_mixed_op_params(
            keyset, 25, 10, input_bit_width=8, output_bit_width=16, signed=False
        )
        outputs = fhe_runner("scale_u8", keyset, params)
        assert_single_output(outputs, keyset, 250, signed=False)


@pytest.mark.usefixtures("require_binaries")
class TestKeySerializationWithProgramRunner:
    """Tests verifying key serialization works with program_runner."""

    def test_serialized_keys_work_with_program_runner(self, fhe_runner, keyset, temp_dir):
        """Test that serialized/deserialized keys work correctly with program_runner."""
        key_dir = temp_dir / "keys"
        key_dir.mkdir()

        # Save keys using file I/O
        with open(key_dir / "secret.key", "wb") as f:
            f.write(keyset.secret_key.to_bytes())
        with open(key_dir / "public.key", "wb") as f:
            f.write(keyset.public_key.to_bytes())
        with open(key_dir / "compute.key", "wb") as f:
            f.write(keyset.compute_key.to_bytes())

        # Load keys back
        from tfhe_client import ComputeKey, PublicKey, SecretKey

        with open(key_dir / "secret.key", "rb") as f:
            secret_key = SecretKey.from_bytes(f.read())
        with open(key_dir / "public.key", "rb") as f:
            public_key = PublicKey.from_bytes(f.read())
        with open(key_dir / "compute.key", "rb") as f:
            compute_key = ComputeKey.from_bytes(f.read())
        loaded_keys = KeySet(secret_key, public_key, compute_key)

        # Encrypt with loaded keys
        params = build_binary_op_params(loaded_keys, 25, 75, output_bit_width=8, signed=False)
        outputs = fhe_runner("add_u8", loaded_keys, params)

        # Decrypt with original keys (should still work)
        assert_single_output(outputs, keyset, 100, signed=False)


@pytest.mark.usefixtures("require_binaries")
class TestMultiBitWidth:
    """Tests for arithmetic operations across all bit widths."""

    @pytest.mark.parametrize(
        "a,b,expected,bit_width,func_name",
        [
            (100, 50, 150, 8, "add_u8"),
            (1000, 2000, 3000, 16, "add_u16"),
            (100000, 200000, 300000, 32, "add_u32"),
            (10_000_000_000, 5_000_000_000, 15_000_000_000, 64, "add_u64"),
        ],
        ids=["u8", "u16", "u32", "u64"],
    )
    def test_add_unsigned(self, fhe_runner, keyset, a, b, expected, bit_width, func_name):
        """Test unsigned addition across bit widths."""
        params = build_binary_op_params(keyset, a, b, output_bit_width=bit_width, signed=False)
        outputs = fhe_runner(func_name, keyset, params)
        assert_single_output(outputs, keyset, expected, signed=False)

    @pytest.mark.parametrize(
        "a,b,expected,bit_width,func_name",
        [
            (-20, -30, -50, 8, "add_i8"),
            (-1000, -500, -1500, 16, "add_i16"),
            (-100000, -50000, -150000, 32, "add_i32"),
            (-10_000_000_000, -5_000_000_000, -15_000_000_000, 64, "add_i64"),
        ],
        ids=["i8", "i16", "i32", "i64"],
    )
    def test_add_signed(self, fhe_runner, keyset, a, b, expected, bit_width, func_name):
        """Test signed addition across bit widths."""
        params = build_binary_op_params(keyset, a, b, output_bit_width=bit_width, signed=True)
        outputs = fhe_runner(func_name, keyset, params)
        assert_single_output(outputs, keyset, expected, signed=True)


@pytest.mark.usefixtures("require_binaries")
class TestProgramChaining:
    """Tests for chaining FHE program outputs into subsequent programs."""

    def test_chain_add_u8_twice(self, fhe_runner, keyset):
        """Test chaining: (100 + 50) + 25 = 175.

        Run add_u8 twice, feeding the output of the first run into the second.
        This verifies that ciphertext outputs can be used as inputs to subsequent programs.
        """
        # First run: 100 + 50 = 150
        params1 = build_binary_op_params(keyset, 100, 50, output_bit_width=8, signed=False)
        outputs1 = fhe_runner("add_u8", keyset, params1)
        assert len(outputs1) == 1

        # Chain the output into a second run: 150 + 25 = 175
        params2 = (
            ParameterBuilder()
            .ciphertext(outputs1[0])  # use output from first run
            .encrypt(25, 8, signed=False)
            .output(8, 1)
            .build(keyset.public_key)
        )
        outputs2 = fhe_runner("add_u8", keyset, params2)

        assert_single_output(outputs2, keyset, 175, signed=False)

    def test_chain_with_array_output(self, fhe_runner, keyset):
        """Test chaining array outputs: add arrays, then sum result.

        First: [1,2,3,4] + [10,20,30,40] = [11,22,33,44]
        Then: sum([11,22,33,44]) = 110
        """
        # First run: element-wise add
        a = encrypt_array(keyset, [1, 2, 3, 4], bit_width=8, signed=False)
        b = encrypt_array(keyset, [10, 20, 30, 40], bit_width=8, signed=False)
        params1 = ParameterBuilder().ciphertext(a).ciphertext(b).output(8, 4).build()
        outputs1 = fhe_runner("add_arrays_u8", keyset, params1)
        assert len(outputs1) == 4

        # Chain the array output into sum_array
        params2 = ParameterBuilder().ciphertext(outputs1).output(16, 1).build()
        outputs2 = fhe_runner("sum_array_u8", keyset, params2)

        assert_single_output(outputs2, keyset, 110, signed=False)
