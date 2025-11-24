"""Tests for ParameterBuilder and Parameters."""

import pytest
from conftest import SIGNED_ARRAYS_BY_WIDTH, UNSIGNED_ARRAYS_BY_WIDTH
from tfhe_client import (
    CiphertextArrayParam,
    CiphertextParam,
    OutputParam,
    ParameterBuilder,
    Parameters,
    PlaintextArrayParam,
    PlaintextParam,
)


class TestParameterBuilder:
    """Tests for ParameterBuilder class."""

    def test_empty_builder(self):
        """Test creating an empty parameter builder."""
        builder = ParameterBuilder()
        assert len(builder) == 0

    def test_add_ciphertext(self, keyset):
        """Test adding a single ciphertext."""
        ct = keyset.encrypt(42, bit_width=8, signed=False)
        builder = ParameterBuilder().ciphertext(ct)
        assert len(builder) == 1

    def test_add_ciphertext_array(self, keyset):
        """Test adding an array of ciphertexts."""
        cts = [keyset.encrypt(i, bit_width=8, signed=False) for i in range(5)]
        builder = ParameterBuilder().ciphertext(cts)
        assert len(builder) == 1

    def test_ciphertext_array_validates_bit_width(self, keyset):
        """Test that ciphertext arrays must have same bit_width."""
        ct8 = keyset.encrypt(1, bit_width=8, signed=False)
        ct16 = keyset.encrypt(2, bit_width=16, signed=False)

        with pytest.raises(ValueError, match="same bit_width"):
            ParameterBuilder().ciphertext([ct8, ct16])

    def test_add_output(self):
        """Test declaring an output buffer."""
        builder = ParameterBuilder().output(16, 4)
        assert len(builder) == 1

    def test_output_invalid_bit_width(self):
        """Test output rejects invalid bit widths."""
        with pytest.raises(ValueError, match="bit_width must be"):
            ParameterBuilder().output(7, 1)

    def test_output_invalid_size(self):
        """Test output rejects zero size."""
        with pytest.raises(ValueError, match="size must be at least 1"):
            ParameterBuilder().output(8, 0)

    @pytest.mark.parametrize(
        "value,bit_width",
        [
            (255, 8),
            (65535, 16),
            (4000000000, 32),
            (10000000000000, 64),
        ],
    )
    def test_add_plaintext_unsigned(self, value, bit_width):
        """Test adding unsigned plaintext values."""
        builder = ParameterBuilder().plaintext(value, bit_width, signed=False)
        assert len(builder) == 1

    @pytest.mark.parametrize(
        "value,bit_width",
        [
            (-128, 8),
            (-32768, 16),
            (-2000000000, 32),
            (-9000000000000000000, 64),
        ],
    )
    def test_add_plaintext_signed(self, value, bit_width):
        """Test adding signed plaintext values."""
        builder = ParameterBuilder().plaintext(value, bit_width, signed=True)
        assert len(builder) == 1

    @pytest.mark.parametrize("values,bit_width", UNSIGNED_ARRAYS_BY_WIDTH)
    def test_add_plaintext_array_unsigned(self, values, bit_width):
        """Test adding unsigned plaintext arrays."""
        builder = ParameterBuilder().plaintext(values, bit_width, signed=False)
        assert len(builder) == 1

    @pytest.mark.parametrize("values,bit_width", SIGNED_ARRAYS_BY_WIDTH)
    def test_add_plaintext_array_signed(self, values, bit_width):
        """Test adding signed plaintext arrays."""
        builder = ParameterBuilder().plaintext(values, bit_width, signed=True)
        assert len(builder) == 1

    def test_encrypt_single_value(self, public_key):
        """Test encrypting a single value at build time."""
        params = ParameterBuilder().encrypt(42, 8, signed=False).output(8, 1).build(public_key)

        assert len(params) == 2
        assert isinstance(params[0], CiphertextParam)
        assert params[0].bit_width == 8

    def test_encrypt_array(self, public_key):
        """Test encrypting an array at build time."""
        params = (
            ParameterBuilder()
            .encrypt([1, 2, 3, 4], 8, signed=False)
            .output(16, 1)
            .build(public_key)
        )

        assert len(params) == 2
        entry = params[0]
        assert isinstance(entry, CiphertextArrayParam)
        assert entry.bit_width == 8
        assert len(entry) == 4

    def test_encrypt_requires_public_key(self):
        """Test that encrypt requires public_key at build time."""
        builder = ParameterBuilder().encrypt(42, 8, signed=False).output(8, 1)

        with pytest.raises(ValueError, match="public_key is required"):
            builder.build()

    def test_build_without_encryption(self, keyset):
        """Test building without encryption does not require public_key."""
        ct = keyset.encrypt(42, bit_width=8, signed=False)
        params = ParameterBuilder().ciphertext(ct).output(8, 1).build()

        assert len(params) == 2

    def test_mixed_encrypt_and_ciphertext(self, keyset, public_key):
        """Test mixing pre-encrypted ciphertexts and encrypt()."""
        ct = keyset.encrypt(100, bit_width=8, signed=False)
        params = (
            ParameterBuilder()
            .ciphertext(ct)
            .encrypt(50, 8, signed=False)
            .output(8, 1)
            .build(public_key)
        )

        assert len(params) == 3
        assert isinstance(params[0], CiphertextParam)
        assert isinstance(params[1], CiphertextParam)

    def test_large_unsigned_value(self, public_key):
        """Test plaintext with value > i64::MAX."""
        # This value is greater than i64::MAX (9223372036854775807)
        large_value = 2**63 + 1000

        params = ParameterBuilder().plaintext(large_value, 64, signed=False).output(64, 1).build()

        assert len(params) == 2
        entry = params[0]
        assert isinstance(entry, PlaintextParam)
        assert entry.value == large_value

    def test_method_chaining(self, public_key):
        """Test that method chaining works correctly."""
        params = (
            ParameterBuilder()
            .encrypt(1, 8, signed=False)
            .encrypt(2, 8, signed=False)
            .plaintext(100, 8, signed=False)
            .output(8, 1)
            .build(public_key)
        )

        assert len(params) == 4


class TestParameters:
    """Tests for Parameters frozen dataclass."""

    def test_serialization_roundtrip(self, keyset, public_key):
        """Test parameter serialization and deserialization."""
        params = (
            ParameterBuilder()
            .ciphertext(keyset.encrypt(42, bit_width=8, signed=False))
            .plaintext(1000, 16, signed=False)
            .output(8, 1)
            .build()
        )

        data = params.to_bytes()
        params2 = Parameters.from_bytes(data)

        assert len(params2) == 3
        assert data == params2.to_bytes()

    def test_file_roundtrip(self, keyset, temp_file):
        """Test writing and reading parameters to/from file."""
        params = (
            ParameterBuilder()
            .ciphertext(keyset.encrypt(42, bit_width=8, signed=False))
            .output(8, 1)
            .build()
        )

        temp_file.write_bytes(params.to_bytes())
        params2 = Parameters.from_bytes(temp_file.read_bytes())

        assert len(params2) == 2
        assert params.to_bytes() == params2.to_bytes()

    def test_frozen(self, public_key):
        """Test that Parameters is immutable."""
        params = ParameterBuilder().plaintext(42, 8, signed=False).output(8, 1).build()

        with pytest.raises(AttributeError):
            params.entries = ()  # type: ignore[misc]

    def test_iteration(self, public_key):
        """Test iterating over parameters."""
        params = (
            ParameterBuilder()
            .plaintext(1, 8, signed=False)
            .plaintext([2, 3], 8, signed=False)
            .output(8, 1)
            .build()
        )

        entries = list(params)
        assert len(entries) == 3
        assert isinstance(entries[0], PlaintextParam)
        assert isinstance(entries[1], PlaintextArrayParam)
        assert isinstance(entries[2], OutputParam)

    def test_indexing(self, public_key):
        """Test indexing into parameters."""
        params = (
            ParameterBuilder()
            .plaintext(42, 8, signed=False)
            .plaintext([1, 2, 3], 16, signed=False)
            .output(32, 2)
            .build()
        )

        entry0 = params[0]
        assert isinstance(entry0, PlaintextParam)
        assert entry0.value == 42
        assert entry0.bit_width == 8

        entry1 = params[1]
        assert isinstance(entry1, PlaintextArrayParam)
        assert entry1.values == (1, 2, 3)
        assert entry1.bit_width == 16

        entry2 = params[2]
        assert isinstance(entry2, OutputParam)
        assert entry2.bit_width == 32
        assert entry2.size == 2

    def test_complex_parameter_set(self, keyset, public_key):
        """Test building a complex set of parameters."""
        params = (
            ParameterBuilder()
            # Pre-encrypted ciphertexts
            .ciphertext(keyset.encrypt(10, bit_width=8, signed=False))
            .ciphertext(keyset.encrypt(20, bit_width=8, signed=False))
            # Encrypted array at build time
            .encrypt([100, 200, 300], 16, signed=False)
            # Plaintext values
            .plaintext(12345, 32, signed=False)
            .plaintext([1, 2, 3, 4], 8, signed=False)
            # Outputs
            .output(8, 1)
            .output(16, 3)
            .build(public_key)
        )

        assert len(params) == 7

        # Verify serialization works
        data = params.to_bytes()
        assert len(data) > 0

        # Verify types
        assert isinstance(params[0], CiphertextParam)
        assert isinstance(params[1], CiphertextParam)
        assert isinstance(params[2], CiphertextArrayParam)
        assert isinstance(params[3], PlaintextParam)
        assert isinstance(params[4], PlaintextArrayParam)
        assert isinstance(params[5], OutputParam)
        assert isinstance(params[6], OutputParam)
