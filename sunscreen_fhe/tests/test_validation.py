"""Tests for validation and error handling."""

from typing import cast

import pytest
from conftest import BIT_WIDTH_ERROR_MSG, INVALID_BIT_WIDTHS
from sunscreen_fhe import Ciphertext, ParameterBuilder, Parameters, SecretKey


class TestInvalidBitWidth:
    """Tests for invalid bit width handling."""

    @pytest.mark.parametrize("bit_width", INVALID_BIT_WIDTHS)
    def test_keyset_encrypt_invalid_bit_width(self, keyset, bit_width):
        """Verify that invalid bit widths raise ValueError during encryption."""
        with pytest.raises(ValueError, match=BIT_WIDTH_ERROR_MSG):
            keyset.encrypt(42, bit_width=bit_width, signed=False)

    @pytest.mark.parametrize("bit_width", INVALID_BIT_WIDTHS)
    def test_ciphertext_encrypt_invalid_bit_width(self, public_key, bit_width):
        """Verify that invalid bit widths raise ValueError in low-level API."""
        with pytest.raises(ValueError, match=BIT_WIDTH_ERROR_MSG):
            Ciphertext.encrypt(42, public_key, bit_width=bit_width, signed=False)

    @pytest.mark.parametrize("bit_width", INVALID_BIT_WIDTHS)
    def test_parameter_builder_output_invalid_bit_width(self, bit_width):
        """Verify that invalid bit widths raise ValueError for output declaration."""
        with pytest.raises(ValueError, match=BIT_WIDTH_ERROR_MSG):
            ParameterBuilder().output(bit_width=bit_width, size=1)

    @pytest.mark.parametrize("bit_width", INVALID_BIT_WIDTHS)
    def test_parameter_builder_plaintext_invalid_bit_width(self, bit_width):
        """Verify that invalid bit widths raise ValueError for plaintext."""
        with pytest.raises(ValueError, match=BIT_WIDTH_ERROR_MSG):
            ParameterBuilder().plaintext(42, bit_width=bit_width, signed=False)


class TestUnsignedValueValidation:
    """Tests for unsigned value range validation."""

    @pytest.mark.parametrize(
        "value,bit_width",
        [
            (-1, 8),
            (-100, 8),
            (-1, 16),
            (-1, 32),
            (-1, 64),
        ],
    )
    def test_encrypt_negative_unsigned_fails(self, keyset, value, bit_width):
        """Verify that negative values with signed=False raise OverflowError."""
        with pytest.raises(OverflowError):
            keyset.encrypt(value, bit_width=bit_width, signed=False)

    @pytest.mark.parametrize(
        "value,bit_width",
        [
            (-1, 8),
            (-100, 16),
        ],
    )
    def test_plaintext_negative_unsigned_fails(self, value, bit_width):
        """Verify that negative plaintext values with signed=False raise ValueError."""
        with pytest.raises(ValueError, match="unsigned value cannot be negative"):
            ParameterBuilder().plaintext(value, bit_width=bit_width, signed=False)

    @pytest.mark.parametrize(
        "value,bit_width",
        [
            (256, 8),
            (65536, 16),
        ],
    )
    def test_plaintext_overflow_unsigned_fails(self, value, bit_width):
        """Verify that plaintext values exceeding bit width max raise ValueError."""
        with pytest.raises(ValueError, match="exceeds maximum"):
            ParameterBuilder().plaintext(value, bit_width=bit_width, signed=False)


class TestOutputValidation:
    """Tests for output parameter validation."""

    def test_output_zero_size_fails(self):
        """Verify that output size of 0 raises ValueError."""
        with pytest.raises(ValueError, match="size must be at least 1"):
            ParameterBuilder().output(bit_width=8, size=0)


class TestSerializationErrors:
    """Tests for serialization error handling."""

    def test_secret_key_from_corrupted_bytes(self):
        """Verify that corrupted data raises appropriate error."""
        with pytest.raises(ValueError):
            SecretKey.from_bytes(b"corrupted data that is not valid msgpack")

    def test_ciphertext_from_corrupted_bytes(self):
        """Verify that corrupted ciphertext data raises appropriate error."""
        with pytest.raises(ValueError):
            Ciphertext.from_bytes(b"not a valid ciphertext")

    def test_parameters_from_corrupted_bytes(self):
        """Verify that corrupted parameter data raises appropriate error."""
        with pytest.raises(ValueError):
            Parameters.from_bytes(b"invalid parameter data")


class TestBoundaryValues:
    """Tests for boundary values at each bit width."""

    @pytest.mark.parametrize(
        "bit_width,max_value",
        [
            (8, 255),
            (16, 65535),
            (32, 4294967295),
            (64, 2**64 - 1),
        ],
    )
    def test_max_unsigned_value(self, keyset, bit_width, max_value):
        """Test encryption of maximum unsigned value for each bit width."""
        ct = keyset.encrypt(max_value, bit_width=bit_width, signed=False)
        assert keyset.decrypt(ct, signed=False) == max_value

    @pytest.mark.parametrize(
        "bit_width,min_value",
        [
            (8, -128),
            (16, -32768),
            (32, -2147483648),
            (64, -(2**63)),
        ],
    )
    def test_min_signed_value(self, keyset, bit_width, min_value):
        """Test encryption of minimum signed value for each bit width."""
        ct = keyset.encrypt(min_value, bit_width=bit_width, signed=True)
        assert keyset.decrypt(ct, signed=True) == min_value

    @pytest.mark.parametrize(
        "bit_width,max_value",
        [
            (8, 127),
            (16, 32767),
            (32, 2147483647),
            (64, 2**63 - 1),
        ],
    )
    def test_max_signed_value(self, keyset, bit_width, max_value):
        """Test encryption of maximum signed value for each bit width."""
        ct = keyset.encrypt(max_value, bit_width=bit_width, signed=True)
        assert keyset.decrypt(ct, signed=True) == max_value

    def test_zero_all_bit_widths(self, keyset):
        """Test encryption of zero for all bit widths."""
        for bit_width in [8, 16, 32, 64]:
            ct = keyset.encrypt(0, bit_width=bit_width, signed=False)
            assert keyset.decrypt(ct, signed=False) == 0

            ct_signed = keyset.encrypt(0, bit_width=bit_width, signed=True)
            assert keyset.decrypt(ct_signed, signed=True) == 0


class TestVersioning:
    """Tests for version functions."""

    def test_peek_parameters_version_success(self, keyset):
        """Verify peek_parameters_version returns correct version."""
        from sunscreen_fhe import ParameterBuilder, get_parameters_version, peek_parameters_version

        params = ParameterBuilder().plaintext(42, 8, signed=False).build()
        data = params.to_bytes()

        version = peek_parameters_version(data)
        assert version == get_parameters_version()

    def test_get_version_constants(self):
        """Verify get_*_version functions return positive integers."""
        from sunscreen_fhe import get_output_version, get_parameters_version

        assert get_parameters_version() >= 1
        assert get_output_version() >= 1
        assert isinstance(get_parameters_version(), int)
        assert isinstance(get_output_version(), int)


def _encode_version(version: int) -> bytes:
    """Encode a version number as big-endian u32."""
    return version.to_bytes(4, byteorder="big")


class TestVersionMismatch:
    """Tests for version mismatch errors."""

    # Output tests

    def test_output_version_mismatch(self):
        """Test that invalid output version raises ValueError."""
        import msgpack
        from sunscreen_fhe import read_outputs

        # Create output bytes with unsupported version using wire format:
        # [SPFO: 4 bytes][version: 4 bytes big-endian u32][payload: msgpack]
        payload = cast(bytes, msgpack.packb([]))
        bad_bytes = b"SPFO" + _encode_version(999) + payload

        with pytest.raises(ValueError, match="unsupported version 999"):
            read_outputs(bad_bytes)

    def test_output_invalid_magic(self):
        """Test that invalid magic bytes raise ValueError."""
        import msgpack
        from sunscreen_fhe import read_outputs

        payload = cast(bytes, msgpack.packb([]))
        bad_bytes = b"BAAD" + _encode_version(1) + payload

        with pytest.raises(ValueError, match="invalid magic bytes"):
            read_outputs(bad_bytes)

    def test_output_truncated_header(self):
        """Test that truncated header raises ValueError."""
        from sunscreen_fhe import read_outputs

        # Only 3 bytes - too short for magic + version
        with pytest.raises(ValueError, match="data too short"):
            read_outputs(b"SPF")

    # Parameters tests (symmetric with output tests)

    def test_parameters_version_mismatch(self):
        """Test that invalid parameters version raises ValueError."""
        import msgpack

        # Create parameter bytes with unsupported version using wire format:
        # [SPFP: 4 bytes][version: 4 bytes big-endian u32][payload: msgpack]
        payload = cast(bytes, msgpack.packb([]))
        bad_bytes = b"SPFP" + _encode_version(999) + payload

        with pytest.raises(ValueError, match="unsupported version 999"):
            Parameters.from_bytes(bad_bytes)

    def test_parameters_invalid_magic(self):
        """Test that invalid magic bytes raise ValueError."""
        import msgpack

        payload = cast(bytes, msgpack.packb([]))
        bad_bytes = b"BAAD" + _encode_version(1) + payload

        with pytest.raises(ValueError, match="invalid magic bytes"):
            Parameters.from_bytes(bad_bytes)

    def test_parameters_truncated_header(self):
        """Test that truncated header raises ValueError."""
        # Only 3 bytes - too short for magic + version
        with pytest.raises(ValueError, match="data too short"):
            Parameters.from_bytes(b"SPF")
