"""Tests for encryption and decryption operations."""

import pytest
from conftest import SIGNED_VALUES_BY_WIDTH, UNSIGNED_VALUES_BY_WIDTH
from sunscreen_fhe import Ciphertext


class TestCiphertextLowLevel:
    """Tests for low-level Ciphertext API."""

    @pytest.mark.parametrize("value,bit_width", UNSIGNED_VALUES_BY_WIDTH)
    def test_encrypt_decrypt_unsigned(self, key_pair, value, bit_width):
        """Test unsigned integer encryption/decryption roundtrip."""
        sk, pk = key_pair
        ct = Ciphertext.encrypt(value, pk, bit_width=bit_width, signed=False)
        assert ct.bit_width == bit_width
        assert ct.decrypt(sk, signed=False) == value

    @pytest.mark.parametrize("value,bit_width", SIGNED_VALUES_BY_WIDTH)
    def test_encrypt_decrypt_signed(self, key_pair, value, bit_width):
        """Test signed integer encryption/decryption roundtrip."""
        sk, pk = key_pair
        ct = Ciphertext.encrypt(value, pk, bit_width=bit_width, signed=True)
        assert ct.bit_width == bit_width
        assert ct.decrypt(sk, signed=True) == value

    def test_ciphertext_serialization(self, key_pair):
        """Test ciphertext serialization roundtrip."""
        sk, pk = key_pair
        ct = Ciphertext.encrypt(99, pk, bit_width=8, signed=False)
        data = ct.to_bytes()

        ct2 = Ciphertext.from_bytes(data)
        assert ct2.bit_width == ct.bit_width
        assert ct2.decrypt(sk, signed=False) == 99

    def test_encrypt_u64_max(self, key_pair):
        """Test encrypting u64::MAX value."""
        sk, pk = key_pair
        u64_max = 2**64 - 1
        ct = Ciphertext.encrypt(u64_max, pk, bit_width=64, signed=False)
        assert ct.decrypt(sk, signed=False) == u64_max


class TestKeySetEncryption:
    """Tests for high-level KeySet encryption API."""

    @pytest.mark.parametrize("value,bit_width", UNSIGNED_VALUES_BY_WIDTH)
    def test_encrypt_decrypt_unsigned(self, keyset, value, bit_width):
        """Test unsigned encryption/decryption via KeySet."""
        ct = keyset.encrypt(value, bit_width=bit_width, signed=False)
        assert keyset.decrypt(ct, signed=False) == value

    @pytest.mark.parametrize("value,bit_width", SIGNED_VALUES_BY_WIDTH)
    def test_encrypt_decrypt_signed(self, keyset, value, bit_width):
        """Test signed encryption/decryption via KeySet."""
        ct = keyset.encrypt(value, bit_width=bit_width, signed=True)
        assert keyset.decrypt(ct, signed=True) == value

    def test_batch_encryption(self, keyset):
        """Test encrypting multiple values."""
        values = [10, 20, 30, 40, 50]
        cts = [keyset.encrypt(v, bit_width=8, signed=False) for v in values]

        decrypted = [keyset.decrypt(ct, signed=False) for ct in cts]
        assert decrypted == values

    def test_encrypt_u64_max(self, keyset):
        """Test encrypting u64::MAX value via KeySet."""
        u64_max = 2**64 - 1
        ct = keyset.encrypt(u64_max, bit_width=64, signed=False)
        assert keyset.decrypt(ct, signed=False) == u64_max
