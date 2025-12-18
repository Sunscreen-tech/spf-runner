"""Tests for key generation and serialization."""

from conftest import assert_serialization_roundtrip
from sunscreen_fhe import ComputeKey, KeySet, PublicKey, SecretKey


class TestSecretKey:
    """Tests for SecretKey class."""

    def test_generate(self):
        """Test secret key generation produces valid bytes."""
        sk = SecretKey.generate()
        assert len(sk.to_bytes()) > 0

    def test_serialization_roundtrip(self, secret_key):
        """Test that secret keys can be serialized and deserialized."""
        assert_serialization_roundtrip(secret_key, SecretKey.from_bytes)


class TestPublicKey:
    """Tests for PublicKey class."""

    def test_from_secret_key(self, secret_key):
        """Test deriving public key from secret key produces valid bytes."""
        pk = PublicKey.from_secret_key(secret_key)
        assert len(pk.to_bytes()) > 0

    def test_serialization_roundtrip(self, public_key):
        """Test that public keys can be serialized and deserialized."""
        assert_serialization_roundtrip(public_key, PublicKey.from_bytes)


class TestComputeKey:
    """Tests for ComputeKey class."""

    def test_from_secret_key(self, secret_key):
        """Test deriving compute key from secret key produces valid bytes."""
        ck = ComputeKey.from_secret_key(secret_key)
        assert len(ck.to_bytes()) > 0

    def test_serialization_roundtrip(self, compute_key):
        """Test that compute keys can be serialized and deserialized."""
        assert_serialization_roundtrip(compute_key, ComputeKey.from_bytes)


class TestKeySet:
    """Tests for KeySet class."""

    def test_generate(self):
        """Test key set generation produces all three keys with valid bytes."""
        keys = KeySet.generate()
        assert len(keys.secret_key.to_bytes()) > 0
        assert len(keys.public_key.to_bytes()) > 0
        assert len(keys.compute_key.to_bytes()) > 0

    def test_construct_from_keys(self, secret_key, public_key, compute_key):
        """Test constructing a KeySet from individual keys."""
        keys = KeySet(secret_key, public_key, compute_key)
        assert keys.secret_key.to_bytes() == secret_key.to_bytes()
        assert keys.public_key.to_bytes() == public_key.to_bytes()
        assert keys.compute_key.to_bytes() == compute_key.to_bytes()
