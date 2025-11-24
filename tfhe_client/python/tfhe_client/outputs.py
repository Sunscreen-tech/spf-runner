"""Output deserialization for FHE program results."""

from __future__ import annotations

from tfhe_client._native import Ciphertext
from tfhe_client._native import deserialize_outputs as _deserialize_outputs


def read_outputs(data: bytes) -> list[Ciphertext]:
    """Read output ciphertexts from program runner result.

    Args:
        data: MessagePack bytes from program runner output

    Returns:
        List of Ciphertext objects in order

    Raises:
        ValueError: If version is not supported or deserialization fails
    """
    return _deserialize_outputs(data)
