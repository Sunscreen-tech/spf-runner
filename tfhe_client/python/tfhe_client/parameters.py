"""Parameter types and containers for FHE program inputs."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from tfhe_client._native import (
    Ciphertext,
    PublicKey,
    WireCiphertext,
    WireCiphertextArray,
    WireOutputCiphertextArray,
    WirePlaintext,
    WirePlaintextArray,
    deserialize_parameters,
    serialize_parameters,
)


@dataclass(frozen=True)
class CiphertextParam:
    """Single encrypted value parameter."""

    bit_width: int
    _data: bytes  # serialized L1GlweCiphertextWithBitWidth

    def __str__(self) -> str:
        return f"CiphertextParam(bit_width={self.bit_width}, data_len={len(self._data)})"

    def finalize(self, public_key: PublicKey | None) -> CiphertextParam:
        """Return self (already finalized)."""
        return self


@dataclass(frozen=True)
class CiphertextArrayParam:
    """Array of encrypted values (all same bit width)."""

    bit_width: int
    _data: tuple[bytes, ...]

    def __str__(self) -> str:
        return f"CiphertextArrayParam(bit_width={self.bit_width}, count={len(self._data)})"

    def __len__(self) -> int:
        return len(self._data)

    def finalize(self, public_key: PublicKey | None) -> CiphertextArrayParam:
        """Return self (already finalized)."""
        return self


@dataclass(frozen=True)
class OutputParam:
    """Output buffer declaration."""

    bit_width: int
    size: int

    def finalize(self, public_key: PublicKey | None) -> OutputParam:
        """Return self (already finalized)."""
        return self


@dataclass(frozen=True)
class PlaintextParam:
    """Single plaintext value (server-known)."""

    bit_width: int
    value: int  # stored as unsigned

    def finalize(self, public_key: PublicKey | None) -> PlaintextParam:
        """Return self (already finalized)."""
        return self


@dataclass(frozen=True)
class PlaintextArrayParam:
    """Array of plaintext values (server-known)."""

    bit_width: int
    values: tuple[int, ...]  # stored as unsigned

    def __len__(self) -> int:
        return len(self.values)

    def finalize(self, public_key: PublicKey | None) -> PlaintextArrayParam:
        """Return self (already finalized)."""
        return self


@dataclass(frozen=True)
class PendingCiphertext:
    """Single value to be encrypted at build time."""

    value: int
    bit_width: int
    signed: bool

    def finalize(self, public_key: PublicKey | None) -> CiphertextParam:
        """Encrypt the value and return a CiphertextParam."""
        if public_key is None:
            raise ValueError("public_key is required for pending encryption")
        ct = Ciphertext.encrypt(self.value, public_key, self.bit_width, signed=self.signed)
        return CiphertextParam(bit_width=self.bit_width, _data=ct.to_bytes())


@dataclass(frozen=True)
class PendingCiphertextArray:
    """Array of values to be encrypted at build time."""

    values: tuple[int, ...]
    bit_width: int
    signed: bool

    def __len__(self) -> int:
        return len(self.values)

    def finalize(self, public_key: PublicKey | None) -> CiphertextArrayParam:
        """Encrypt all values and return a CiphertextArrayParam."""
        if public_key is None:
            raise ValueError("public_key is required for pending encryption")
        ciphertexts = [
            Ciphertext.encrypt(v, public_key, self.bit_width, signed=self.signed)
            for v in self.values
        ]
        return CiphertextArrayParam(
            bit_width=self.bit_width, _data=tuple(ct.to_bytes() for ct in ciphertexts)
        )


# Type alias for all parameter entry types (final form)
ParameterEntry = (
    CiphertextParam | CiphertextArrayParam | OutputParam | PlaintextParam | PlaintextArrayParam
)

# Type alias for builder entries (includes pending encryption types)
BuilderEntry = ParameterEntry | PendingCiphertext | PendingCiphertextArray


@dataclass(frozen=True)
class Parameters:
    """Frozen parameter set ready for the FHE program runner."""

    entries: tuple[ParameterEntry, ...]

    def to_bytes(self) -> bytes:
        """Serialize parameters to MessagePack bytes."""
        raw_entries = []
        for entry in self.entries:
            if isinstance(entry, CiphertextParam):
                raw_entries.append(WireCiphertext(entry._data))
            elif isinstance(entry, CiphertextArrayParam):
                raw_entries.append(WireCiphertextArray(entry._data))
            elif isinstance(entry, OutputParam):
                raw_entries.append(WireOutputCiphertextArray(entry.bit_width, entry.size))
            elif isinstance(entry, PlaintextParam):
                raw_entries.append(WirePlaintext(entry.value, entry.bit_width))
            elif isinstance(entry, PlaintextArrayParam):
                raw_entries.append(WirePlaintextArray(entry.values, entry.bit_width))
            else:
                raise TypeError(f"unexpected parameter entry type: {type(entry)}")
        return serialize_parameters(raw_entries)

    @classmethod
    def from_bytes(cls, data: bytes) -> Parameters:
        """Deserialize parameters from MessagePack bytes."""
        raw_entries = deserialize_parameters(data)
        entries: list[ParameterEntry] = []
        for raw in raw_entries:
            if isinstance(raw, WireCiphertext):
                entries.append(CiphertextParam(bit_width=raw.bit_width, _data=raw.data))
            elif isinstance(raw, WireCiphertextArray):
                entries.append(CiphertextArrayParam(bit_width=raw.bit_width, _data=tuple(raw.data)))
            elif isinstance(raw, WireOutputCiphertextArray):
                entries.append(OutputParam(bit_width=raw.bit_width, size=raw.size))
            elif isinstance(raw, WirePlaintext):
                entries.append(PlaintextParam(bit_width=raw.bit_width, value=raw.value))
            elif isinstance(raw, WirePlaintextArray):
                entries.append(
                    PlaintextArrayParam(bit_width=raw.bit_width, values=tuple(raw.values))
                )
            else:
                raise TypeError(f"unexpected wire parameter type: {type(raw)}")
        return cls(entries=tuple(entries))

    def __len__(self) -> int:
        return len(self.entries)

    def __getitem__(self, index: int) -> ParameterEntry:
        return self.entries[index]

    def __iter__(self) -> Iterator[ParameterEntry]:
        return iter(self.entries)
