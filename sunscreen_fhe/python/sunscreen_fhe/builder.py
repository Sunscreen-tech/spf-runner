"""Parameter builder for FHE program inputs."""

from __future__ import annotations

from sunscreen_fhe._native import Ciphertext, PublicKey
from sunscreen_fhe.parameters import (
    BuilderEntry,
    CiphertextArrayParam,
    CiphertextParam,
    OutputParam,
    Parameters,
    PendingCiphertext,
    PendingCiphertextArray,
    PlaintextArrayParam,
    PlaintextParam,
)
from sunscreen_fhe.validation import (
    convert_to_unsigned,
    validate_bit_width,
    validate_value_range,
)


class ParameterBuilder:
    """Builder for constructing FHE program parameters.

    Supports method chaining and deferred encryption at build time.
    """

    def __init__(self) -> None:
        self._entries: list[BuilderEntry] = []

    def ciphertext(
        self, ct: Ciphertext | list[Ciphertext] | tuple[Ciphertext, ...]
    ) -> ParameterBuilder:
        """Add pre-encrypted ciphertext parameter(s).

        For arrays, all ciphertexts must have the same bit_width.

        Args:
            ct: Single Ciphertext or list/tuple of Ciphertexts.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If array elements have different bit widths.
        """
        if isinstance(ct, (list, tuple)):
            if len(ct) == 0:
                raise ValueError("ciphertext array cannot be empty")
            # Validate all have same bit_width
            bit_width = ct[0].bit_width
            for i, c in enumerate(ct[1:], 1):
                if c.bit_width != bit_width:
                    raise ValueError(
                        f"all ciphertexts must have same bit_width, "
                        f"got {bit_width} at index 0 and {c.bit_width} at index {i}"
                    )
            self._entries.append(
                CiphertextArrayParam(bit_width=bit_width, _data=tuple(c.to_bytes() for c in ct))
            )
        else:
            self._entries.append(CiphertextParam(bit_width=ct.bit_width, _data=ct.to_bytes()))
        return self

    def encrypt(
        self,
        value: int | list[int] | tuple[int, ...],
        bit_width: int,
        signed: bool,
    ) -> ParameterBuilder:
        """Add value(s) to be encrypted at build time.

        Args:
            value: Single integer or list/tuple of integers to encrypt.
            bit_width: Bit width for encryption (8, 16, 32, or 64).
            signed: If True, use signed (two's complement) encoding.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If bit_width is invalid or values are out of range.
        """
        validate_bit_width(bit_width)

        if isinstance(value, (list, tuple)):
            if len(value) == 0:
                raise ValueError("encrypt array cannot be empty")
            for v in value:
                validate_value_range(v, bit_width, signed)
            self._entries.append(
                PendingCiphertextArray(values=tuple(value), bit_width=bit_width, signed=signed)
            )
        else:
            validate_value_range(value, bit_width, signed)
            self._entries.append(PendingCiphertext(value=value, bit_width=bit_width, signed=signed))
        return self

    def plaintext(
        self,
        value: int | list[int] | tuple[int, ...],
        bit_width: int,
        signed: bool,
    ) -> ParameterBuilder:
        """Add plaintext parameter(s).

        Plaintext values are server-known and baked into the computation.

        Args:
            value: Single integer or list/tuple of integers.
            bit_width: Bit width (8, 16, 32, or 64).
            signed: If True, use signed (two's complement) encoding.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If bit_width is invalid or values are out of range.
        """
        validate_bit_width(bit_width)

        if isinstance(value, (list, tuple)):
            if len(value) == 0:
                raise ValueError("plaintext array cannot be empty")
            unsigned_values = tuple(convert_to_unsigned(v, bit_width, signed) for v in value)
            self._entries.append(PlaintextArrayParam(bit_width=bit_width, values=unsigned_values))
        else:
            unsigned_value = convert_to_unsigned(value, bit_width, signed)
            self._entries.append(PlaintextParam(bit_width=bit_width, value=unsigned_value))
        return self

    def output(self, bit_width: int, size: int) -> ParameterBuilder:
        """Declare an output buffer.

        Args:
            bit_width: Bit width for output values (8, 16, 32, or 64).
            size: Number of output elements (must be >= 1).

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If bit_width is invalid or size < 1.
        """
        validate_bit_width(bit_width)
        if size < 1:
            raise ValueError("output size must be at least 1")
        self._entries.append(OutputParam(bit_width=bit_width, size=size))
        return self

    def build(self, public_key: PublicKey | None = None) -> Parameters:
        """Build frozen Parameters, encrypting any pending values.

        Args:
            public_key: Required if there are values to encrypt.
                Can be omitted if only using pre-encrypted ciphertexts.

        Returns:
            Frozen Parameters object ready for serialization.

        Raises:
            ValueError: If encryption is needed but public_key is None.
        """
        entries = tuple(entry.finalize(public_key) for entry in self._entries)
        return Parameters(entries=entries)

    def __len__(self) -> int:
        return len(self._entries)
