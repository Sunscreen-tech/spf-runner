"""Validation helpers for FHE operations."""

from __future__ import annotations

# Valid bit widths for FHE operations
VALID_BIT_WIDTHS = frozenset({8, 16, 32, 64})


def validate_bit_width(bit_width: int) -> None:
    """Validate that bit_width is 8, 16, 32, or 64."""
    if bit_width not in VALID_BIT_WIDTHS:
        raise ValueError(f"bit_width must be 8, 16, 32, or 64, got {bit_width}")


def validate_value_range(value: int, bit_width: int, signed: bool) -> None:
    """Validate that a value is in range for the given bit_width and signedness.

    Args:
        value: The integer value to validate.
        bit_width: The bit width (8, 16, 32, or 64).
        signed: If True, check signed range; otherwise unsigned range.

    Raises:
        ValueError: If value is out of range.
    """
    if signed:
        min_val = -(1 << (bit_width - 1))
        max_val = (1 << (bit_width - 1)) - 1
        if value < min_val or value > max_val:
            raise ValueError(
                f"signed value {value} out of range for {bit_width}-bit "
                f"integer (range: {min_val} to {max_val})"
            )
    else:
        max_val = (1 << bit_width) - 1
        if value < 0:
            raise ValueError(f"unsigned value cannot be negative, got {value}")
        if value > max_val:
            raise ValueError(
                f"value {value} exceeds maximum for {bit_width}-bit "
                f"unsigned integer (max: {max_val})"
            )


def convert_to_unsigned(value: int, bit_width: int, signed: bool) -> int:
    """Convert a value to unsigned representation.

    Args:
        value: The integer value to convert.
        bit_width: The bit width (8, 16, 32, or 64).
        signed: If True, use two's complement conversion.

    Returns:
        The unsigned representation of the value.

    Raises:
        ValueError: If value is out of range for the given bit_width and signedness.
    """
    # Validate range first
    validate_value_range(value, bit_width, signed)

    if signed:
        # Two's complement: mask to bit_width bits
        max_unsigned = (1 << bit_width) - 1
        return value & max_unsigned
    else:
        return value
