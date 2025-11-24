//! Validation and conversion utilities for FHE operations.

use pyo3::prelude::*;

/// Extension trait for converting errors to PyValueError.
pub trait ToPyValueError<T> {
    fn to_py_value_error(self) -> PyResult<T>;
}

impl<T, E: std::fmt::Display> ToPyValueError<T> for Result<T, E> {
    fn to_py_value_error(self) -> PyResult<T> {
        self.map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
}

/// Create a PyValueError from any displayable message.
pub fn value_error(msg: impl std::fmt::Display) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyValueError, _>(msg.to_string())
}

// Re-export BitWidth from program_runner for use throughout tfhe_client.
// This ensures serialization compatibility between the two crates.
pub use program_runner::BitWidth;

/// Helper trait for PyO3 wrapper types that hold Arc<T> inner values.
///
/// Provides common serialization methods.
pub trait PyArcWrapper<T>: Sized
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    /// Get a reference to the inner value.
    fn inner_ref(&self) -> &T;

    /// Create a new instance from the inner value wrapped in Arc.
    fn from_arc(inner: std::sync::Arc<T>) -> Self;

    /// Serialize to bytes.
    fn serialize_to_bytes(&self) -> PyResult<Vec<u8>> {
        to_msgpack(self.inner_ref())
    }

    /// Deserialize from bytes.
    fn deserialize_from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let inner: T = from_msgpack(bytes)?;
        Ok(Self::from_arc(std::sync::Arc::new(inner)))
    }
}

/// Extension trait for BitWidth that provides PyResult-returning conversions.
pub trait BitWidthExt {
    /// Parse a bit width from u16, returning a PyResult for Python API boundaries.
    fn try_from_u16(value: u16) -> PyResult<BitWidth>;
}

impl BitWidthExt for BitWidth {
    fn try_from_u16(value: u16) -> PyResult<BitWidth> {
        BitWidth::try_from(value).map_err(value_error)
    }
}

/// Convert an unsigned value to its signed representation based on bit width.
///
/// Interprets the value using two's complement encoding. The `BitWidth` enum
/// ensures only valid bit widths can be passed, making this function infallible.
pub fn to_signed(value: u64, bit_width: BitWidth) -> i64 {
    bit_width.unsigned_to_signed(value)
}

/// Serialize a value to MessagePack bytes with consistent error handling.
pub fn to_msgpack<T: serde::Serialize>(value: &T) -> PyResult<Vec<u8>> {
    rmp_serde::to_vec(value).to_py_value_error()
}

/// Deserialize a value from MessagePack bytes with consistent error handling.
pub fn from_msgpack<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> PyResult<T> {
    rmp_serde::from_slice(bytes).to_py_value_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_width_try_from_u16_valid() {
        Python::attach(|_py| {
            assert_eq!(BitWidth::try_from_u16(8).unwrap(), BitWidth::U8);
            assert_eq!(BitWidth::try_from_u16(16).unwrap(), BitWidth::U16);
            assert_eq!(BitWidth::try_from_u16(32).unwrap(), BitWidth::U32);
            assert_eq!(BitWidth::try_from_u16(64).unwrap(), BitWidth::U64);
        });
    }

    #[test]
    fn test_bit_width_try_from_u16_invalid() {
        Python::attach(|_py| {
            assert!(BitWidth::try_from_u16(0).is_err());
            assert!(BitWidth::try_from_u16(1).is_err());
            assert!(BitWidth::try_from_u16(7).is_err());
            assert!(BitWidth::try_from_u16(12).is_err());
            assert!(BitWidth::try_from_u16(128).is_err());
            assert!(BitWidth::try_from_u16(256).is_err());
        });
    }

    #[test]
    fn test_bit_width_into_u8() {
        assert_eq!(u8::from(BitWidth::U8), 8);
        assert_eq!(u8::from(BitWidth::U16), 16);
        assert_eq!(u8::from(BitWidth::U32), 32);
        assert_eq!(u8::from(BitWidth::U64), 64);
    }

    #[test]
    fn test_bit_width_into_u16() {
        assert_eq!(u16::from(BitWidth::U8), 8);
        assert_eq!(u16::from(BitWidth::U16), 16);
        assert_eq!(u16::from(BitWidth::U32), 32);
        assert_eq!(u16::from(BitWidth::U64), 64);
    }

    #[test]
    fn test_bit_width_into_u32() {
        assert_eq!(u32::from(BitWidth::U8), 8);
        assert_eq!(u32::from(BitWidth::U16), 16);
        assert_eq!(u32::from(BitWidth::U32), 32);
        assert_eq!(u32::from(BitWidth::U64), 64);
    }

    #[test]
    fn test_bit_width_into_usize() {
        assert_eq!(usize::from(BitWidth::U8), 8);
        assert_eq!(usize::from(BitWidth::U16), 16);
        assert_eq!(usize::from(BitWidth::U32), 32);
        assert_eq!(usize::from(BitWidth::U64), 64);
    }

    #[test]
    fn test_to_signed() {
        // Positive values stay positive
        assert_eq!(to_signed(42, BitWidth::U8), 42);
        assert_eq!(to_signed(1000, BitWidth::U16), 1000);

        // Two's complement conversion
        assert_eq!(to_signed(255, BitWidth::U8), -1);
        assert_eq!(to_signed(128, BitWidth::U8), -128);
        assert_eq!(to_signed(65535, BitWidth::U16), -1);
        assert_eq!(to_signed(32768, BitWidth::U16), -32768);
    }
}
