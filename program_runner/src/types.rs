//! Type definitions for FHE parameters and ciphertexts.

use std::num::NonZeroU32;

use parasol_runtime::L1GlweCiphertext;
use serde::{Deserialize, Serialize};

/// Type-safe bit width representation for FHE operations.
///
/// This enum ensures only valid bit widths can be used, eliminating the need
/// for runtime validation in internal functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BitWidth {
    U8 = 8,
    U16 = 16,
    U32 = 32,
    U64 = 64,
}

/// Error type for invalid bit width conversions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("bit_width must be 8, 16, 32, or 64, got {0}")]
pub struct InvalidBitWidth(pub u32);

impl BitWidth {
    /// Get the byte width (bit_width / 8).
    pub fn byte_width(self) -> u32 {
        u32::from(self) / 8
    }

    /// Get the maximum unsigned value for this bit width.
    pub fn max_unsigned(self) -> u64 {
        match self {
            BitWidth::U8 => u8::MAX as u64,
            BitWidth::U16 => u16::MAX as u64,
            BitWidth::U32 => u32::MAX as u64,
            BitWidth::U64 => u64::MAX,
        }
    }

    /// Convert a signed value to its unsigned representation using two's complement.
    pub fn signed_to_unsigned(self, value: i64) -> u64 {
        match self {
            BitWidth::U8 => (value as i8) as u8 as u64,
            BitWidth::U16 => (value as i16) as u16 as u64,
            BitWidth::U32 => (value as i32) as u32 as u64,
            BitWidth::U64 => value as u64,
        }
    }

    /// Convert an unsigned value to its signed representation using two's complement.
    pub fn unsigned_to_signed(self, value: u64) -> i64 {
        match self {
            BitWidth::U8 => (value as u8) as i8 as i64,
            BitWidth::U16 => (value as u16) as i16 as i64,
            BitWidth::U32 => (value as u32) as i32 as i64,
            BitWidth::U64 => value as i64,
        }
    }
}

impl TryFrom<u16> for BitWidth {
    type Error = InvalidBitWidth;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        BitWidth::try_from(value as u32)
    }
}

impl TryFrom<u32> for BitWidth {
    type Error = InvalidBitWidth;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            8 => Ok(BitWidth::U8),
            16 => Ok(BitWidth::U16),
            32 => Ok(BitWidth::U32),
            64 => Ok(BitWidth::U64),
            _ => Err(InvalidBitWidth(value)),
        }
    }
}

impl From<BitWidth> for u8 {
    fn from(bw: BitWidth) -> u8 {
        bw as u8
    }
}

impl From<BitWidth> for u16 {
    fn from(bw: BitWidth) -> u16 {
        bw as u16
    }
}

impl From<BitWidth> for u32 {
    fn from(bw: BitWidth) -> u32 {
        bw as u32
    }
}

impl From<BitWidth> for usize {
    fn from(bw: BitWidth) -> usize {
        bw as usize
    }
}

/// Parameter types for FHE program inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterType {
    /// Single ciphertext parameter
    Ciphertext {
        content: L1GlweCiphertextWithBitWidth,
    },
    /// Array of ciphertext parameters
    CiphertextArray {
        contents: Vec<L1GlweCiphertextWithBitWidth>,
    },
    /// Output ciphertext array (result)
    OutputCiphertextArray {
        bit_width: BitWidth,
        size: NonZeroU32,
    },
    /// Single plaintext parameter
    Plaintext { bit_width: BitWidth, value: u64 },
    /// Array of plaintext parameters
    PlaintextArray {
        bit_width: BitWidth,
        values: Vec<u64>,
    },
}

/// Ciphertext with associated bit width.
#[derive(Clone, Serialize, Deserialize)]
pub struct L1GlweCiphertextWithBitWidth {
    pub bit_width: BitWidth,
    pub ciphertext: L1GlweCiphertext,
}

impl std::fmt::Debug for L1GlweCiphertextWithBitWidth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L1GlweCiphertextWithBitWidth")
            .field("bit_width", &self.bit_width)
            .field("ciphertext", &"<L1GlweCiphertext>")
            .finish()
    }
}
