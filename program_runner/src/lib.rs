//! Shared types and serialization for FHE program parameters and outputs.
//!
//! # Wire Format
//!
//! Parameters and outputs use a versioned binary format:
//!
//! ```text
//! [MAGIC: 4 bytes][VERSION: 4 bytes big-endian u32][PAYLOAD: msgpack bytes]
//! ```
//!
//! - **MAGIC**: File type identifier ("SPFP" for parameters, "SPFO" for outputs)
//! - **VERSION**: Protocol version as big-endian u32 (fixed 4 bytes)
//! - **PAYLOAD**: MessagePack-serialized data
//!
//! # Versioning Policy
//!
//! This implementation uses strict version matching: the deserializer only
//! accepts data with an exact version match. This ensures:
//!
//! - Predictable behavior across client/server versions
//! - Early failure on incompatible data rather than silent corruption
//! - Clear upgrade path when protocol changes
//!
//! When protocol changes are needed:
//! 1. Increment the version constant
//! 2. Update serialization/deserialization logic
//! 3. Clients must upgrade to match server version

use std::num::NonZeroU32;

use parasol_runtime::L1GlweCiphertext;
use serde::{Deserialize, Serialize};

/// Current protocol version for parameters.
pub const PARAMETERS_VERSION: u32 = 1;

/// Current protocol version for outputs.
pub const OUTPUT_VERSION: u32 = 1;

/// Magic bytes identifying SPF parameter files: "SPFP" in ASCII.
pub const PARAMETERS_MAGIC: [u8; 4] = *b"SPFP";

/// Magic bytes identifying SPF output files: "SPFO" in ASCII.
pub const OUTPUT_MAGIC: [u8; 4] = *b"SPFO";

/// Header size: 4 bytes magic + 4 bytes version.
pub const HEADER_SIZE: usize = 8;

/// Error type for peeking version from serialized data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeekError {
    /// Data is too short to contain a valid header.
    TooShort,
    /// Magic bytes do not match expected value.
    InvalidMagic,
    /// Version field is corrupt or unreadable.
    InvalidVersion,
}

impl std::fmt::Display for PeekError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeekError::TooShort => write!(f, "data too short to contain valid header"),
            PeekError::InvalidMagic => write!(f, "invalid magic bytes"),
            PeekError::InvalidVersion => write!(f, "version field is corrupt or unreadable"),
        }
    }
}

impl std::error::Error for PeekError {}

/// Error type for deserialization operations.
#[derive(Debug)]
pub enum DeserializeError {
    /// Error peeking the version header.
    Peek(PeekError),
    /// Version is not supported.
    UnsupportedVersion { got: u32, expected: u32 },
    /// Error deserializing the payload.
    Payload(rmp_serde::decode::Error),
}

impl std::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // PeekError is a leaf error with no source, so include its message
            DeserializeError::Peek(e) => write!(f, "{e}"),
            DeserializeError::UnsupportedVersion { got, expected } => {
                write!(f, "unsupported version {got}, expected {expected}")
            }
            // rmp_serde errors have their own chain; don't duplicate
            DeserializeError::Payload(_) => write!(f, "payload deserialization failed"),
        }
    }
}

impl std::error::Error for DeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DeserializeError::Peek(e) => Some(e),
            DeserializeError::UnsupportedVersion { .. } => None,
            DeserializeError::Payload(e) => Some(e),
        }
    }
}

impl From<PeekError> for DeserializeError {
    fn from(e: PeekError) -> Self {
        DeserializeError::Peek(e)
    }
}

/// Error type for serialization operations.
#[derive(Debug)]
pub struct SerializeError(rmp_serde::encode::Error);

impl std::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "payload serialization failed")
    }
}

impl std::error::Error for SerializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Peek the version number from parameter bytes without full deserialization.
///
/// This reads only the header (magic bytes + version) to allow fast-fail
/// for unsupported versions without deserializing the entire payload.
pub fn peek_parameters_version(bytes: &[u8]) -> Result<u32, PeekError> {
    peek_version(bytes, &PARAMETERS_MAGIC)
}

/// Peek the version number from output bytes without full deserialization.
pub fn peek_output_version(bytes: &[u8]) -> Result<u32, PeekError> {
    peek_version(bytes, &OUTPUT_MAGIC)
}

fn peek_version(bytes: &[u8], expected_magic: &[u8; 4]) -> Result<u32, PeekError> {
    if bytes.len() < HEADER_SIZE {
        return Err(PeekError::TooShort);
    }
    if &bytes[0..4] != expected_magic {
        return Err(PeekError::InvalidMagic);
    }
    let version_bytes: [u8; 4] = bytes[4..8].try_into().map_err(|_| PeekError::InvalidVersion)?;
    Ok(u32::from_be_bytes(version_bytes))
}

/// Serialize parameters with magic bytes and version header.
pub fn serialize_parameters(params: &[ParameterType]) -> Result<Vec<u8>, SerializeError> {
    serialize_with_header(&PARAMETERS_MAGIC, PARAMETERS_VERSION, params)
}

/// Serialize outputs with magic bytes and version header.
pub fn serialize_outputs(
    outputs: &[L1GlweCiphertextWithBitWidth],
) -> Result<Vec<u8>, SerializeError> {
    serialize_with_header(&OUTPUT_MAGIC, OUTPUT_VERSION, outputs)
}

fn serialize_with_header<T: Serialize + ?Sized>(
    magic: &[u8; 4],
    version: u32,
    payload: &T,
) -> Result<Vec<u8>, SerializeError> {
    let mut buf = Vec::with_capacity(HEADER_SIZE);
    buf.extend_from_slice(magic);
    buf.extend_from_slice(&version.to_be_bytes());
    let payload_bytes = rmp_serde::to_vec(payload).map_err(SerializeError)?;
    buf.extend_from_slice(&payload_bytes);
    Ok(buf)
}

/// Deserialize parameters, validating magic bytes and version.
pub fn deserialize_parameters(bytes: &[u8]) -> Result<Vec<ParameterType>, DeserializeError> {
    deserialize_with_header(bytes, &PARAMETERS_MAGIC, PARAMETERS_VERSION)
}

/// Deserialize outputs, validating magic bytes and version.
pub fn deserialize_outputs(
    bytes: &[u8],
) -> Result<Vec<L1GlweCiphertextWithBitWidth>, DeserializeError> {
    deserialize_with_header(bytes, &OUTPUT_MAGIC, OUTPUT_VERSION)
}

fn deserialize_with_header<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    expected_magic: &[u8; 4],
    expected_version: u32,
) -> Result<T, DeserializeError> {
    if bytes.len() < HEADER_SIZE {
        return Err(PeekError::TooShort.into());
    }
    if &bytes[0..4] != expected_magic {
        return Err(PeekError::InvalidMagic.into());
    }

    let version_bytes: [u8; 4] = bytes[4..8]
        .try_into()
        .map_err(|_| PeekError::InvalidVersion)?;
    let version = u32::from_be_bytes(version_bytes);

    if version != expected_version {
        return Err(DeserializeError::UnsupportedVersion {
            got: version,
            expected: expected_version,
        });
    }

    rmp_serde::from_slice(&bytes[HEADER_SIZE..]).map_err(DeserializeError::Payload)
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBitWidth(pub u32);

impl std::fmt::Display for InvalidBitWidth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bit_width must be 8, 16, 32, or 64, got {}", self.0)
    }
}

impl std::error::Error for InvalidBitWidth {}

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

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct L1GlweCiphertextWithBitWidth {
    pub bit_width: BitWidth,
    pub ciphertext: L1GlweCiphertext,
}
