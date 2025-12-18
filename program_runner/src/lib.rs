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

mod error;
mod types;
mod wire;

pub use error::{DeserializeError, PeekError, SerializeError};
use parasol_runtime::{DEFAULT_128, Params};
pub use types::{BitWidth, InvalidBitWidth, L1GlweCiphertextWithBitWidth, ParameterType};
pub use wire::{
    deserialize_outputs, deserialize_parameters, deserialize_parameters_payload,
    peek_output_version, peek_parameters_version, serialize_outputs, serialize_parameters,
};

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

// Gas cost related constants
pub const BYTE_WIDTH_MULTIPLIER_COST: u32 = 320;

/// Exponential base for ciphertext unpacking gas calculation.
/// Used as: base^log2(byte_width)
pub const CIPHERTEXT_UNPACK_EXPONENTIAL_BASE_COST: u32 = 6;

/// Normalizer divisor for exponential component in unpacking gas calculation.
pub const CIPHERTEXT_UNPACK_NORMALIZER_COST: f64 = 600.0;

/// Final multiplier applied to compute total unpacking gas cost.
pub const CIPHERTEXT_UNPACK_MULTIPLIER_COST: f64 = 56280.0;

/// Base unit offset added before final multiplication in unpacking gas calculation.
pub const CIPHERTEXT_UNPACK_BASE_UNIT_COST: f64 = 1.0;

/// Default FHE parameters (128-bit security).
pub static PARAMS: Params = DEFAULT_128;
