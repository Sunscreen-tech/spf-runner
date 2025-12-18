//! Serialization and deserialization for parameters and outputs.

use serde::Serialize;

use crate::error::{DeserializeError, PeekError, SerializeError};
use crate::types::{L1GlweCiphertextWithBitWidth, ParameterType};
use crate::{HEADER_SIZE, OUTPUT_MAGIC, OUTPUT_VERSION, PARAMETERS_MAGIC, PARAMETERS_VERSION};

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
    let version_bytes: [u8; 4] = bytes[4..8]
        .try_into()
        .map_err(|_| PeekError::InvalidVersion)?;
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

/// Deserialize parameters payload, assuming header was already validated.
///
/// The caller must have validated the header via `peek_parameters_version` and
/// pass the returned version. This function validates the version matches the
/// expected `PARAMETERS_VERSION` and deserializes the msgpack payload.
pub fn deserialize_parameters_payload(
    bytes: &[u8],
    version: u32,
) -> Result<Vec<ParameterType>, DeserializeError> {
    if version != PARAMETERS_VERSION {
        return Err(DeserializeError::UnsupportedVersion {
            got: version,
            expected: PARAMETERS_VERSION,
        });
    }
    rmp_serde::from_slice(&bytes[HEADER_SIZE..]).map_err(DeserializeError::Payload)
}

/// Deserialize parameters, validating magic bytes and version.
pub fn deserialize_parameters(bytes: &[u8]) -> Result<Vec<ParameterType>, DeserializeError> {
    let version = peek_parameters_version(bytes)?;
    deserialize_parameters_payload(bytes, version)
}

/// Deserialize outputs, validating magic bytes and version.
pub fn deserialize_outputs(
    bytes: &[u8],
) -> Result<Vec<L1GlweCiphertextWithBitWidth>, DeserializeError> {
    let version = peek_output_version(bytes)?;
    if version != OUTPUT_VERSION {
        return Err(DeserializeError::UnsupportedVersion {
            got: version,
            expected: OUTPUT_VERSION,
        });
    }
    rmp_serde::from_slice(&bytes[HEADER_SIZE..]).map_err(DeserializeError::Payload)
}
