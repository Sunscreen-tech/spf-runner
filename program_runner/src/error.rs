//! Error types for serialization and deserialization operations.

/// Error type for peeking version from serialized data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeekError {
    /// Data is too short to contain a valid header.
    #[error("data too short to contain valid header")]
    TooShort,
    /// Magic bytes do not match expected value.
    #[error("invalid magic bytes")]
    InvalidMagic,
    /// Version field is corrupt or unreadable.
    #[error("version field is corrupt or unreadable")]
    InvalidVersion,
}

/// Error type for deserialization operations.
#[derive(Debug, thiserror::Error)]
pub enum DeserializeError {
    /// Error peeking the version header.
    #[error("header validation failed: {0}")]
    Peek(#[from] PeekError),
    /// Version is not supported.
    #[error("unsupported version {got}, expected {expected}")]
    UnsupportedVersion { got: u32, expected: u32 },
    /// Error deserializing the payload.
    #[error("payload deserialization failed")]
    Payload(#[source] rmp_serde::decode::Error),
}

/// Error type for serialization operations.
#[derive(Debug, thiserror::Error)]
#[error("payload serialization failed")]
pub struct SerializeError(#[source] pub(crate) rmp_serde::encode::Error);
