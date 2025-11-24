//! Ciphertext type and encryption/decryption operations.

use parasol_runtime::fluent::{PackedUInt16, PackedUInt32, PackedUInt64, PackedUInt8};
use parasol_runtime::L1GlweCiphertext;
use program_runner::L1GlweCiphertextWithBitWidth;
use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;

use parasol_runtime::Encryption;

use crate::keys::{PyPublicKey, PySecretKey};
use crate::validation::{from_msgpack, to_msgpack, to_signed, BitWidth, BitWidthExt};

/// An encrypted value (ciphertext) with associated bit width.
///
/// Ciphertexts can be serialized for transmission to the server
/// and deserialized after computation to decrypt the result.
#[pyclass(name = "Ciphertext")]
#[derive(Clone)]
pub struct PyCiphertext {
    /// The underlying ciphertext data.
    ciphertext: L1GlweCiphertext,
    /// Validated bit width (8, 16, 32, or 64).
    bit_width: BitWidth,
}

impl std::fmt::Debug for PyCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PyCiphertext")
            .field("bit_width", &self.bit_width)
            .field("ciphertext", &"<L1GlweCiphertext>")
            .finish()
    }
}

impl PyCiphertext {
    /// Create a new PyCiphertext from raw components.
    ///
    /// This is the single constructor that ensures bit_width is always valid.
    fn new(ciphertext: L1GlweCiphertext, bit_width: BitWidth) -> Self {
        Self {
            ciphertext,
            bit_width,
        }
    }

    /// Parse from the wire format.
    pub(crate) fn from_wire_format(inner: L1GlweCiphertextWithBitWidth) -> Self {
        Self::new(inner.ciphertext, inner.bit_width)
    }

    /// Convert to the wire format for serialization.
    fn to_wire_format(&self) -> L1GlweCiphertextWithBitWidth {
        L1GlweCiphertextWithBitWidth {
            bit_width: self.bit_width,
            ciphertext: self.ciphertext.clone(),
        }
    }

    /// Internal decryption implementation returning unsigned value.
    pub(crate) fn decrypt_impl(
        &self,
        encryption: &Encryption,
        secret_key: &PySecretKey,
    ) -> PyResult<u64> {
        let value: u64 = encryption
            .decrypt_glwe_l1(&self.ciphertext, &secret_key.inner)
            .coeffs()
            .iter()
            .take(usize::from(self.bit_width))
            .enumerate()
            .map(|(i, &v)| v << i)
            .sum();
        Ok(value)
    }

    /// Get the bit width as a BitWidth enum (for internal use).
    pub(crate) fn bit_width_enum(&self) -> BitWidth {
        self.bit_width
    }

    /// Internal encryption dispatcher based on bit width.
    ///
    /// Encrypts the given unsigned value with the appropriate packed type
    /// based on the bit width. The `BitWidth` enum ensures only valid values
    /// can be passed.
    pub(crate) fn encrypt_with_bit_width(
        value: u64,
        bit_width: BitWidth,
        encryption: &parasol_runtime::Encryption,
        public_key: &PyPublicKey,
    ) -> Self {
        let ciphertext = match bit_width {
            BitWidth::U8 => {
                PackedUInt8::encrypt(value as u128, encryption, &public_key.inner).inner()
            }
            BitWidth::U16 => {
                PackedUInt16::encrypt(value as u128, encryption, &public_key.inner).inner()
            }
            BitWidth::U32 => {
                PackedUInt32::encrypt(value as u128, encryption, &public_key.inner).inner()
            }
            BitWidth::U64 => {
                PackedUInt64::encrypt(value as u128, encryption, &public_key.inner).inner()
            }
        };

        Self::new(ciphertext, bit_width)
    }
}

#[pymethods]
impl PyCiphertext {
    /// Get the bit width of the encrypted value.
    #[getter]
    fn bit_width(&self) -> u32 {
        self.bit_width.into()
    }

    /// Serialize the ciphertext to MessagePack bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        to_msgpack(&self.to_wire_format())
    }

    /// Deserialize a ciphertext from MessagePack bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let inner: L1GlweCiphertextWithBitWidth = from_msgpack(bytes)?;
        Ok(Self::from_wire_format(inner))
    }

    /// Decrypt this ciphertext using a secret key.
    ///
    /// Args:
    ///     secret_key: The secret key for decryption
    ///     signed: If True, interpret result as signed (two's complement)
    ///
    /// Returns:
    ///     Decrypted integer value (i64 if signed, u64 if unsigned)
    fn decrypt(
        &self,
        py: Python<'_>,
        secret_key: &PySecretKey,
        signed: bool,
    ) -> PyResult<Py<PyAny>> {
        let encryption = Encryption::default();
        let unsigned = self.decrypt_impl(&encryption, secret_key)?;
        if signed {
            let signed_val = to_signed(unsigned, self.bit_width);
            Ok(signed_val.into_pyobject(py)?.into_any().unbind())
        } else {
            Ok(unsigned.into_pyobject(py)?.into_any().unbind())
        }
    }

    /// Encrypt an integer value with a public key.
    ///
    /// Args:
    ///     value: Integer value to encrypt (i64 for signed, u64 for unsigned)
    ///     public_key: Public key for encryption
    ///     bit_width: Must be 8, 16, 32, or 64
    ///     signed: If True, treat value as signed (two's complement)
    ///
    /// Returns:
    ///     Encrypted ciphertext
    ///
    /// Raises:
    ///     ValueError: If bit_width is not 8, 16, 32, or 64
    ///     OverflowError: If value cannot be converted to the expected type
    #[staticmethod]
    fn encrypt(
        value: &Bound<'_, PyAny>,
        public_key: &PyPublicKey,
        bit_width: u16,
        signed: bool,
    ) -> PyResult<Self> {
        let bit_width = BitWidth::try_from_u16(bit_width)?;
        let encryption = Encryption::default();
        let unsigned_value = if signed {
            let v: i64 = value.extract()?;
            bit_width.signed_to_unsigned(v)
        } else {
            value.extract::<u64>()?
        };
        Ok(Self::encrypt_with_bit_width(
            unsigned_value,
            bit_width,
            &encryption,
            public_key,
        ))
    }
}
