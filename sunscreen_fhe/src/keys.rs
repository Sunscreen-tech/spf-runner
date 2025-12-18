//! Key generation and management for TFHE operations.

use parasol_runtime::{ComputeKey, Encryption, PublicKey, SecretKey};
use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;
use std::sync::Arc;

use program_runner::PARAMS;

use crate::ciphertext::PyCiphertext;
use crate::validation::{to_signed, BitWidth, BitWidthExt, PyArcWrapper};

/// Implement PyArcWrapper trait for a PyO3 wrapper type.
macro_rules! impl_py_arc_wrapper {
    ($py_type:ty, $inner_type:ty) => {
        impl PyArcWrapper<$inner_type> for $py_type {
            fn inner_ref(&self) -> &$inner_type {
                &self.inner
            }

            fn from_arc(inner: Arc<$inner_type>) -> Self {
                Self {
                    inner,
                    encryption: Encryption::new(&program_runner::PARAMS),
                }
            }
        }
    };
}

/// Secret key for decryption operations.
///
/// The secret key must be kept secure and never shared.
#[pyclass(name = "SecretKey")]
#[derive(Clone)]
pub struct PySecretKey {
    pub(crate) inner: Arc<SecretKey>,
    pub(crate) encryption: Encryption,
}

impl_py_arc_wrapper!(PySecretKey, SecretKey);

#[pymethods]
impl PySecretKey {
    /// Generate a new secret key with 128-bit security.
    #[staticmethod]
    fn generate() -> Self {
        Self {
            inner: Arc::new(SecretKey::generate(&PARAMS)),
            encryption: Encryption::new(&PARAMS),
        }
    }

    /// Serialize to bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        PyArcWrapper::serialize_to_bytes(self)
    }

    /// Deserialize from bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        <Self as PyArcWrapper<SecretKey>>::deserialize_from_bytes(bytes)
    }

    /// Decrypt a ciphertext.
    ///
    /// Args:
    ///     ciphertext: The encrypted value to decrypt
    ///     signed: If True, interpret result as signed (two's complement)
    ///
    /// Returns:
    ///     Decrypted integer value (i64 if signed, u64 if unsigned)
    fn decrypt(
        &self,
        py: Python<'_>,
        ciphertext: &PyCiphertext,
        signed: bool,
    ) -> PyResult<Py<PyAny>> {
        let unsigned = ciphertext.decrypt_impl(&self.encryption, self)?;
        if signed {
            let signed_val = to_signed(unsigned, ciphertext.bit_width_enum());
            Ok(signed_val.into_pyobject(py)?.into_any().unbind())
        } else {
            Ok(unsigned.into_pyobject(py)?.into_any().unbind())
        }
    }
}

/// Public key for encryption operations.
///
/// The public key can be shared freely.
#[pyclass(name = "PublicKey")]
#[derive(Clone)]
pub struct PyPublicKey {
    pub(crate) inner: Arc<PublicKey>,
    pub(crate) encryption: Encryption,
}

impl_py_arc_wrapper!(PyPublicKey, PublicKey);

#[pymethods]
impl PyPublicKey {
    /// Derive a public key from a secret key.
    #[staticmethod]
    fn from_secret_key(secret_key: &PySecretKey) -> Self {
        Self {
            inner: Arc::new(PublicKey::generate(&PARAMS, &secret_key.inner)),
            encryption: Encryption::new(&PARAMS),
        }
    }

    /// Serialize to bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        PyArcWrapper::serialize_to_bytes(self)
    }

    /// Deserialize from bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        <Self as PyArcWrapper<PublicKey>>::deserialize_from_bytes(bytes)
    }

    /// Encrypt an integer value.
    ///
    /// Encrypts the given value as a ciphertext with the specified bit width.
    /// For signed values, set `signed=True`.
    ///
    /// Args:
    ///     value: Integer value to encrypt (i64 for signed, u64 for unsigned)
    ///     bit_width: Must be 8, 16, 32, or 64
    ///     signed: If True, treat value as signed (two's complement)
    ///
    /// Returns:
    ///     Encrypted ciphertext
    ///
    /// Raises:
    ///     ValueError: If bit_width is not 8, 16, 32, or 64
    ///     OverflowError: If value cannot be converted to the expected type
    fn encrypt(
        &self,
        value: &Bound<'_, PyAny>,
        bit_width: u16,
        signed: bool,
    ) -> PyResult<PyCiphertext> {
        let bit_width = BitWidth::try_from_u16(bit_width)?;
        let unsigned_value = if signed {
            let v: i64 = value.extract()?;
            bit_width.signed_to_unsigned(v)
        } else {
            value.extract::<u64>()?
        };
        Ok(PyCiphertext::encrypt_with_bit_width(
            unsigned_value,
            bit_width,
            &self.encryption,
            self,
        ))
    }
}

/// Compute key for server-side FHE operations.
///
/// The compute key is sent to the server to perform homomorphic computations
/// on encrypted data without learning the plaintext.
#[pyclass(name = "ComputeKey")]
#[derive(Clone)]
pub struct PyComputeKey {
    pub(crate) inner: Arc<ComputeKey>,
}

impl PyArcWrapper<ComputeKey> for PyComputeKey {
    fn inner_ref(&self) -> &ComputeKey {
        &self.inner
    }

    fn from_arc(inner: Arc<ComputeKey>) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyComputeKey {
    /// Derive a compute key from a secret key.
    #[staticmethod]
    fn from_secret_key(secret_key: &PySecretKey) -> Self {
        Self {
            inner: Arc::new(ComputeKey::generate(&secret_key.inner, &PARAMS)),
        }
    }

    /// Serialize to bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        PyArcWrapper::serialize_to_bytes(self)
    }

    /// Deserialize from bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        <Self as PyArcWrapper<ComputeKey>>::deserialize_from_bytes(bytes)
    }
}

/// A complete set of keys for FHE operations.
///
/// Bundles together all three keys (secret, public, and compute).
#[pyclass(name = "KeySet")]
#[derive(Clone)]
pub struct PyKeySet {
    secret_key: PySecretKey,
    public_key: PyPublicKey,
    compute_key: PyComputeKey,
}

#[pymethods]
impl PyKeySet {
    /// Generate a new complete key set with 128-bit security.
    #[staticmethod]
    fn generate() -> Self {
        let secret_key = PySecretKey::generate();
        let public_key = PyPublicKey::from_secret_key(&secret_key);
        let compute_key = PyComputeKey::from_secret_key(&secret_key);

        Self {
            secret_key,
            public_key,
            compute_key,
        }
    }

    /// Construct a KeySet from individual keys.
    #[new]
    fn new(secret_key: PySecretKey, public_key: PyPublicKey, compute_key: PyComputeKey) -> Self {
        Self {
            secret_key,
            public_key,
            compute_key,
        }
    }

    /// Get the secret key.
    #[getter]
    fn secret_key(&self) -> PySecretKey {
        self.secret_key.clone()
    }

    /// Get the public key.
    #[getter]
    fn public_key(&self) -> PyPublicKey {
        self.public_key.clone()
    }

    /// Get the compute key.
    #[getter]
    fn compute_key(&self) -> PyComputeKey {
        self.compute_key.clone()
    }

    /// Encrypt an integer value.
    ///
    /// Encrypts the given value as a ciphertext with the specified bit width.
    /// For signed values, set `signed=True`.
    ///
    /// Args:
    ///     value: Integer value to encrypt (i64 for signed, u64 for unsigned)
    ///     bit_width: Must be 8, 16, 32, or 64
    ///     signed: If True, treat value as signed (two's complement)
    ///
    /// Returns:
    ///     Encrypted ciphertext
    ///
    /// Raises:
    ///     ValueError: If bit_width is not 8, 16, 32, or 64
    ///     OverflowError: If value cannot be converted to the expected type
    fn encrypt(
        &self,
        value: &Bound<'_, PyAny>,
        bit_width: u16,
        signed: bool,
    ) -> PyResult<PyCiphertext> {
        self.public_key.encrypt(value, bit_width, signed)
    }

    /// Decrypt a ciphertext.
    ///
    /// Args:
    ///     ciphertext: The encrypted value to decrypt
    ///     signed: If True, interpret result as signed (two's complement)
    ///
    /// Returns:
    ///     Decrypted integer value (i64 if signed, u64 if unsigned)
    fn decrypt(
        &self,
        py: Python<'_>,
        ciphertext: &PyCiphertext,
        signed: bool,
    ) -> PyResult<Py<PyAny>> {
        self.secret_key.decrypt(py, ciphertext, signed)
    }
}
