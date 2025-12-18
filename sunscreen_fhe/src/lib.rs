//! Python bindings for TFHE client operations.
//!
//! This crate provides Python bindings for key generation, encryption, decryption,
//! and parameter building for the FHE program runner.

use pyo3::prelude::*;

mod ciphertext;
mod keys;
mod parameters;
mod validation;

pub use ciphertext::PyCiphertext;
pub use keys::{PyComputeKey, PyKeySet, PyPublicKey, PySecretKey};
pub use parameters::{
    deserialize_output, deserialize_parameters, get_output_version, get_parameters_version,
    py_peek_output_version, py_peek_parameters_version, serialize_parameters, PyWireCiphertext,
    PyWireCiphertextArray, PyWireOutputCiphertextArray, PyWirePlaintext, PyWirePlaintextArray,
};

/// Python module for sunscreen_fhe native bindings.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Key classes
    m.add_class::<PySecretKey>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyComputeKey>()?;
    m.add_class::<PyKeySet>()?;

    // Ciphertext class
    m.add_class::<PyCiphertext>()?;

    // Wire format parameter classes (internal)
    m.add_class::<PyWireCiphertext>()?;
    m.add_class::<PyWireCiphertextArray>()?;
    m.add_class::<PyWireOutputCiphertextArray>()?;
    m.add_class::<PyWirePlaintext>()?;
    m.add_class::<PyWirePlaintextArray>()?;

    // Parameter serialization functions
    m.add_function(wrap_pyfunction!(serialize_parameters, m)?)?;
    m.add_function(wrap_pyfunction!(deserialize_parameters, m)?)?;

    // Output deserialization function
    m.add_function(wrap_pyfunction!(deserialize_output, m)?)?;

    // Version peeking functions
    m.add_function(wrap_pyfunction!(py_peek_parameters_version, m)?)?;
    m.add_function(wrap_pyfunction!(py_peek_output_version, m)?)?;

    // Version getters
    m.add_function(wrap_pyfunction!(get_parameters_version, m)?)?;
    m.add_function(wrap_pyfunction!(get_output_version, m)?)?;

    Ok(())
}
