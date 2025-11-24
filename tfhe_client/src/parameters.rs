//! Parameter serialization functions for FHE program inputs.

use std::num::NonZeroU32;

use program_runner::{
    BitWidth, L1GlweCiphertextWithBitWidth, ParameterType, VersionedOutput, VersionedParameters,
    OUTPUT_VERSION, PARAMETERS_VERSION,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

use crate::ciphertext::PyCiphertext;
use crate::validation::{from_msgpack, to_msgpack, value_error, BitWidthExt};

// -----------------------------------------------------------------------------
// Wire format types for Python<->Rust serialization boundary
// -----------------------------------------------------------------------------

/// Serialized ciphertext for wire format (internal).
#[pyclass(name = "WireCiphertext", eq)]
#[derive(Clone, PartialEq)]
pub struct PyWireCiphertext {
    data: Vec<u8>,
    bit_width: u16,
}

#[pymethods]
impl PyWireCiphertext {
    #[new]
    fn new(data: Vec<u8>) -> PyResult<Self> {
        let ct: L1GlweCiphertextWithBitWidth = from_msgpack(&data)?;
        Ok(Self {
            data,
            bit_width: ct.bit_width.into(),
        })
    }

    #[getter]
    fn bit_width(&self) -> u16 {
        self.bit_width
    }

    #[getter]
    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Serialized ciphertext array for wire format (internal).
#[pyclass(name = "WireCiphertextArray", eq)]
#[derive(Clone, PartialEq)]
pub struct PyWireCiphertextArray {
    data: Vec<Vec<u8>>,
    bit_width: u16,
}

#[pymethods]
impl PyWireCiphertextArray {
    #[new]
    fn new(data: Vec<Vec<u8>>) -> PyResult<Self> {
        let bit_width = data
            .first()
            .map(|first| from_msgpack::<L1GlweCiphertextWithBitWidth>(first))
            .transpose()?
            .map(|ct| ct.bit_width.into())
            .ok_or_else(|| value_error("ciphertext array cannot be empty"))?;
        Ok(Self { data, bit_width })
    }

    #[getter]
    fn bit_width(&self) -> u16 {
        self.bit_width
    }

    #[getter]
    fn data(&self) -> Vec<Vec<u8>> {
        self.data.clone()
    }

    fn __len__(&self) -> usize {
        self.data.len()
    }
}

/// Output buffer declaration for wire format (internal).
#[pyclass(name = "WireOutputCiphertextArray", eq)]
#[derive(Clone, PartialEq)]
pub struct PyWireOutputCiphertextArray {
    bit_width: u16,
    size: u32,
}

#[pymethods]
impl PyWireOutputCiphertextArray {
    #[new]
    fn new(bit_width: u16, size: u32) -> Self {
        Self { bit_width, size }
    }

    #[getter]
    fn bit_width(&self) -> u16 {
        self.bit_width
    }

    #[getter]
    fn size(&self) -> u32 {
        self.size
    }
}

/// Plaintext value for wire format (internal).
#[pyclass(name = "WirePlaintext", eq)]
#[derive(Clone, PartialEq)]
pub struct PyWirePlaintext {
    value: u64,
    bit_width: u16,
}

#[pymethods]
impl PyWirePlaintext {
    #[new]
    fn new(value: u64, bit_width: u16) -> Self {
        Self { value, bit_width }
    }

    #[getter]
    fn bit_width(&self) -> u16 {
        self.bit_width
    }

    #[getter]
    fn value(&self) -> u64 {
        self.value
    }
}

/// Plaintext array for wire format (internal).
#[pyclass(name = "WirePlaintextArray", eq)]
#[derive(Clone, PartialEq)]
pub struct PyWirePlaintextArray {
    values: Vec<u64>,
    bit_width: u16,
}

#[pymethods]
impl PyWirePlaintextArray {
    #[new]
    fn new(values: Vec<u64>, bit_width: u16) -> Self {
        Self { values, bit_width }
    }

    #[getter]
    fn bit_width(&self) -> u16 {
        self.bit_width
    }

    #[getter]
    fn values(&self) -> Vec<u64> {
        self.values.clone()
    }

    fn __len__(&self) -> usize {
        self.values.len()
    }
}

// -----------------------------------------------------------------------------
// Parameter serialization functions
// -----------------------------------------------------------------------------

/// Serialize parameter entries from Python to MessagePack Vec<ParameterType>.
///
/// Accepts a list of Wire* objects representing parameter entries.
/// Returns serialized MessagePack bytes.
#[pyfunction]
pub fn serialize_parameters(py: Python<'_>, entries: &Bound<'_, PyList>) -> PyResult<Py<PyBytes>> {
    let mut params = Vec::with_capacity(entries.len());

    for entry in entries.iter() {
        if let Ok(ct) = entry.extract::<PyRef<PyWireCiphertext>>() {
            let inner: L1GlweCiphertextWithBitWidth = from_msgpack(&ct.data)?;
            params.push(ParameterType::Ciphertext { content: inner });
        } else if let Ok(arr) = entry.extract::<PyRef<PyWireCiphertextArray>>() {
            let mut cts = Vec::with_capacity(arr.data.len());
            for bytes in &arr.data {
                let ct: L1GlweCiphertextWithBitWidth = from_msgpack(bytes)?;
                cts.push(ct);
            }
            params.push(ParameterType::CiphertextArray { contents: cts });
        } else if let Ok(out) = entry.extract::<PyRef<PyWireOutputCiphertextArray>>() {
            let bit_width = BitWidth::try_from_u16(out.bit_width)?;
            let size = NonZeroU32::new(out.size)
                .ok_or_else(|| value_error("output size must be at least 1"))?;
            params.push(ParameterType::OutputCiphertextArray { bit_width, size });
        } else if let Ok(pt) = entry.extract::<PyRef<PyWirePlaintext>>() {
            let bit_width = BitWidth::try_from_u16(pt.bit_width)?;
            params.push(ParameterType::Plaintext {
                bit_width,
                value: pt.value,
            });
        } else if let Ok(arr) = entry.extract::<PyRef<PyWirePlaintextArray>>() {
            let bit_width = BitWidth::try_from_u16(arr.bit_width)?;
            params.push(ParameterType::PlaintextArray {
                bit_width,
                values: arr.values.clone(),
            });
        } else {
            return Err(value_error("unknown parameter type"));
        }
    }

    let versioned = VersionedParameters::new(params);
    let bytes = to_msgpack(&versioned)?;
    Ok(PyBytes::new(py, &bytes).into())
}

/// Deserialize MessagePack bytes to list of Wire* parameter objects.
///
/// Returns a list of WireCiphertext, WireCiphertextArray, WireOutput,
/// WirePlaintext, or WirePlaintextArray objects.
#[pyfunction]
pub fn deserialize_parameters(py: Python<'_>, bytes: &[u8]) -> PyResult<Py<PyList>> {
    let versioned: VersionedParameters = from_msgpack(bytes)?;

    if versioned.version != PARAMETERS_VERSION {
        return Err(value_error(format!(
            "unsupported parameters version {}, expected {}",
            versioned.version, PARAMETERS_VERSION
        )));
    }

    let params = versioned.parameters;
    let result = PyList::empty(py);

    for param in params {
        match param {
            ParameterType::Ciphertext { content } => {
                let bit_width: u16 = content.bit_width.into();
                let ct_bytes = to_msgpack(&content)?;
                result.append(
                    PyWireCiphertext {
                        data: ct_bytes,
                        bit_width,
                    }
                    .into_pyobject(py)?,
                )?;
            }
            ParameterType::CiphertextArray { contents } => {
                let bit_width: u16 = contents
                    .first()
                    .map(|c| c.bit_width.into())
                    .ok_or_else(|| value_error("ciphertext array cannot be empty"))?;
                let data: Vec<Vec<u8>> =
                    contents.iter().map(to_msgpack).collect::<PyResult<_>>()?;
                result.append(PyWireCiphertextArray { data, bit_width }.into_pyobject(py)?)?;
            }
            ParameterType::OutputCiphertextArray { bit_width, size } => {
                result.append(
                    PyWireOutputCiphertextArray {
                        bit_width: bit_width.into(),
                        size: size.get(),
                    }
                    .into_pyobject(py)?,
                )?;
            }
            ParameterType::Plaintext { bit_width, value } => {
                result.append(
                    PyWirePlaintext {
                        value,
                        bit_width: bit_width.into(),
                    }
                    .into_pyobject(py)?,
                )?;
            }
            ParameterType::PlaintextArray { bit_width, values } => {
                result.append(
                    PyWirePlaintextArray {
                        values,
                        bit_width: bit_width.into(),
                    }
                    .into_pyobject(py)?,
                )?;
            }
        }
    }

    Ok(result.into())
}

/// Deserialize versioned output bytes to a list of Ciphertext objects.
///
/// Accepts MessagePack bytes containing a VersionedOutput struct and returns
/// a list of PyCiphertext objects.
///
/// Args:
///     bytes: MessagePack-serialized VersionedOutput
///
/// Returns:
///     List of Ciphertext objects
///
/// Raises:
///     ValueError: If version is not supported or deserialization fails
#[pyfunction]
pub fn deserialize_outputs(py: Python<'_>, bytes: &[u8]) -> PyResult<Py<PyList>> {
    let versioned: VersionedOutput = from_msgpack(bytes)?;

    if versioned.version != OUTPUT_VERSION {
        return Err(value_error(format!(
            "unsupported output version {}, expected {}",
            versioned.version, OUTPUT_VERSION
        )));
    }

    let result = PyList::empty(py);
    for ct_with_bw in versioned.outputs {
        let ciphertext = PyCiphertext::from_wire_format(ct_with_bw);
        result.append(ciphertext.into_pyobject(py)?)?;
    }

    Ok(result.into())
}
