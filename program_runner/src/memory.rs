//! Memory allocation and ciphertext operations.

use std::num::NonZeroU32;

use anyhow::{Context, Result, anyhow};
use parasol_cpu::{FheComputer, Memory, Ptr32};
use parasol_runtime::{
    L1GlweCiphertext,
    fluent::{DynamicUInt, PackedDynamicUInt},
};
use program_runner::{
    BitWidth, CIPHERTEXT_UNPACK_BASE_UNIT_COST, CIPHERTEXT_UNPACK_EXPONENTIAL_BASE_COST,
    CIPHERTEXT_UNPACK_MULTIPLIER_COST, CIPHERTEXT_UNPACK_NORMALIZER_COST,
    L1GlweCiphertextWithBitWidth,
};

use crate::gas::GasTracker;

/// Output buffer descriptor for collecting results after program execution.
pub(crate) struct OutputBuffer {
    /// Memory location of the output array.
    pub ptr: Ptr32,
    /// Bit width of each element in the output array.
    pub bit_width: BitWidth,
    /// Number of elements in the output array.
    pub size: NonZeroU32,
}

/// Unpack a ciphertext with gas tracking.
pub(crate) fn charged_unpack(
    proc: &mut FheComputer,
    ct: L1GlweCiphertextWithBitWidth,
    gas: &mut GasTracker,
) -> Result<(DynamicUInt<L1GlweCiphertext>, BitWidth)> {
    let bit_width_u32 = u32::from(ct.bit_width);
    // Gas cost formula: ((base^log2(byte_width) / normalizer) + base_unit) * multiplier
    let gas_cost = ((CIPHERTEXT_UNPACK_EXPONENTIAL_BASE_COST.pow(ct.bit_width.byte_width().ilog2())
        as f64
        / CIPHERTEXT_UNPACK_NORMALIZER_COST
        + CIPHERTEXT_UNPACK_BASE_UNIT_COST)
        * CIPHERTEXT_UNPACK_MULTIPLIER_COST) as u32;
    gas.charge(gas_cost, "Ciphertext unpacking");
    let unpacked = proc
        .unpack_int_dyn(PackedDynamicUInt::from((bit_width_u32, ct.ciphertext)))
        .context("failed to unpack ciphertext")?;
    Ok((unpacked, ct.bit_width))
}

/// Write a plaintext value to memory at the given pointer with the specified bit width.
pub(crate) fn write_plaintext_to_memory(
    memory: &Memory,
    ptr: Ptr32,
    bit_width: BitWidth,
    value: u64,
) -> Result<()> {
    let max_value = bit_width.max_unsigned();
    if value > max_value {
        return Err(anyhow!(
            "plaintext value {} exceeds maximum for bit width {} (max: {})",
            value,
            u8::from(bit_width),
            max_value
        ));
    }

    match bit_width {
        BitWidth::U8 => memory
            .try_write_type(ptr, &(value as u8))
            .context("failed to write plaintext value to memory"),
        BitWidth::U16 => memory
            .try_write_type(ptr, &(value as u16))
            .context("failed to write plaintext value to memory"),
        BitWidth::U32 => memory
            .try_write_type(ptr, &(value as u32))
            .context("failed to write plaintext value to memory"),
        BitWidth::U64 => memory
            .try_write_type(ptr, &value)
            .context("failed to write plaintext value to memory"),
    }
}

/// Unpack a ciphertext array, validate consistent bit widths, allocate memory, and write values.
pub(crate) fn process_ciphertext_array(
    contents: Vec<L1GlweCiphertextWithBitWidth>,
    proc: &mut FheComputer,
    memory: &Memory,
    gas: &mut GasTracker,
) -> Result<Ptr32> {
    if contents.is_empty() {
        return Err(anyhow!("empty ciphertext array"));
    }

    let mut first_bit_width: Option<BitWidth> = None;
    let mut unpacked = Vec::with_capacity(contents.len());

    for content in contents {
        let (ct, bw) = charged_unpack(proc, content, gas)?;
        unpacked.push(ct);
        match first_bit_width {
            None => first_bit_width = Some(bw),
            Some(expected) if expected != bw => {
                return Err(anyhow!(
                    "inconsistent bit width in ciphertext array, first saw {} then saw {}",
                    u8::from(expected),
                    u8::from(bw)
                ));
            }
            _ => {}
        }
    }

    let bit_width = first_bit_width.expect("bit_width must be set after non-empty loop");
    let byte_width = bit_width.byte_width();
    let ptr = memory
        .try_allocate(unpacked.len() as u32 * byte_width)
        .context("failed to allocate memory for ciphertext array")?;

    for (i, val) in unpacked.iter().enumerate() {
        memory
            .try_write_type_dyn(
                ptr.try_offset(i as u32 * byte_width)
                    .context("failed to compute offset for ciphertext array element")?,
                val,
            )
            .context("failed to write ciphertext to memory")?;
    }

    Ok(ptr)
}

/// Allocate memory for a plaintext array and write values.
pub(crate) fn process_plaintext_array(
    bit_width: BitWidth,
    values: Vec<u64>,
    memory: &Memory,
) -> Result<Ptr32> {
    let byte_width = bit_width.byte_width();
    let ptr = memory
        .try_allocate(values.len() as u32 * byte_width)
        .context("failed to allocate memory for plaintext array")?;

    for (i, val) in values.into_iter().enumerate() {
        let p = ptr
            .try_offset(i as u32 * byte_width)
            .context("failed to compute offset for plaintext array element")?;
        write_plaintext_to_memory(memory, p, bit_width, val)?;
    }

    Ok(ptr)
}

/// Load a value from memory and pack it as a single Packed ciphertext.
pub(crate) fn pack_output_element(
    memory: &Memory,
    proc: &mut FheComputer,
    ptr: Ptr32,
    bit_width: BitWidth,
) -> Result<L1GlweCiphertextWithBitWidth> {
    let byte_width = bit_width.byte_width();
    let val = memory
        .try_load_type_dyn::<DynamicUInt<_>>(ptr, byte_width as usize, byte_width as usize)
        .context("failed to read output from memory")?;

    Ok(L1GlweCiphertextWithBitWidth {
        bit_width,
        ciphertext: proc
            .pack_int_dyn(val)
            .context("failed to pack ciphertext")?
            .inner(),
    })
}

/// Collect outputs from memory buffers and pack them as ciphertexts.
pub(crate) fn collect_outputs(
    output_buffers: Vec<OutputBuffer>,
    memory: &Memory,
    proc: &mut FheComputer,
) -> Result<Vec<L1GlweCiphertextWithBitWidth>> {
    let total_outputs: usize = output_buffers.iter().map(|b| b.size.get() as usize).sum();
    let mut outputs = Vec::with_capacity(total_outputs);

    for OutputBuffer {
        ptr,
        bit_width,
        size,
    } in output_buffers
    {
        let byte_width = bit_width.byte_width();
        for i in 0..size.get() {
            let element_ptr = ptr
                .try_offset(byte_width * i)
                .context("failed to compute offset for output element")?;
            outputs.push(pack_output_element(memory, proc, element_ptr, bit_width)?);
        }
    }

    Ok(outputs)
}
