//! Parameter processing and FHE execution setup.

use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::{Context, Result};
use parasol_cpu::{ArgsBuilder, FheComputer, Memory, Ptr32, RunProgramOptionsBuilder};
use program_runner::{BitWidth, L1GlweCiphertextWithBitWidth, ParameterType};

use crate::gas::GasTracker;
use crate::memory::{
    OutputBuffer, charged_unpack, process_ciphertext_array, process_plaintext_array,
};

/// Execute an FHE program with gas tracking.
pub(crate) fn run_program(
    proc: &mut FheComputer,
    func: Ptr32,
    memory: &Arc<Memory>,
    args_builder: ArgsBuilder,
    gas: &mut GasTracker,
) -> Result<()> {
    let opt = RunProgramOptionsBuilder::new().gas_limit(None).build();
    let (gas_cost, _) = proc
        .run_program_with_options(func, memory, args_builder.no_return_value(), &opt)
        .context("program execution failed")?;
    gas.charge(gas_cost, "Program running");
    Ok(())
}

/// Accumulator for processing parameters.
struct Accumulator {
    args_builder: ArgsBuilder,
    output_buffers: Vec<OutputBuffer>,
    total_result_byte_width: u32,
}

impl Accumulator {
    fn new() -> Self {
        Self {
            args_builder: ArgsBuilder::new(),
            output_buffers: Vec::new(),
            total_result_byte_width: 0,
        }
    }

    fn into_results(self) -> (ArgsBuilder, Vec<OutputBuffer>, u32) {
        (
            self.args_builder,
            self.output_buffers,
            self.total_result_byte_width,
        )
    }
}

/// Process a single ciphertext parameter.
fn process_ciphertext(
    mut acc: Accumulator,
    content: L1GlweCiphertextWithBitWidth,
    proc: &mut FheComputer,
    gas: &mut GasTracker,
) -> Result<Accumulator> {
    let (unpacked, _) = charged_unpack(proc, content, gas)?;
    acc.args_builder = acc.args_builder.arg_dyn(unpacked);
    Ok(acc)
}

/// Process a ciphertext array parameter.
fn process_ciphertext_array_param(
    mut acc: Accumulator,
    contents: Vec<L1GlweCiphertextWithBitWidth>,
    proc: &mut FheComputer,
    memory: &Memory,
    gas: &mut GasTracker,
) -> Result<Accumulator> {
    let ptr = process_ciphertext_array(contents, proc, memory, gas)?;
    acc.args_builder = acc.args_builder.arg(ptr);
    Ok(acc)
}

/// Process an output buffer parameter.
fn process_output_buffer(
    mut acc: Accumulator,
    bit_width: BitWidth,
    size: NonZeroU32,
    memory: &Memory,
) -> Result<Accumulator> {
    let byte_width = bit_width.byte_width();
    let total_byte_width = byte_width * size.get();
    let ptr = memory
        .try_allocate(total_byte_width)
        .context("memory allocation failure")?;
    acc.args_builder = acc.args_builder.arg(ptr);

    acc.total_result_byte_width += total_byte_width;
    acc.output_buffers.push(OutputBuffer {
        ptr,
        bit_width,
        size,
    });
    Ok(acc)
}

/// Process a plaintext scalar parameter.
fn process_plaintext(mut acc: Accumulator, bit_width: BitWidth, value: u64) -> Result<Accumulator> {
    let max_value = bit_width.max_unsigned();
    if value > max_value {
        return Err(anyhow::anyhow!(
            "plaintext value {} exceeds maximum for bit width {} (max: {})",
            value,
            u8::from(bit_width),
            max_value
        ));
    }

    acc.args_builder = match bit_width {
        BitWidth::U8 => acc.args_builder.arg(value as u8),
        BitWidth::U16 => acc.args_builder.arg(value as u16),
        BitWidth::U32 => acc.args_builder.arg(value as u32),
        BitWidth::U64 => acc.args_builder.arg(value),
    };
    Ok(acc)
}

/// Process a plaintext array parameter.
fn process_plaintext_array_param(
    mut acc: Accumulator,
    bit_width: BitWidth,
    values: Vec<u64>,
    memory: &Memory,
) -> Result<Accumulator> {
    let ptr = process_plaintext_array(bit_width, values, memory)?;
    acc.args_builder = acc.args_builder.arg(ptr);
    Ok(acc)
}

/// Process a parameter and update the accumulator.
fn process_param(
    acc: Accumulator,
    parameter: ParameterType,
    proc: &mut FheComputer,
    memory: &Memory,
    gas: &mut GasTracker,
) -> Result<Accumulator> {
    match parameter {
        ParameterType::Ciphertext { content } => process_ciphertext(acc, content, proc, gas),
        ParameterType::CiphertextArray { contents } => {
            process_ciphertext_array_param(acc, contents, proc, memory, gas)
        }
        ParameterType::OutputCiphertextArray { bit_width, size } => {
            process_output_buffer(acc, bit_width, size, memory)
        }
        ParameterType::Plaintext { bit_width, value } => process_plaintext(acc, bit_width, value),
        ParameterType::PlaintextArray { bit_width, values } => {
            process_plaintext_array_param(acc, bit_width, values, memory)
        }
    }
}

/// Process parameters: unpack ciphertexts, allocate memory for arrays, and build function arguments.
pub(crate) fn process_parameters(
    parameters: Vec<ParameterType>,
    proc: &mut FheComputer,
    memory: &Memory,
    gas: &mut GasTracker,
) -> Result<(ArgsBuilder, Vec<OutputBuffer>, u32)> {
    parameters
        .into_iter()
        .try_fold(Accumulator::new(), |acc, param| {
            process_param(acc, param, proc, memory, gas)
        })
        .map(|acc| acc.into_results())
}
