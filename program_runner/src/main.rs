use std::{
    fs::{read, write},
    io::{self, Read, Write},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Result, anyhow};
use clap::Parser;
use log::info;
use parasol_cpu::{ArgsBuilder, FheComputer, Memory, RunProgramOptionsBuilder};
use parasol_runtime::{
    DEFAULT_128, Encryption, Evaluation, L1GlweCiphertext, Params,
    fluent::{DynamicUInt, PackedDynamicUInt},
};
use program_runner::{
    BitWidth, L1GlweCiphertextWithBitWidth, ParameterType, deserialize_parameters,
    serialize_outputs,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    elf: PathBuf,

    #[arg(short, long)]
    func: String,

    #[arg(short, long)]
    key: PathBuf,

    /// Parameters file. If not specified, reads from stdin.
    #[arg(short, long)]
    params: Option<PathBuf>,

    /// Output file. If not specified, writes to stdout.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

static PARAMS: Params = DEFAULT_128;

fn charged_unpack(
    proc: &mut FheComputer,
    ct: L1GlweCiphertextWithBitWidth,
    gas_used: &mut u32,
) -> Result<(DynamicUInt<L1GlweCiphertext>, BitWidth)> {
    let bit_width_u32 = u32::from(ct.bit_width);
    let gas_use =
        ((6_u32.pow(ct.bit_width.byte_width().ilog2()) as f64 / 600.0 + 1.0) * 56280.0) as u32;
    *gas_used += gas_use;
    info!(
        "Ciphertext unpacking consumes {gas_use} gas and the accumulated gas consumption is {gas_used}"
    );
    let unpacked = proc
        .unpack_int_dyn(PackedDynamicUInt::from((bit_width_u32, ct.ciphertext)))
        .map_err(|e| anyhow!("ciphertext unpacking fails in circuit running due to: {e}"))?;
    Ok((unpacked, ct.bit_width))
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let mut gas_used = 0;
    info!("Initial gas consumption set as {gas_used}");

    // set up program
    let elf_bytes = read(&args.elf)
        .map_err(|e| anyhow!("failed to read ELF file '{}': {e}", args.elf.display()))?;
    let memory = Arc::new(
        Memory::new_from_elf(&elf_bytes)
            .map_err(|e| anyhow!("failed to parse ELF file '{}': {e}", args.elf.display()))?,
    );
    let func = memory.get_function_entry(&args.func).ok_or(anyhow!(
        "function '{}' does not exist in ELF file '{}'",
        args.func,
        args.elf.display()
    ))?;
    info!(
        "Successfully loaded function '{}' from ELF file '{}'.",
        args.func,
        args.elf.display()
    );

    // set up computer
    let compute_key_bytes = read(&args.key)
        .map_err(|e| anyhow!("failed to read key file '{}': {e}", args.key.display()))?;
    let compute_key = rmp_serde::from_slice(&compute_key_bytes).map_err(|e| {
        anyhow!(
            "failed to deserialize from key file '{}': {e}",
            args.key.display()
        )
    })?;

    let enc = Encryption::new(&PARAMS);
    let eval = Evaluation::new(Arc::new(compute_key), &DEFAULT_128, &enc);
    let mut proc = FheComputer::new(&enc, &eval);

    info!(
        "Successfully created processor using key file '{}' and parameters '{:#?}'",
        args.key.display(),
        PARAMS
    );

    // prepare args and unpack ciphertexts with gas charging
    let parameters_bytes = match &args.params {
        Some(path) => read(path)
            .map_err(|e| anyhow!("failed to read parameters file '{}': {e}", path.display()))?,
        None => {
            let mut buffer = Vec::new();
            io::stdin()
                .read_to_end(&mut buffer)
                .map_err(|e| anyhow!("failed to read parameters from stdin: {e}"))?;
            buffer
        }
    };
    let params_source = match &args.params {
        Some(path) => path.display().to_string(),
        None => "stdin".to_string(),
    };
    let parameters = deserialize_parameters(&parameters_bytes).map_err(|e| {
        anyhow!(
            "failed to deserialize parameters from '{}': {e}",
            params_source
        )
    })?;

    let mut args_builder = ArgsBuilder::new();
    let mut output_buffers = Vec::new();
    let mut total_result_byte_width = 0;
    for parameter in parameters {
        match parameter {
            ParameterType::Ciphertext { content } => {
                let (unpacked, _) = charged_unpack(&mut proc, content, &mut gas_used)?;
                args_builder = args_builder.arg_dyn(unpacked);
            }
            ParameterType::CiphertextArray { contents } => {
                if contents.is_empty() {
                    return Err(anyhow!("empty ciphertext array"));
                }

                let mut first_bit_width: Option<BitWidth> = None;
                let mut unpacked = Vec::new();

                for content in contents {
                    let (ct, bw) = charged_unpack(&mut proc, content, &mut gas_used)?;
                    unpacked.push(ct);
                    match first_bit_width {
                        None => first_bit_width = Some(bw),
                        Some(expected) => {
                            if expected != bw {
                                return Err(anyhow!(
                                    "inconsistent bit width in ciphertext array, first saw {} then saw {}",
                                    u8::from(expected),
                                    u8::from(bw)
                                ));
                            }
                        }
                    }
                }

                // Safe: we checked contents.is_empty() above, so at least one element was processed
                let bit_width = first_bit_width.unwrap();
                let byte_width = bit_width.byte_width();
                let byte_len = unpacked.len() as u32 * byte_width;
                let ptr = memory
                    .try_allocate(byte_len)
                    .map_err(|e| anyhow!("memory allocation failure due to {e}"))?;
                args_builder = args_builder.arg(ptr);

                for (i, val) in unpacked.iter().enumerate() {
                    memory
                        .try_write_type_dyn(
                            ptr.try_offset(i as u32 * byte_width)
                                .map_err(|e| anyhow!("pointer arithmetic failure due to {e}"))?,
                            val,
                        )
                        .map_err(|e| anyhow!("memory access failure due to {e}"))?;
                }
            }
            ParameterType::OutputCiphertextArray { bit_width, size } => {
                let byte_width = bit_width.byte_width();
                let total_byte_width = byte_width * size.get();
                let buf = memory
                    .try_allocate(total_byte_width)
                    .map_err(|e| anyhow!("memory allocation failure due to {e}"))?;
                args_builder = args_builder.arg(buf);

                total_result_byte_width += total_byte_width;
                output_buffers.push((buf, bit_width, size));
            }
            ParameterType::Plaintext { bit_width, value } => match bit_width {
                BitWidth::U8 => args_builder = args_builder.arg(value as u8),
                BitWidth::U16 => args_builder = args_builder.arg(value as u16),
                BitWidth::U32 => args_builder = args_builder.arg(value as u32),
                BitWidth::U64 => args_builder = args_builder.arg(value),
            },
            ParameterType::PlaintextArray { bit_width, values } => {
                let byte_width = bit_width.byte_width();
                let ptr = memory
                    .try_allocate(values.len() as u32 * byte_width)
                    .map_err(|e| anyhow!("memory allocation failure due to {e}"))?;
                args_builder = args_builder.arg(ptr);

                for (i, val) in values.into_iter().enumerate() {
                    let p = ptr
                        .try_offset(i as u32 * byte_width)
                        .map_err(|e| anyhow!("pointer arithmetic failure due to {e}"))?;

                    match bit_width {
                        BitWidth::U8 => memory
                            .try_write_type(p, &(val as u8))
                            .map_err(|e| anyhow!("memory access failure due to {e}"))?,
                        BitWidth::U16 => memory
                            .try_write_type(p, &(val as u16))
                            .map_err(|e| anyhow!("memory access failure due to {e}"))?,
                        BitWidth::U32 => memory
                            .try_write_type(p, &(val as u32))
                            .map_err(|e| anyhow!("memory access failure due to {e}"))?,
                        BitWidth::U64 => memory
                            .try_write_type(p, &val)
                            .map_err(|e| anyhow!("memory access failure due to {e}"))?,
                    };
                }
            }
        }
    }

    // run program
    let opt = RunProgramOptionsBuilder::new().gas_limit(None).build();
    let (gas_use, _) = proc
        .run_program_with_options(func, &memory, args_builder.no_return_value(), &opt)
        .map_err(|e| anyhow!("program execution fails due to processor error: {e}"))?;
    gas_used += gas_use;
    info!(
        "Program running consumes {gas_use} gas and the accumulated gas consumption is {gas_used}"
    );

    // parse output parameters and collect all ciphertexts
    let mut outputs = Vec::new();
    for (ptr, bit_width, size) in output_buffers {
        let byte_width = bit_width.byte_width();
        for i in 0..size.get() {
            let val = memory
                .try_load_type_dyn::<DynamicUInt<_>>(
                    ptr.try_offset(byte_width * i)
                        .map_err(|e| anyhow!("pointer arithmetic failure due to {e}"))?,
                    byte_width as usize,
                    byte_width as usize,
                )
                .map_err(|e| anyhow!("memory access failure due to {e}"))?;

            let ct = L1GlweCiphertextWithBitWidth {
                bit_width,
                ciphertext: proc
                    .pack_int_dyn(val)
                    .map_err(|e| {
                        anyhow!("ciphertext packing fails in circuit running due to: {e}")
                    })?
                    .inner(),
            };

            outputs.push(ct);
        }
    }

    // serialize versioned output
    let output_bytes =
        serialize_outputs(&outputs).map_err(|e| anyhow!("failed to serialize output: {e}"))?;

    // write to file or stdout
    match &args.output {
        Some(path) => {
            write(path, &output_bytes)
                .map_err(|e| anyhow!("Failed to write output file '{}': {e}", path.display()))?;
        }
        None => {
            io::stdout()
                .write_all(&output_bytes)
                .map_err(|e| anyhow!("Failed to write to stdout: {e}"))?;
        }
    }

    let gas_use = total_result_byte_width * 320;
    gas_used += gas_use;
    info!(
        "Result ciphertext packing consumes {gas_use} gas and the accumulated gas consumption is {gas_used}"
    );

    Ok(())
}
