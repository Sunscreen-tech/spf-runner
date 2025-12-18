//! FHE program runner binary.
//!
//! Executes FHE programs compiled for the Parasol CPU with encrypted inputs,
//! producing encrypted outputs. Tracks gas consumption for execution costs.

mod cli;
mod gas;
mod io;
mod loader;
mod memory;
mod processor;

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use log::info;
use parasol_cpu::FheComputer;
use parasol_runtime::{Encryption, Evaluation};
use program_runner::{
    BYTE_WIDTH_MULTIPLIER_COST, PARAMS, deserialize_parameters_payload, serialize_outputs,
};

use cli::Args;
use gas::GasTracker;
use io::{read_parameters, write_output};
use loader::{load_compute_key, load_elf_function};
use memory::collect_outputs;
use processor::{process_parameters, run_program};

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let mut gas = GasTracker::new();

    // Load ELF program and function entry point
    let (memory, func) = load_elf_function(&args.elf, &args.func)?;
    info!(
        "Successfully loaded function '{}' from ELF file '{}'.",
        args.func,
        args.elf.display()
    );

    // Initialize FHE processor with compute key
    let compute_key = load_compute_key(&args.key)?;
    let enc = Encryption::new(&PARAMS);
    let eval = Evaluation::new(Arc::new(compute_key), &PARAMS, &enc);
    let mut proc = FheComputer::new(&enc, &eval);
    info!(
        "Successfully created processor using key file '{}' and parameters '{:#?}'",
        args.key.display(),
        PARAMS
    );

    // Read and deserialize parameters
    let (parameters_bytes, params_source, version) = read_parameters(args.params.as_deref())?;
    let parameters = deserialize_parameters_payload(&parameters_bytes, version)
        .with_context(|| format!("failed to deserialize parameters from '{}'", params_source))?;

    // Process parameters and build function arguments
    let (args_builder, output_buffers, output_byte_width) =
        process_parameters(parameters, &mut proc, &memory, &mut gas)?;

    // Execute FHE program
    run_program(&mut proc, func, &memory, args_builder, &mut gas)?;

    // Collect and serialize outputs
    let outputs = collect_outputs(output_buffers, &memory, &mut proc)?;
    gas.charge(
        output_byte_width * BYTE_WIDTH_MULTIPLIER_COST,
        "Result ciphertext packing",
    );
    let output_bytes = serialize_outputs(&outputs).context("failed to serialize output")?;

    // Write results
    write_output(args.output.as_deref(), &output_bytes)?;

    Ok(())
}
