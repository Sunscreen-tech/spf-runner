use std::fs::read;

use anyhow::{Result, anyhow};
use clap::Parser;
use parasol_cpu::Memory;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    elf_path: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let elf_bytes = read(&args.elf_path)
        .map_err(|e| anyhow!("failed to read ELF file '{}': {e}", args.elf_path))?;
    Memory::new_from_elf(&elf_bytes)
        .map_err(|e| anyhow!("failed to parse ELF file '{}': {e}", args.elf_path))?;

    Ok(())
}
