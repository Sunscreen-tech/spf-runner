//! Command-line argument parsing.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
pub(crate) struct Args {
    /// Path to the compiled FHE program ELF file.
    #[arg(short, long)]
    pub elf: PathBuf,

    /// Function name to execute within the ELF.
    #[arg(short, long)]
    pub func: String,

    /// Path to the compute key file.
    #[arg(short, long)]
    pub key: PathBuf,

    /// Parameters file. If not specified, reads from stdin.
    #[arg(short, long)]
    pub params: Option<PathBuf>,

    /// Output file. If not specified, writes to stdout.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}
