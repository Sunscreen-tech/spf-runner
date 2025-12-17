//! Parameter and output I/O operations.

use std::{
    fs::{File, write},
    io::{self, BufReader, Read, Write},
    path::Path,
};

use anyhow::{Context, Result};
use program_runner::{HEADER_SIZE, peek_parameters_version};

/// Read and validate parameters from a file, returning bytes and version.
fn read_parameters_from_file(path: &Path) -> Result<(Vec<u8>, u32)> {
    let file = File::open(path)
        .with_context(|| format!("failed to open parameters file '{}'", path.display()))?;
    let file_size = file
        .metadata()
        .with_context(|| {
            format!(
                "failed to get metadata for parameters file '{}'",
                path.display()
            )
        })?
        .len() as usize;
    let mut reader = BufReader::new(file);

    let mut header = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header).with_context(|| {
        format!(
            "failed to read header from parameters file '{}'",
            path.display()
        )
    })?;
    let version = peek_parameters_version(&header)
        .with_context(|| format!("invalid parameters header in '{}'", path.display()))?;

    let mut buffer = Vec::with_capacity(file_size);
    buffer.extend_from_slice(&header);
    reader.read_to_end(&mut buffer).with_context(|| {
        format!(
            "failed to read parameters payload from '{}'",
            path.display()
        )
    })?;
    Ok((buffer, version))
}

/// Read and validate parameters from stdin, returning bytes and version.
fn read_parameters_from_stdin() -> Result<(Vec<u8>, u32)> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    let mut header = [0u8; HEADER_SIZE];
    handle
        .read_exact(&mut header)
        .context("failed to read header from stdin")?;
    let version =
        peek_parameters_version(&header).context("invalid parameters header from stdin")?;

    let mut buffer = Vec::new();
    buffer.extend_from_slice(&header);
    handle
        .read_to_end(&mut buffer)
        .context("failed to read parameters payload from stdin")?;
    Ok((buffer, version))
}

/// Read parameters from file or stdin, returning bytes, source description, and version.
pub(crate) fn read_parameters(params_path: Option<&Path>) -> Result<(Vec<u8>, String, u32)> {
    match params_path {
        Some(path) => {
            let (bytes, version) = read_parameters_from_file(path)?;
            Ok((bytes, path.display().to_string(), version))
        }
        None => {
            let (bytes, version) = read_parameters_from_stdin()?;
            Ok((bytes, "stdin".to_string(), version))
        }
    }
}

/// Write output bytes to a file or stdout.
pub(crate) fn write_output(output_path: Option<&Path>, bytes: &[u8]) -> Result<()> {
    match output_path {
        Some(path) => {
            write(path, bytes)
                .with_context(|| format!("failed to write output file '{}'", path.display()))?;
        }
        None => {
            io::stdout()
                .write_all(bytes)
                .context("failed to write to stdout")?;
        }
    }
    Ok(())
}
