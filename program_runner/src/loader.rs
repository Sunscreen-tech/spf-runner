//! ELF and key file loading.

use std::{fs::read, path::Path, sync::Arc};

use anyhow::{Context, Result, anyhow};
use parasol_cpu::{Memory, Ptr32};
use parasol_runtime::ComputeKey;

/// Load an ELF file and look up a function entry point.
pub(crate) fn load_elf_function(elf_path: &Path, func_name: &str) -> Result<(Arc<Memory>, Ptr32)> {
    let elf_bytes = read(elf_path)
        .with_context(|| format!("failed to read ELF file '{}'", elf_path.display()))?;
    let memory = Arc::new(
        Memory::new_from_elf(&elf_bytes)
            .with_context(|| format!("failed to parse ELF file '{}'", elf_path.display()))?,
    );
    let func = memory.get_function_entry(func_name).ok_or_else(|| {
        anyhow!(
            "function '{}' does not exist in ELF file '{}'",
            func_name,
            elf_path.display()
        )
    })?;
    Ok((memory, func))
}

/// Load and deserialize a compute key from a file.
pub(crate) fn load_compute_key(key_path: &Path) -> Result<ComputeKey> {
    let compute_key_bytes = read(key_path)
        .with_context(|| format!("failed to read key file '{}'", key_path.display()))?;
    rmp_serde::from_slice(&compute_key_bytes).with_context(|| {
        format!(
            "failed to deserialize from key file '{}'",
            key_path.display()
        )
    })
}
