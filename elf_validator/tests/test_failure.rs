use std::{path::Path, process::Command};

#[test]
fn test_elf_file_not_present() {
    let not_present_elf = "tests/data/no.such.program";

    let output = Command::new(env!("CARGO_BIN_EXE_elf_validator"))
        .arg("--elf-path")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(not_present_elf))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(err_msg.contains("failed to read ELF file") && err_msg.contains(not_present_elf));
}

#[test]
fn test_elf_file_not_valid() {
    let not_valid_elf = "tests/data/illegal.program";

    let output = Command::new(env!("CARGO_BIN_EXE_elf_validator"))
        .arg("--elf-path")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(not_valid_elf))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(err_msg.contains("failed to parse ELF file") && err_msg.contains(not_valid_elf));
}
