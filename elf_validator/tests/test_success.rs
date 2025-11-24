use std::{path::Path, process::Command};

#[test]
fn test_inc() {
    let output = Command::new(env!("CARGO_BIN_EXE_elf_validator"))
        .arg("--elf-path")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/inc.program"))
        .output()
        .unwrap();

    assert!(output.status.success());
}
