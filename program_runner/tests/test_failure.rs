use std::{fs::write, path::Path, process::Command};

use program_runner::PARAMETERS_MAGIC;

mod setup;

#[test]
fn test_elf_file_not_present() {
    let setup = setup::setup();
    let not_present_elf = setup::test_programs_elf()
        .parent()
        .unwrap()
        .join("no.such.program");

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(&not_present_elf)
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(setup.compute_key_path)
        .arg("--params")
        .arg(setup.params_path)
        .arg("--output")
        .arg(setup.test_dir.path().join("result.bin"))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("failed to read ELF file")
            && err_msg.contains(not_present_elf.to_str().unwrap())
    );
}

#[test]
fn test_elf_file_not_valid() {
    let setup = setup::setup();
    let not_valid_elf = "tests/data/illegal.program";

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(not_valid_elf))
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(setup.compute_key_path)
        .arg("--params")
        .arg(setup.params_path)
        .arg("--output")
        .arg(setup.test_dir.path().join("result.bin"))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(err_msg.contains("failed to parse ELF file") && err_msg.contains(not_valid_elf));
}

#[test]
fn test_elf_file_not_including_program() {
    let setup = setup::setup();
    let test_programs = setup::test_programs_elf();
    let not_included_function = "nonexistent_function";

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(&test_programs)
        .arg("--func")
        .arg(not_included_function)
        .arg("--key")
        .arg(setup.compute_key_path)
        .arg("--params")
        .arg(setup.params_path)
        .arg("--output")
        .arg(setup.test_dir.path().join("result.bin"))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains(&format!(
            "function '{not_included_function}' does not exist in ELF file"
        )) && err_msg.contains(test_programs.to_str().unwrap())
    );
}

#[test]
fn test_key_file_not_present() {
    let setup = setup::setup();
    let not_present_key = setup.compute_key_path.parent().unwrap().join("no.such.key");

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(setup::test_programs_elf())
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(&not_present_key)
        .arg("--params")
        .arg(setup.params_path)
        .arg("--output")
        .arg(setup.test_dir.path().join("result.bin"))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("failed to read key file")
            && err_msg.contains(not_present_key.to_str().unwrap())
    );
}

#[test]
fn test_key_file_not_valid() {
    let setup = setup::setup();
    write(&setup.compute_key_path, "NOT_A_VALID_KEY_FILE").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(setup::test_programs_elf())
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(&setup.compute_key_path)
        .arg("--params")
        .arg(setup.params_path)
        .arg("--output")
        .arg(setup.test_dir.path().join("result.bin"))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("failed to deserialize from key file")
            && err_msg.contains(setup.compute_key_path.to_str().unwrap()),
    );
}

#[test]
fn test_params_file_not_present() {
    let setup = setup::setup();
    let not_present_params = setup
        .compute_key_path
        .parent()
        .unwrap()
        .join("no.such.params");

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(setup::test_programs_elf())
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(setup.compute_key_path)
        .arg("--params")
        .arg(&not_present_params)
        .arg("--output")
        .arg(setup.test_dir.path().join("result.bin"))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("failed to read parameters file")
            && err_msg.contains(not_present_params.to_str().unwrap())
    );
}

#[test]
fn test_params_file_not_valid() {
    let setup = setup::setup();
    write(&setup.params_path, "NOT_A_VALID_PARAMETERS_FILE").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(setup::test_programs_elf())
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(setup.compute_key_path)
        .arg("--params")
        .arg(&setup.params_path)
        .arg("--output")
        .arg(setup.test_dir.path().join("result.bin"))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("failed to deserialize parameters from")
            && err_msg.contains(setup.params_path.to_str().unwrap()),
    );
}

#[test]
fn test_params_version_mismatch() {
    let setup = setup::setup();

    // Create params with an unsupported version using the wire format:
    // [MAGIC: 4 bytes][VERSION: 4 bytes big-endian u32][PAYLOAD: msgpack]
    let mut bad_params = Vec::new();
    bad_params.extend_from_slice(&PARAMETERS_MAGIC);
    bad_params.extend_from_slice(&999u32.to_be_bytes());
    // Empty array payload
    bad_params.extend_from_slice(&rmp_serde::to_vec::<Vec<()>>(&vec![]).unwrap());

    write(&setup.params_path, &bad_params).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(setup::test_programs_elf())
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(setup.compute_key_path)
        .arg("--params")
        .arg(&setup.params_path)
        .arg("--output")
        .arg(setup.test_dir.path().join("result.bin"))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("unsupported version 999"),
        "Expected version mismatch error, got: {err_msg}"
    );
}

#[test]
fn test_params_invalid_magic() {
    let setup = setup::setup();

    // Create params with invalid magic bytes
    let mut bad_params = Vec::new();
    bad_params.extend_from_slice(b"BAAD"); // Wrong magic
    bad_params.extend_from_slice(&1u32.to_be_bytes());
    bad_params.extend_from_slice(&rmp_serde::to_vec::<Vec<()>>(&vec![]).unwrap());

    write(&setup.params_path, &bad_params).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(setup::test_programs_elf())
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(setup.compute_key_path)
        .arg("--params")
        .arg(&setup.params_path)
        .arg("--output")
        .arg(setup.test_dir.path().join("result.bin"))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("invalid magic bytes"),
        "Expected invalid magic error, got: {err_msg}"
    );
}

#[test]
fn test_params_truncated_header() {
    let setup = setup::setup();

    // Create params that are too short (only 3 bytes)
    write(&setup.params_path, b"SPF").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(setup::test_programs_elf())
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(setup.compute_key_path)
        .arg("--params")
        .arg(&setup.params_path)
        .arg("--output")
        .arg(setup.test_dir.path().join("result.bin"))
        .output()
        .unwrap();

    assert!(!output.status.success());

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("data too short"),
        "Expected truncated header error, got: {err_msg}"
    );
}
