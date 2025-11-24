use std::{fs::write, path::Path, process::Command};

use program_runner::VersionedParameters;

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

    // Create params with an unsupported version
    let bad_versioned_params = VersionedParameters {
        version: 999, // unsupported version
        parameters: vec![],
    };
    write(
        &setup.params_path,
        rmp_serde::to_vec(&bad_versioned_params).unwrap(),
    )
    .unwrap();

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
        err_msg.contains("unsupported parameters version 999"),
        "Expected version mismatch error, got: {err_msg}"
    );
}
