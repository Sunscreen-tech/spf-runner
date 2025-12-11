use std::process::Command;

use program_runner::deserialize_outputs;

mod setup;

#[test]
fn test_inc() {
    let setup = setup::setup();
    let result_path = setup.test_dir.path().join("result.bin");

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(setup::test_programs_elf())
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(setup.compute_key_path)
        .arg("--params")
        .arg(setup.params_path)
        .arg("--output")
        .arg(&result_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result_bytes = std::fs::read(&result_path).unwrap();
    let outputs = deserialize_outputs(&result_bytes).unwrap();

    assert_eq!(outputs.len(), 1);

    let ct = &outputs[0];
    let result: u64 = setup
        .enc
        .decrypt_glwe_l1(&ct.ciphertext, &setup.secret_key)
        .coeffs()
        .iter()
        .take(ct.bit_width as usize)
        .enumerate()
        .map(|(i, &v)| v << i)
        .sum();

    assert_eq!(result, setup.value + 1);
}

#[test]
fn test_inc_stdout() {
    let setup = setup::setup();

    let output = Command::new(env!("CARGO_BIN_EXE_program_runner"))
        .arg("--elf")
        .arg(setup::test_programs_elf())
        .arg("--func")
        .arg("inc")
        .arg("--key")
        .arg(setup.compute_key_path)
        .arg("--params")
        .arg(setup.params_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Output should be written to stdout
    let outputs = deserialize_outputs(&output.stdout).unwrap();

    assert_eq!(outputs.len(), 1);

    let ct = &outputs[0];
    let result: u64 = setup
        .enc
        .decrypt_glwe_l1(&ct.ciphertext, &setup.secret_key)
        .coeffs()
        .iter()
        .take(ct.bit_width as usize)
        .enumerate()
        .map(|(i, &v)| v << i)
        .sum();

    assert_eq!(result, setup.value + 1);
}
