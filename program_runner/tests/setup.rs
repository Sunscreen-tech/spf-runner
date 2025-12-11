use std::{fs::write, num::NonZeroU32, path::PathBuf};

use parasol_runtime::{ComputeKey, DEFAULT_128, Encryption, SecretKey, fluent::PackedUInt16};
use program_runner::{BitWidth, L1GlweCiphertextWithBitWidth, ParameterType, serialize_parameters};
use rand::{RngCore, rng};
use tempfile::TempDir;

/// Path to the compiled test_programs ELF containing all test FHE functions.
/// Source: fhe-programs/src/test_programs.c
pub fn test_programs_elf() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("fhe-programs/compiled/test_programs")
}

// they are all used in the "success case" but not the "failure one"
// so rustc/clippy/etc complains
#[allow(unused)]
pub struct TestSetup {
    pub value: u64,
    pub enc: Encryption,
    pub secret_key: SecretKey,
    pub compute_key_path: PathBuf,
    pub params_path: PathBuf,
    pub test_dir: TempDir,
}

pub fn setup() -> TestSetup {
    let test_dir = TempDir::new().unwrap();
    let value = rng().next_u32() as u16 as u64;

    let enc = Encryption::new(&DEFAULT_128);
    let secret_key = SecretKey::generate(&DEFAULT_128);
    let compute_key = ComputeKey::generate(&secret_key, &DEFAULT_128);

    let params = vec![
        ParameterType::Ciphertext {
            content: L1GlweCiphertextWithBitWidth {
                bit_width: BitWidth::U16,
                ciphertext: PackedUInt16::encrypt_secret(value as u128, &enc, &secret_key).inner(),
            },
        },
        ParameterType::OutputCiphertextArray {
            bit_width: BitWidth::U16,
            size: NonZeroU32::new(1).unwrap(),
        },
    ];

    let compute_key_path = test_dir.path().join("computation.key");
    write(&compute_key_path, rmp_serde::to_vec(&compute_key).unwrap()).unwrap();

    let params_path = test_dir.path().join("params");
    write(&params_path, serialize_parameters(&params).unwrap()).unwrap();

    TestSetup {
        value,
        enc,
        secret_key,
        compute_key_path,
        params_path,
        test_dir,
    }
}
