"""Python client for FHE program runner.

Provides key generation, encryption, decryption, and parameter building for
fully homomorphic encryption (FHE) operations.

Example::

    import subprocess
    import tempfile
    from pathlib import Path
    from sunscreen_fhe import KeySet, ParameterBuilder, read_outputs

    # Generate keys
    keys = KeySet.generate()

    # Build parameters: encrypt two 8-bit values, declare one 8-bit output
    params = (
        ParameterBuilder()
        .encrypt(100, bit_width=8, signed=False)
        .encrypt(50, bit_width=8, signed=False)
        .output(bit_width=8, size=1)
        .build(keys.public_key)
    )

    # Save compute key for program_runner
    with tempfile.TemporaryDirectory() as job_dir:
        job_path = Path(job_dir)
        compute_key_path = job_path / "compute.key"
        compute_key_path.write_bytes(keys.compute_key.to_bytes())

        # Run the FHE program (params via stdin, output via stdout)
        result = subprocess.run(
            [
                "program_runner",
                "-e", "program.elf",
                "-f", "add_u8",
                "-k", str(compute_key_path),
            ],
            input=params.to_bytes(),
            capture_output=True,
            check=True,
        )

        # Decrypt outputs
        outputs = read_outputs(result.stdout)
        result_value = keys.decrypt(outputs[0], signed=False)  # 150
"""

from sunscreen_fhe._native import (
    Ciphertext,
    ComputeKey,
    KeySet,
    PublicKey,
    SecretKey,
    get_output_version,
    get_parameters_version,
    peek_output_version,
    peek_parameters_version,
)
from sunscreen_fhe.builder import ParameterBuilder
from sunscreen_fhe.outputs import read_outputs
from sunscreen_fhe.parameters import (
    CiphertextArrayParam,
    CiphertextParam,
    OutputParam,
    ParameterEntry,
    Parameters,
    PlaintextArrayParam,
    PlaintextParam,
)

__all__ = [
    # Key types
    "Ciphertext",
    "ComputeKey",
    "KeySet",
    "PublicKey",
    "SecretKey",
    # Parameter types
    "CiphertextArrayParam",
    "CiphertextParam",
    "OutputParam",
    "ParameterBuilder",
    "ParameterEntry",
    "Parameters",
    "PlaintextArrayParam",
    "PlaintextParam",
    # Functions
    "get_output_version",
    "get_parameters_version",
    "peek_output_version",
    "peek_parameters_version",
    "read_outputs",
]

__version__ = "0.1.0"
