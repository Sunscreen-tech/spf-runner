"""Python client for FHE program runner.

Provides key generation, encryption, decryption, and parameter building for
fully homomorphic encryption (FHE) operations.

Example::

    from pathlib import Path
    import subprocess
    import tempfile
    from tfhe_client import KeySet, ParameterBuilder, read_outputs

    # Generate keys
    keys = KeySet.generate()

    # Build parameters: encrypt two 8-bit values, declare one 8-bit output
    params = (
        ParameterBuilder()
        .encrypt(100, 8, signed=False)
        .encrypt(50, 8, signed=False)
        .output(8, 1)
        .build(keys.public_key)
    )

    # Save inputs for program_runner
    with tempfile.TemporaryDirectory() as job_dir:
        job_path = Path(job_dir)
        job_path.joinpath("computation.key").write_bytes(
            keys.compute_key.to_bytes()
        )
        job_path.joinpath("params").write_bytes(params.to_bytes())

        # Run the FHE program
        result = subprocess.run(
            [
                "program_runner",
                "-e", "program.elf",
                "-f", "add_u8",
                "-k", str(job_path / "computation.key"),
                "-p", str(job_path / "params"),
            ],
            capture_output=True,
            check=True,
        )

        # Decrypt outputs
        outputs = read_outputs(result.stdout)
        result_value = keys.decrypt(outputs[0], signed=False)
"""

from tfhe_client._native import (
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
from tfhe_client.builder import ParameterBuilder
from tfhe_client.outputs import read_outputs
from tfhe_client.parameters import (
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
