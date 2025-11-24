# tfhe-client

Python client for FHE program runner.

## Installation

```bash
pip install tfhe-client
```

## Usage

```python
from tfhe_client import KeySet, ParameterBuilder, read_outputs

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

# Save compute key for server
from pathlib import Path
Path("computation.key").write_bytes(keys.compute_key.to_bytes())

# Run the FHE program (params via stdin, output via stdout)
import subprocess
result = subprocess.run(
    ["program_runner", "-e", "program.elf", "-f", "add_u8", "-k", "computation.key"],
    input=params.to_bytes(),
    capture_output=True, check=True
)

# Decrypt outputs
outputs = read_outputs(result.stdout)
decrypted = keys.decrypt(outputs[0], signed=False)
```

## Development

This is a PyO3 extension module built with maturin.

### With Nix (recommended)

The Nix development shell provides all required dependencies.

```bash
# Enter the Nix development shell (from repository root)
nix develop

# Run all tests (builds everything automatically)
make test-python

# Or run steps individually:
uv sync
maturin develop --release
uv run pytest tests/ -v
```

### Without Nix

Prerequisites:

- Python 3.10+
- Rust toolchain ([rustup.rs](https://rustup.rs))

Note: E2E tests require the FHE test programs which need the Parasol compiler (Nix only). Without Nix, E2E tests will be skipped automatically.

Using uv (recommended):

```bash
# Install uv if needed: https://docs.astral.sh/uv/getting-started/installation/

# From tfhe_client directory:
uv sync
uv run maturin develop --release
uv run pytest tests/ -v
```

Using pip/venv:

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install maturin and dev dependencies
pip install maturin pytest pytest-cov

# Build and install the extension module
maturin develop --release

# Run tests
pytest tests/ -v
```

### Testing Notes

PyO3 extension modules cannot be tested with `cargo test` directly because they are shared libraries designed to be loaded by Python. The linker cannot resolve Python symbols when building a standalone test binary. Always test via the `maturin develop` + `pytest` path shown above.

## License

MIT
