# SPF Runner

Tools for running FHE programs using Sunscreens [Secure Processing Framework (SPF)](https://github.com/sunscreen-tech/spf). Includes a Python client for encryption/decryption and a program runner for local or server-side execution.

## Prerequisites

### Option A: Manual installation

- [Rust](https://rustup.rs/) (stable toolchain)
- [Python 3.10+](https://www.python.org/)
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [maturin](https://www.maturin.rs/) (PyO3 build tool)
- [Sunscreen LLVM](https://github.com/Sunscreen-tech/llvm-project/tree/sunscreen) (for compiling FHE programs)

Set the `LLVM_DIR` environment variable to the Sunscreen LLVM bin directory:

```sh
export LLVM_DIR=/path/to/sunscreen-llvm/bin
```

### Option B: Nix

Install [Nix](https://nixos.org/download.html) with flakes enabled. All dependencies are provided automatically.

```sh
# Enter the development shell (provides toolchain and sets LLVM_DIR)
nix develop
```

## Build

```sh
# Build all Rust crates
cargo build --release

# Compile FHE programs
make
```

## Test

```sh
# Run Rust tests
cargo test --release -p program_runner -p elf_validator

# Run Python client tests
make test-python
```

## Lint

```sh
cargo fmt
cargo clippy
uv run ruff check python/ tests/
uv run ruff format python/ tests/
```

## Components

| Crate            | Description                                                           |
| ---------------- | --------------------------------------------------------------------- |
| `elf_validator`  | Validates ELF binaries for the Parasol CPU                            |
| `program_runner` | Executes FHE programs with encrypted inputs                           |
| `tfhe_client`    | Python library for key generation, encryption, and parameter building |

## Usage

### Writing an FHE Program

FHE programs are written in C using Sunscreen's Parasol compiler attributes:

```c
// add.c
#include <parasol.h>

[[clang::fhe_program]] void add(
    [[clang::encrypted]] uint8_t a,
    [[clang::encrypted]] uint8_t b,
    [[clang::encrypted]] uint8_t *out
) {
    *out = a + b;
}
```

Compile with the Sunscreen LLVM toolchain:

```sh
$LLVM_DIR/clang -O2 -target parasol -o add add.c
```

### Running with Python

```python
import subprocess
from pathlib import Path
from tfhe_client import KeySet, ParameterBuilder, read_outputs

# Generate keys
keys = KeySet.generate()

# Build parameters: encrypt inputs and declare output
params = (
    ParameterBuilder()
    .encrypt(100, bit_width=8, signed=False)
    .encrypt(50, bit_width=8, signed=False)
    .output(bit_width=8, size=1)
    .build(keys.public_key)
)

# Save compute key
Path("compute.key").write_bytes(keys.compute_key.to_bytes())

# Run the FHE program
result = subprocess.run(
    ["program_runner", "-e", "add", "-f", "add", "-k", "compute.key"],
    input=params.to_bytes(),
    capture_output=True,
    check=True,
)

# Decrypt result
outputs = read_outputs(result.stdout)
print(keys.decrypt(outputs[0], signed=False))  # 150
```
