# Compiling a Parasol FHE Program

Compile a fully homomorphic encryption (FHE) program that adds two encrypted integers using the Parasol compiler.

## Download the compiler

Download the pre-built Parasol compiler for the target platform from the
[sunscreen-llvm releases](https://github.com/Sunscreen-tech/sunscreen-llvm/releases) page:

| Platform      | Filename                                           |
| ------------- | -------------------------------------------------- |
| Linux x86-64  | `parasol-compiler-linux-x86-64-2025-11-24.tar.gz`  |
| Linux aarch64 | `parasol-compiler-linux-aarch64-2025-11-24.tar.gz` |
| macOS aarch64 | `parasol-compiler-macos-aarch64-2025-11-24.tar.gz` |

```sh
# Download the compiler for Linux x86-64. Replace the filename for other
# platforms (see the table above).
curl -LO https://github.com/Sunscreen-tech/sunscreen-llvm/releases/download/v2025.11.24/parasol-compiler-linux-x86-64-2025-11-24.tar.gz

# Extract into a local directory. The tarball contains bin/ at the top level,
# so this creates parasol-compiler/bin/clang, ld.lld, etc.
mkdir parasol-compiler
tar xzf parasol-compiler-linux-x86-64-2025-11-24.tar.gz -C parasol-compiler
```

## The source code

`add.c` adds two encrypted `uint8_t` values and writes the result through an output pointer:

```c
#include <parasol.h>

// [[clang::fhe_program]] marks a function as an FHE circuit entry point.
// [[clang::encrypted]] marks a parameter as a ciphertext.
// Parameters without [[clang::encrypted]] are plaintext (server-known values).
// Outputs must use pointers; return values are not supported.
// parasol.h ships with the compiler toolchain.

[[clang::fhe_program]] void add(
    [[clang::encrypted]] uint8_t a,
    [[clang::encrypted]] uint8_t b,
    [[clang::encrypted]] uint8_t *out
) {
    *out = a + b;
}
```

## Compile

```sh
./parasol-compiler/bin/clang -O2 -target parasol -o add add.c
```

## Output

The resulting `add` file is a Parasol ELF binary, which can be used with the
SPF runner.
