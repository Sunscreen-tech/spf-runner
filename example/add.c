// Add two encrypted 8-bit unsigned integers.

#include <parasol.h>

[[clang::fhe_program]] void add(
    [[clang::encrypted]] uint8_t a,
    [[clang::encrypted]] uint8_t b,
    [[clang::encrypted]] uint8_t *out
) {
    *out = a + b;
}
