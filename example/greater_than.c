// Add two encrypted 8-bit unsigned integers.

#include <parasol.h>

[[clang::fhe_program]] void greater_than(
    [[clang::encrypted]] uint8_t a,
    [[clang::encrypted]] uint8_t b,
    [[clang::encrypted]] bool *out
) {
    *out = a > b;
}
