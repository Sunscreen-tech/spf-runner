// Compare two encrypted unsigned integers, producing an encrypted boolean.
// Defines greater_than_u{8,16,32,64} variants via macro.

#include <parasol.h>

#define DEFINE_GREATER_THAN(bits)                          \
    [[clang::fhe_program]] void greater_than_u##bits(      \
        [[clang::encrypted]] uint##bits##_t a,             \
        [[clang::encrypted]] uint##bits##_t b,             \
        [[clang::encrypted]] bool *out                     \
    ) {                                                    \
        *out = a > b;                                      \
    }

DEFINE_GREATER_THAN(8)
DEFINE_GREATER_THAN(16)
DEFINE_GREATER_THAN(32)
DEFINE_GREATER_THAN(64)
