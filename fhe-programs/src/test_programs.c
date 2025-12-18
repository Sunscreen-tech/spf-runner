// FHE test programs for sunscreen_fhe E2E tests.
// Compile with: clang -target parasol -O2 test_programs.c -o test_programs

#include <parasol.h>

// Increment a u16 value (used by program_runner Rust tests)
[[clang::fhe_program]] void inc(
    [[clang::encrypted]] uint16_t a,
    [[clang::encrypted]] uint16_t *out
) {
    *out = a + 1;
}

// Add two u8 values
[[clang::fhe_program]] void add_u8(
    [[clang::encrypted]] uint8_t a,
    [[clang::encrypted]] uint8_t b,
    [[clang::encrypted]] uint8_t *out
) {
    *out = a + b;
}

// Add two i8 values (signed)
[[clang::fhe_program]] void add_i8(
    [[clang::encrypted]] int8_t a,
    [[clang::encrypted]] int8_t b,
    [[clang::encrypted]] int8_t *out
) {
    *out = a + b;
}

// Sum an array of 4 u8 values
[[clang::fhe_program]] void sum_array_u8(
    [[clang::encrypted]] uint8_t *arr,
    [[clang::encrypted]] uint16_t *out
) {
    uint16_t sum = 0;
    for (int i = 0; i < 4; i++) {
        sum += arr[i];
    }
    *out = sum;
}

// Element-wise add of two 4-element arrays
[[clang::fhe_program]] void add_arrays_u8(
    [[clang::encrypted]] uint8_t *a,
    [[clang::encrypted]] uint8_t *b,
    [[clang::encrypted]] uint8_t *out
) {
    for (int i = 0; i < 4; i++) {
        out[i] = a[i] + b[i];
    }
}

// Mixed plaintext/ciphertext: scale a ciphertext by a plaintext
[[clang::fhe_program]] void scale_u8(
    [[clang::encrypted]] uint8_t ct,
    uint8_t scale,
    [[clang::encrypted]] uint16_t *out
) {
    *out = (uint16_t)ct * (uint16_t)scale;
}

// 16-bit operations

// Add two u16 values
[[clang::fhe_program]] void add_u16(
    [[clang::encrypted]] uint16_t a,
    [[clang::encrypted]] uint16_t b,
    [[clang::encrypted]] uint16_t *out
) {
    *out = a + b;
}

// Add two i16 values (signed)
[[clang::fhe_program]] void add_i16(
    [[clang::encrypted]] int16_t a,
    [[clang::encrypted]] int16_t b,
    [[clang::encrypted]] int16_t *out
) {
    *out = a + b;
}

// 32-bit operations

// Add two u32 values
[[clang::fhe_program]] void add_u32(
    [[clang::encrypted]] uint32_t a,
    [[clang::encrypted]] uint32_t b,
    [[clang::encrypted]] uint32_t *out
) {
    *out = a + b;
}

// Add two i32 values (signed)
[[clang::fhe_program]] void add_i32(
    [[clang::encrypted]] int32_t a,
    [[clang::encrypted]] int32_t b,
    [[clang::encrypted]] int32_t *out
) {
    *out = a + b;
}

// 64-bit operations

// Add two u64 values
[[clang::fhe_program]] void add_u64(
    [[clang::encrypted]] uint64_t a,
    [[clang::encrypted]] uint64_t b,
    [[clang::encrypted]] uint64_t *out
) {
    *out = a + b;
}

// Add two i64 values (signed)
[[clang::fhe_program]] void add_i64(
    [[clang::encrypted]] int64_t a,
    [[clang::encrypted]] int64_t b,
    [[clang::encrypted]] int64_t *out
) {
    *out = a + b;
}
