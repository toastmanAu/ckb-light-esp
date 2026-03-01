// blake2b_ref.h — DEPRECATED stub, kept for backward compat with test_block_filter.cpp
// New code: use blake2b_real.h (real implementation, same API, host-safe).
//
// This stub returns zeroed output — only valid for tests that pre-compute
// expected values and don't rely on hash correctness.

#pragma once
#include <string.h>
#include <stdint.h>
#include <stddef.h>

static inline void blake2b_256_stub(const uint8_t*, size_t, uint8_t* out) {
    memset(out, 0, 32);
}
