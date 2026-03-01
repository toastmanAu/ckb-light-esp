#pragma once
// blake2b_real.h — Real CKB Blake2b-256 for ckb-light-esp host tests
//
// Replaces the stub blake2b_ref.h which returned fake data.
// Pulls directly from CKB-ESP32's self-contained ckb_blake2b.h —
// no Arduino deps, no system library needed, compiles as plain C++.
//
// CKB personalisation: "ckb-default-hash" (16 bytes)
//
// Usage (same API as the stub):
//   uint8_t hash[32];
//   ckb_blake2b_hash(data, len, hash);
//
//   // or multi-part:
//   CKB_Blake2b ctx;
//   ckb_blake2b_init(&ctx);
//   ckb_blake2b_update(&ctx, part1, len1);
//   ckb_blake2b_update(&ctx, part2, len2);
//   ckb_blake2b_final(&ctx, hash);
//
// Include path: add -I/home/phill/workspace/CKB-ESP32/src to g++ flags,
// or copy ckb_blake2b.h alongside this file.

// Prefer CKB-ESP32's header-only implementation
#if __has_include("ckb_blake2b.h")
#  include "ckb_blake2b.h"
#elif __has_include("../../CKB-ESP32/src/ckb_blake2b.h")
#  include "../../CKB-ESP32/src/ckb_blake2b.h"
#else
#  error "Cannot find ckb_blake2b.h — add -I/home/phill/workspace/CKB-ESP32/src to compiler flags"
#endif

// ── Convenience wrappers ──────────────────────────────────────────────────────

// Hash a Script struct to get its 32-byte script hash.
// Script = mol_write_script() output bytes.
static inline void ckb_script_hash(const uint8_t* scriptBytes, size_t len, uint8_t out[32]) {
    ckb_blake2b_hash(scriptBytes, len, out);
}

// Hash two 32-byte values (used for CBMT merge and transactions_root).
static inline void ckb_merge(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, a, 32);
    ckb_blake2b_update(&ctx, b, 32);
    ckb_blake2b_final(&ctx, out);
}

// Compute signing hash: Blake2b(serialised_tx_hash || witness_lengths_and_data)
// Low-level helper — callers build the full witness hash manually per RFC 0017.
static inline void ckb_signing_hash(const uint8_t* txHash, const uint8_t* witnessData,
                                     size_t witnessLen, uint8_t out[32]) {
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, txHash, 32);
    // witness length as uint64 LE
    uint8_t lenBuf[8];
    for (int i = 0; i < 8; i++) lenBuf[i] = (uint8_t)(witnessLen >> (i*8));
    ckb_blake2b_update(&ctx, lenBuf, 8);
    ckb_blake2b_update(&ctx, witnessData, witnessLen);
    ckb_blake2b_final(&ctx, out);
}
