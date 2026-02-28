/*
 * eaglesong.h — Eaglesong PoW hash for CKB (Nervos Network)
 *
 * Ported from: https://github.com/nervosnetwork/eaglesong
 *
 * Algorithm:
 *   Sponge construction
 *   State  : 16 × uint32_t (512 bits)
 *   Rate   : 256 bits (8 words per block)
 *   Rounds : 43
 *   Delim  : 0x06
 *   Input absorption : big-endian byte packing into u32
 *   Output squeezing : little-endian byte extraction from u32
 *
 * CKB mining usage:
 *   input  = pow_hash[32] || nonce[16 LE]  = 48 bytes
 *   output = eaglesong(input) → 32 bytes
 *   valid  = output (LE) <= target (LE), byte[31] is MSB
 *
 * Test vectors:
 *   eaglesong("")          → 9e4452fc7aed93d7240b7b55263792befd1be09252b456401122ba71a56f62a0
 *   eaglesong("1111....\n") (34 bytes of '1'+'\n') → a50a3310f78cbaeadcffe2d46262119eeeda9d6568b4df1b636399742c867aca
 */

#ifndef EAGLESONG_H
#define EAGLESONG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IRAM_ATTR fallback for non-ESP32 builds (host tests, etc.) */
#ifndef IRAM_ATTR
#define IRAM_ATTR
#endif

/**
 * eaglesong() — hash input_len bytes, write output_len bytes.
 * For CKB mining: input_len=48, output_len=32.
 * Marked IRAM_ATTR so the hot path runs from IRAM on ESP32.
 */
IRAM_ATTR void eaglesong(const uint8_t *input,  size_t input_len,
                         uint8_t       *output, size_t output_len);

/**
 * eaglesong_selftest() — verify against known test vectors.
 * Returns true if all vectors pass.
 * Call from setup() to confirm correct port.
 */
bool eaglesong_selftest(void);

/**
 * ckb_pow_hash() — convenience: hash pow_hash[32]||nonce_le[16] → out[32]
 */
static inline void ckb_pow_hash(const uint8_t pow_hash[32],
                                const uint8_t nonce_le[16],
                                uint8_t       out[32])
{
    uint8_t input[48];
    for (int i = 0; i < 32; i++) input[i]      = pow_hash[i];
    for (int i = 0; i < 16; i++) input[32 + i] = nonce_le[i];
    eaglesong(input, 48, out, 32);
}

/**
 * ckb_check_target() — returns true if hash[32] (LE) <= target[32] (LE).
 * Compares from most-significant byte (index 31) downward.
 */
static inline bool ckb_check_target(const uint8_t hash[32],
                                    const uint8_t target[32])
{
    for (int i = 31; i >= 0; --i) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true; /* exactly equal is valid */
}

#ifdef __cplusplus
}
#endif

#endif /* EAGLESONG_H */
