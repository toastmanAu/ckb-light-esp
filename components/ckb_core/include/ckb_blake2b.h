/*
 * ckb_blake2b.h — Blake2b hash for CKB
 *
 * CKB uses Blake2b-256 with:
 *   - output length: 32 bytes
 *   - personalisation: "ckb-default-hash" (16 bytes)
 *   - no key
 *
 * This is a portable C99 implementation with no external dependencies.
 * Compatible with ESP-IDF and POSIX environments.
 *
 * Reference: RFC 7693, CKB RFC 0022
 */

#ifndef CKB_BLAKE2B_H
#define CKB_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Output sizes */
#define CKB_BLAKE2B_OUTBYTES    32   /* CKB standard: Blake2b-256 */
#define BLAKE2B_OUTBYTES_MAX    64
#define BLAKE2B_KEYBYTES_MAX    64
#define BLAKE2B_SALTBYTES       16
#define BLAKE2B_PERSONALBYTES   16
#define BLAKE2B_BLOCKBYTES      128

/* CKB personalisation string — "ckb-default-hash" */
#define CKB_BLAKE2B_PERSONAL    "ckb-default-hash"

/* Internal state */
typedef struct {
    uint64_t h[8];          /* hash state */
    uint64_t t[2];          /* counter */
    uint64_t f[2];          /* finalization flags */
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
} ckb_blake2b_state;

/* Parameter block (used for initialisation) */
typedef struct {
    uint8_t  digest_length;                   /* 1 */
    uint8_t  key_length;                      /* 2 */
    uint8_t  fanout;                          /* 3 */
    uint8_t  depth;                           /* 4 */
    uint32_t leaf_length;                     /* 8 */
    uint32_t node_offset;                     /* 12 */
    uint32_t xof_length;                      /* 16 */
    uint8_t  node_depth;                      /* 17 */
    uint8_t  inner_length;                    /* 18 */
    uint8_t  reserved[14];                    /* 32 */
    uint8_t  salt[BLAKE2B_SALTBYTES];         /* 48 */
    uint8_t  personal[BLAKE2B_PERSONALBYTES]; /* 64 */
} ckb_blake2b_param;

/* ── Low-level API ── */

/**
 * Initialise a Blake2b state with full parameter control.
 * @return 0 on success, -1 on error.
 */
int ckb_blake2b_init_param(ckb_blake2b_state *S, const ckb_blake2b_param *P);

/**
 * Initialise with output length and optional key.
 * @return 0 on success, -1 on error.
 */
int ckb_blake2b_init_key(ckb_blake2b_state *S, size_t outlen,
                          const void *key, size_t keylen);

/**
 * Initialise with no key.
 */
int ckb_blake2b_init(ckb_blake2b_state *S, size_t outlen);

/**
 * Feed data into the hash state.
 * @return 0 on success, -1 on error.
 */
int ckb_blake2b_update(ckb_blake2b_state *S, const void *in, size_t inlen);

/**
 * Finalise and write digest.
 * @return 0 on success, -1 on error.
 */
int ckb_blake2b_final(ckb_blake2b_state *S, void *out, size_t outlen);

/* ── CKB convenience API ── */

/**
 * Initialise state for CKB standard hashing:
 *   Blake2b-256 with personal="ckb-default-hash", no key.
 */
int ckb_blake2b_init_default(ckb_blake2b_state *S);

/**
 * One-shot CKB hash: compute Blake2b-256("ckb-default-hash") of `in`.
 * Output is always CKB_BLAKE2B_OUTBYTES (32) bytes.
 */
int ckb_blake2b_256(const void *in, size_t inlen,
                    uint8_t out[CKB_BLAKE2B_OUTBYTES]);

/**
 * Hash two buffers concatenated (common in CKB: hash(a || b)).
 */
int ckb_blake2b_256_2(const void *in1, size_t inlen1,
                       const void *in2, size_t inlen2,
                       uint8_t out[CKB_BLAKE2B_OUTBYTES]);

/**
 * Compute the CKB script hash from code_hash, hash_type, and args.
 * script_hash = Blake2b(code_hash || hash_type_byte || args)
 */
int ckb_script_hash(const uint8_t code_hash[32],
                    uint8_t hash_type,
                    const uint8_t *args, size_t args_len,
                    uint8_t out[CKB_BLAKE2B_OUTBYTES]);

#ifdef __cplusplus
}
#endif

#endif /* CKB_BLAKE2B_H */
