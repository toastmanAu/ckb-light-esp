/*
 * ckb_blake2b.c — Blake2b implementation for CKB
 *
 * Based on the reference implementation (CC0 / public domain).
 * Adapted for CKB personalisation and embedded use.
 *
 * No dynamic allocation. No external dependencies.
 * C99 compliant.
 */

#include "ckb_blake2b.h"

#include <string.h>
#include <stdint.h>

/* ── Portability ── */
#if defined(_MSC_VER)
  #define BLAKE2_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
  #define BLAKE2_INLINE __attribute__((always_inline)) inline
#else
  #define BLAKE2_INLINE inline
#endif

static BLAKE2_INLINE uint64_t load64(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint64_t)p[0])       | ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static BLAKE2_INLINE void store64(void *dst, uint64_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w);       p[1] = (uint8_t)(w >>  8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
    p[4] = (uint8_t)(w >> 32); p[5] = (uint8_t)(w >> 40);
    p[6] = (uint8_t)(w >> 48); p[7] = (uint8_t)(w >> 56);
}

static BLAKE2_INLINE uint64_t rotr64(uint64_t w, unsigned c) {
    return (w >> c) | (w << (64 - c));
}

/* Blake2b IV */
static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* Sigma permutation table */
static const uint8_t blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

/* G mixing function */
#define G(r, i, a, b, c, d)                             \
    do {                                                 \
        a = a + b + m[blake2b_sigma[r][2*(i)+0]];       \
        d = rotr64(d ^ a, 32);                          \
        c = c + d;                                       \
        b = rotr64(b ^ c, 24);                          \
        a = a + b + m[blake2b_sigma[r][2*(i)+1]];       \
        d = rotr64(d ^ a, 16);                          \
        c = c + d;                                       \
        b = rotr64(b ^ c, 63);                          \
    } while (0)

#define ROUND(r)                        \
    do {                                \
        G(r, 0, v[ 0], v[ 4], v[ 8], v[12]); \
        G(r, 1, v[ 1], v[ 5], v[ 9], v[13]); \
        G(r, 2, v[ 2], v[ 6], v[10], v[14]); \
        G(r, 3, v[ 3], v[ 7], v[11], v[15]); \
        G(r, 4, v[ 0], v[ 5], v[10], v[15]); \
        G(r, 5, v[ 1], v[ 6], v[11], v[12]); \
        G(r, 6, v[ 2], v[ 7], v[ 8], v[13]); \
        G(r, 7, v[ 3], v[ 4], v[ 9], v[14]); \
    } while (0)

static void blake2b_compress(ckb_blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES]) {
    uint64_t m[16];
    uint64_t v[16];
    int i;

    for (i = 0; i < 16; i++)
        m[i] = load64(block + i * 8);

    for (i = 0; i < 8; i++)
        v[i] = S->h[i];

    v[ 8] = blake2b_IV[0];
    v[ 9] = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ S->t[0];
    v[13] = blake2b_IV[5] ^ S->t[1];
    v[14] = blake2b_IV[6] ^ S->f[0];
    v[15] = blake2b_IV[7] ^ S->f[1];

    ROUND(0); ROUND(1); ROUND(2); ROUND(3);
    ROUND(4); ROUND(5); ROUND(6); ROUND(7);
    ROUND(8); ROUND(9); ROUND(10); ROUND(11);

    for (i = 0; i < 8; i++)
        S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}

static void blake2b_increment_counter(ckb_blake2b_state *S, uint64_t inc) {
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

static void blake2b_set_lastnode(ckb_blake2b_state *S) {
    S->f[1] = (uint64_t)-1;
}

static void blake2b_set_lastblock(ckb_blake2b_state *S) {
    if (S->last_node) blake2b_set_lastnode(S);
    S->f[0] = (uint64_t)-1;
}

/* ── Public API ── */

int ckb_blake2b_init_param(ckb_blake2b_state *S, const ckb_blake2b_param *P) {
    const uint8_t *p = (const uint8_t *)P;
    int i;

    if (!S || !P) return -1;
    if (P->digest_length == 0 || P->digest_length > BLAKE2B_OUTBYTES_MAX) return -1;
    if (P->key_length > BLAKE2B_KEYBYTES_MAX) return -1;

    memset(S, 0, sizeof(*S));
    S->outlen = P->digest_length;

    for (i = 0; i < 8; i++)
        S->h[i] = blake2b_IV[i];

    /* XOR parameter block into IV */
    for (i = 0; i < 8; i++)
        S->h[i] ^= load64(p + i * 8);

    S->buflen = 0;
    S->last_node = 0;
    return 0;
}

int ckb_blake2b_init(ckb_blake2b_state *S, size_t outlen) {
    ckb_blake2b_param P;

    if (!outlen || outlen > BLAKE2B_OUTBYTES_MAX) return -1;

    memset(&P, 0, sizeof(P));
    P.digest_length = (uint8_t)outlen;
    P.fanout = 1;
    P.depth  = 1;

    return ckb_blake2b_init_param(S, &P);
}

int ckb_blake2b_init_key(ckb_blake2b_state *S, size_t outlen,
                          const void *key, size_t keylen) {
    ckb_blake2b_param P;
    uint8_t block[BLAKE2B_BLOCKBYTES];

    if (!outlen || outlen > BLAKE2B_OUTBYTES_MAX) return -1;
    if (!keylen || keylen > BLAKE2B_KEYBYTES_MAX) return -1;
    if (!key) return -1;

    memset(&P, 0, sizeof(P));
    P.digest_length = (uint8_t)outlen;
    P.key_length    = (uint8_t)keylen;
    P.fanout = 1;
    P.depth  = 1;

    if (ckb_blake2b_init_param(S, &P) < 0) return -1;

    memset(block, 0, sizeof(block));
    memcpy(block, key, keylen);
    ckb_blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
    memset(block, 0, sizeof(block)); /* clear key from stack */
    return 0;
}

int ckb_blake2b_init_default(ckb_blake2b_state *S) {
    ckb_blake2b_param P;

    memset(&P, 0, sizeof(P));
    P.digest_length = CKB_BLAKE2B_OUTBYTES;
    P.fanout = 1;
    P.depth  = 1;
    memcpy(P.personal, CKB_BLAKE2B_PERSONAL, BLAKE2B_PERSONALBYTES);

    return ckb_blake2b_init_param(S, &P);
}

int ckb_blake2b_update(ckb_blake2b_state *S, const void *pin, size_t inlen) {
    const uint8_t *in = (const uint8_t *)pin;

    if (!S) return -1;
    if (inlen == 0) return 0;

    while (inlen > 0) {
        size_t left = S->buflen;
        size_t fill = BLAKE2B_BLOCKBYTES - left;

        if (inlen > fill) {
            /* Buffer will be full — compress */
            memcpy(S->buf + left, in, fill);
            blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
            blake2b_compress(S, S->buf);
            S->buflen = 0;
            in    += fill;
            inlen -= fill;
        } else {
            memcpy(S->buf + left, in, inlen);
            S->buflen += inlen;
            break;
        }
    }
    return 0;
}

int ckb_blake2b_final(ckb_blake2b_state *S, void *out, size_t outlen) {
    uint8_t buffer[BLAKE2B_OUTBYTES_MAX] = {0};
    int i;

    if (!S || !out) return -1;
    if (outlen < S->outlen) return -1;
    if (S->f[0] != 0) return -1; /* already finalised */

    blake2b_increment_counter(S, S->buflen);
    blake2b_set_lastblock(S);

    /* Zero-pad remaining buffer */
    memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
    blake2b_compress(S, S->buf);

    for (i = 0; i < 8; i++)
        store64(buffer + i * 8, S->h[i]);

    memcpy(out, buffer, S->outlen);
    memset(buffer, 0, sizeof(buffer));
    return 0;
}

/* ── CKB convenience ── */

int ckb_blake2b_256(const void *in, size_t inlen,
                    uint8_t out[CKB_BLAKE2B_OUTBYTES]) {
    ckb_blake2b_state S;
    if (ckb_blake2b_init_default(&S) < 0) return -1;
    if (ckb_blake2b_update(&S, in, inlen) < 0) return -1;
    return ckb_blake2b_final(&S, out, CKB_BLAKE2B_OUTBYTES);
}

int ckb_blake2b_256_2(const void *in1, size_t inlen1,
                       const void *in2, size_t inlen2,
                       uint8_t out[CKB_BLAKE2B_OUTBYTES]) {
    ckb_blake2b_state S;
    if (ckb_blake2b_init_default(&S) < 0) return -1;
    if (ckb_blake2b_update(&S, in1, inlen1) < 0) return -1;
    if (ckb_blake2b_update(&S, in2, inlen2) < 0) return -1;
    return ckb_blake2b_final(&S, out, CKB_BLAKE2B_OUTBYTES);
}

int ckb_script_hash(const uint8_t code_hash[32],
                    uint8_t hash_type,
                    const uint8_t *args, size_t args_len,
                    uint8_t out[CKB_BLAKE2B_OUTBYTES]) {
    ckb_blake2b_state S;
    if (ckb_blake2b_init_default(&S) < 0) return -1;
    if (ckb_blake2b_update(&S, code_hash, 32) < 0) return -1;
    if (ckb_blake2b_update(&S, &hash_type, 1) < 0) return -1;
    if (args && args_len > 0) {
        if (ckb_blake2b_update(&S, args, args_len) < 0) return -1;
    }
    return ckb_blake2b_final(&S, out, CKB_BLAKE2B_OUTBYTES);
}
