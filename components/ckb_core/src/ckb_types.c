/*
 * ckb_types.c — CKB type implementations
 */

#include "ckb_types.h"
#include "ckb_blake2b.h"
#include <string.h>

/* ── Little-endian helpers ── */
static inline uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t read_u64_le(const uint8_t *p) {
    return (uint64_t)p[0]        | ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void write_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static inline void write_u64_le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

/* ── Header serialise/deserialise ── */

int ckb_header_serialize(const ckb_header_t *h, uint8_t out[CKB_HEADER_SIZE]) {
    if (!h || !out) return -1;
    uint8_t *p = out;

    write_u32_le(p,  h->version);         p += 4;
    write_u32_le(p,  h->compact_target);  p += 4;
    write_u64_le(p,  h->timestamp);       p += 8;
    write_u64_le(p,  h->number);          p += 8;
    write_u64_le(p,  h->epoch);           p += 8;
    memcpy(p, h->parent_hash,       32);  p += 32;
    memcpy(p, h->transactions_root, 32);  p += 32;
    memcpy(p, h->proposals_hash,    32);  p += 32;
    memcpy(p, h->extra_hash,        32);  p += 32;
    memcpy(p, h->dao,               32);  p += 32;
    memcpy(p, h->nonce,             16);  p += 16;

    (void)p; /* p should now be out + 208 */
    return 0;
}

int ckb_header_deserialize(const uint8_t buf[CKB_HEADER_SIZE], ckb_header_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *p = buf;

    out->version        = read_u32_le(p); p += 4;
    out->compact_target = read_u32_le(p); p += 4;
    out->timestamp      = read_u64_le(p); p += 8;
    out->number         = read_u64_le(p); p += 8;
    out->epoch          = read_u64_le(p); p += 8;
    memcpy(out->parent_hash,       p, 32); p += 32;
    memcpy(out->transactions_root, p, 32); p += 32;
    memcpy(out->proposals_hash,    p, 32); p += 32;
    memcpy(out->extra_hash,        p, 32); p += 32;
    memcpy(out->dao,               p, 32); p += 32;
    memcpy(out->nonce,             p, 16); p += 16;

    (void)p;
    return 0;
}

int ckb_header_hash(const ckb_header_t *h, ckb_hash_t out) {
    uint8_t buf[CKB_HEADER_SIZE];
    if (ckb_header_serialize(h, buf) < 0) return -1;
    return ckb_blake2b_256(buf, CKB_HEADER_SIZE, out);
}

/* ── Compact target / difficulty ── */

void ckb_compact_to_target(uint32_t compact, uint8_t target[32]) {
    uint32_t exponent = compact >> 24;
    uint32_t mantissa = compact & 0x007fffffUL;
    memset(target, 0, 32);

    if (exponent == 0 || mantissa == 0) return;

    /* mantissa occupies 3 bytes at byte offset (exponent - 3) from the end */
    /* target is LE, so byte 0 is least significant */
    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        if (exponent >= 1) target[exponent - 1] = (uint8_t)(mantissa);
        if (exponent >= 2) target[exponent - 2] = (uint8_t)(mantissa >> 8);
        if (exponent >= 3) target[exponent - 3] = (uint8_t)(mantissa >> 16);
    } else {
        uint32_t offset = exponent - 3;
        if (offset + 3 > 32) return; /* overflow */
        target[offset]     = (uint8_t)(mantissa);
        target[offset + 1] = (uint8_t)(mantissa >> 8);
        target[offset + 2] = (uint8_t)(mantissa >> 16);
    }
}

int ckb_u256_cmp(const uint8_t a[32], const uint8_t b[32]) {
    /* LE: compare from most significant byte (index 31) down */
    int i;
    for (i = 31; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}

int ckb_u256_add(uint8_t a[32], const uint8_t b[32]) {
    uint32_t carry = 0;
    int i;
    for (i = 0; i < 32; i++) {
        uint32_t sum = (uint32_t)a[i] + (uint32_t)b[i] + carry;
        a[i]  = (uint8_t)(sum & 0xFF);
        carry = sum >> 8;
    }
    return (int)carry;
}
