/*
 * ckb_types.h — CKB core data structures
 *
 * Definitions of CKB's fundamental types as used in headers,
 * scripts, transactions, and MMR nodes.
 *
 * All multi-byte integers are little-endian on the wire (Molecule format).
 */

#ifndef CKB_TYPES_H
#define CKB_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Primitive types ── */

typedef uint8_t  ckb_hash_t[32];   /* 256-bit hash / code_hash */
typedef uint8_t  ckb_bytes32_t[32];

/* ── Hash types (for Script.hash_type) ── */
#define CKB_HASH_TYPE_DATA   0x00
#define CKB_HASH_TYPE_TYPE   0x01
#define CKB_HASH_TYPE_DATA1  0x02

/* ── CKB Script ── */
typedef struct {
    ckb_hash_t  code_hash;    /* 32 bytes */
    uint8_t     hash_type;    /* 1 byte: data=0, type=1, data1=2 */
    uint8_t    *args;         /* variable length */
    uint32_t    args_len;
} ckb_script_t;

/* ── CKB Block Header (208 bytes on wire) ── */
/*
 * Layout (Molecule fixed-size struct):
 *   version          u32     4
 *   compact_target   u32     4
 *   timestamp        u64     8
 *   number           u64     8
 *   epoch            u64     8
 *   parent_hash      Byte32  32
 *   transactions_root Byte32 32
 *   proposals_hash   Byte32  32
 *   extra_hash       Byte32  32
 *   dao              Byte32  32
 *   nonce            u128    16
 *   Total:                   208
 */
#define CKB_HEADER_SIZE  208

typedef struct {
    uint32_t    version;
    uint32_t    compact_target;
    uint64_t    timestamp;          /* unix ms */
    uint64_t    number;             /* block height */
    uint64_t    epoch;              /* packed epoch: length|index|number */
    ckb_hash_t  parent_hash;
    ckb_hash_t  transactions_root;
    ckb_hash_t  proposals_hash;
    ckb_hash_t  extra_hash;
    ckb_hash_t  dao;
    uint8_t     nonce[16];          /* u128 LE */
} ckb_header_t;

/* Unpack epoch fields from packed u64 */
#define CKB_EPOCH_NUMBER(e)  ((uint64_t)((e) & 0xFFFFFF))
#define CKB_EPOCH_INDEX(e)   ((uint64_t)(((e) >> 24) & 0xFFFF))
#define CKB_EPOCH_LENGTH(e)  ((uint64_t)(((e) >> 40) & 0xFFFF))

/* ── MMR HeaderDigest (RFC 0044) ── */
/*
 * Each MMR node contains:
 *   children_hash        Byte32   32
 *   total_difficulty     Uint256  32
 *   start_number         Uint64    8
 *   end_number           Uint64    8
 *   start_epoch          Uint64    8
 *   end_epoch            Uint64    8
 *   start_timestamp      Uint64    8
 *   end_timestamp        Uint64    8
 *   start_compact_target Uint32    4
 *   end_compact_target   Uint32    4
 *   Total:                        120
 */
#define CKB_HEADER_DIGEST_SIZE  120

typedef struct {
    ckb_hash_t  children_hash;          /* hash of this node */
    uint8_t     total_difficulty[32];   /* Uint256 LE */
    uint64_t    start_number;
    uint64_t    end_number;
    uint64_t    start_epoch;
    uint64_t    end_epoch;
    uint64_t    start_timestamp;
    uint64_t    end_timestamp;
    uint32_t    start_compact_target;
    uint32_t    end_compact_target;
} ckb_header_digest_t;

/* ── OutPoint ── */
typedef struct {
    ckb_hash_t  tx_hash;
    uint32_t    index;
} ckb_outpoint_t;

/* ── CellInput ── */
typedef struct {
    uint64_t    since;
    ckb_outpoint_t previous_output;
} ckb_cell_input_t;

/* ── CellOutput ── */
typedef struct {
    uint64_t        capacity;   /* in shannons (1 CKB = 1e8 shannons) */
    ckb_script_t    lock;
    ckb_script_t   *type;       /* nullable */
} ckb_cell_output_t;

/* ── Compact target / difficulty helpers ── */

/**
 * Expand a compact_target u32 to a 32-byte LE difficulty target.
 * Same algorithm as Bitcoin's nBits.
 */
void ckb_compact_to_target(uint32_t compact, uint8_t target[32]);

/**
 * Compare two 32-byte LE big integers.
 * Returns <0, 0, >0.
 */
int ckb_u256_cmp(const uint8_t a[32], const uint8_t b[32]);

/**
 * Add two 32-byte LE big integers in place: a += b.
 * Returns carry (0 or 1).
 */
int ckb_u256_add(uint8_t a[32], const uint8_t b[32]);

/**
 * Serialise a header to its canonical 208-byte wire format (little-endian).
 */
int ckb_header_serialize(const ckb_header_t *h, uint8_t out[CKB_HEADER_SIZE]);

/**
 * Deserialise a 208-byte wire buffer into a ckb_header_t.
 */
int ckb_header_deserialize(const uint8_t buf[CKB_HEADER_SIZE], ckb_header_t *out);

/**
 * Compute the header hash (Blake2b-256("ckb-default-hash") of wire bytes).
 */
int ckb_header_hash(const ckb_header_t *h, ckb_hash_t out);

#ifdef __cplusplus
}
#endif

#endif /* CKB_TYPES_H */
