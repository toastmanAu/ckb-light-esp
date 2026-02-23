/*
 * ckb_molecule.h — Molecule serialisation codec for CKB/Tentacle
 *
 * Molecule is CKB's canonical binary serialisation format.
 * All CKB types (headers, scripts, transactions) and all Tentacle
 * handshake messages are encoded with Molecule.
 *
 * Format overview:
 *   - Fixed-size types: just the bytes, no header
 *   - Dynamic types (Table/Vector): 4-byte LE total-length header,
 *     then 4-byte LE offsets table, then fields
 *
 * This implementation is minimal: just enough to encode/decode
 * the Tentacle SecIO Propose/Exchange messages and CKB light client
 * protocol messages.
 *
 * Reference: https://github.com/nervosnetwork/molecule
 */

#ifndef CKB_MOLECULE_H
#define CKB_MOLECULE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Wire format helpers ── */

/* Read/write 4-byte LE uint32 (Molecule uses LE throughout) */
static inline uint32_t mol_read_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void mol_write_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* ── Molecule Bytes (variable-length byte vector) ──
 * Wire: [4-byte total_len][data...]
 * total_len includes the 4-byte header itself.
 */

/**
 * Encode a byte slice as a Molecule Bytes field.
 * Writes total_len (4 bytes LE) + data into buf.
 * Returns number of bytes written, or -1 if buf too small.
 */
int mol_encode_bytes(const uint8_t *data, uint32_t data_len,
                     uint8_t *buf, uint32_t buf_size);

/**
 * Decode a Molecule Bytes field from buf.
 * Sets *data_out to point inside buf (no copy), *len_out to data length.
 * Returns number of bytes consumed, or -1 on error.
 */
int mol_decode_bytes(const uint8_t *buf, uint32_t buf_size,
                     const uint8_t **data_out, uint32_t *len_out);

/**
 * Size of a Molecule Bytes encoding for data_len bytes.
 */
static inline uint32_t mol_bytes_size(uint32_t data_len) {
    return 4 + data_len;
}

/* ── Molecule String (same wire format as Bytes) ── */
static inline int mol_encode_string(const char *str, uint32_t len,
                                    uint8_t *buf, uint32_t buf_size) {
    return mol_encode_bytes((const uint8_t *)str, len, buf, buf_size);
}

/* ── Molecule Table ──
 * Wire: [4-byte full_size][4-byte field_count][4-byte offset_0]...[4-byte offset_n][fields...]
 * Offsets are absolute from start of table.
 * full_size includes everything.
 */

/** Max fields in a molecule table (for stack allocation) */
#define MOL_MAX_FIELDS  16

typedef struct {
    const uint8_t *field_data[MOL_MAX_FIELDS];
    uint32_t       field_len[MOL_MAX_FIELDS];
    uint32_t       field_count;
} mol_table_t;

/**
 * Calculate total encoded size of a table.
 */
uint32_t mol_table_encoded_size(const mol_table_t *t);

/**
 * Encode a table into buf.
 * Returns bytes written, or -1 if buf too small.
 */
int mol_table_encode(const mol_table_t *t, uint8_t *buf, uint32_t buf_size);

/**
 * Decode a table from buf into t.
 * Fields point into buf (no copy).
 * Returns bytes consumed, or -1 on error.
 */
int mol_table_decode(const uint8_t *buf, uint32_t buf_size, mol_table_t *t);

/* ── SecIO Propose message ──
 *
 * Tentacle SecIO Propose (Molecule Table, 5 fields):
 *   rand      Bytes   — 16 random bytes (nonce)
 *   pubkey    Bytes   — secp256k1 uncompressed public key (65 bytes) or compressed (33)
 *   exchanges String  — "P-256,P-384" or similar; CKB uses "P-256"
 *   ciphers   String  — "AES-128,AES-256"; CKB uses "AES-128"
 *   hashes    String  — "SHA256,SHA512"; CKB uses "SHA256"
 */
typedef struct {
    uint8_t  rand[16];
    uint8_t  pubkey[65];
    uint32_t pubkey_len;        /* 33 or 65 */
    char     exchanges[64];
    uint32_t exchanges_len;
    char     ciphers[64];
    uint32_t ciphers_len;
    char     hashes[64];
    uint32_t hashes_len;
} secio_propose_t;

/**
 * Encode a SecIO Propose into buf.
 * Returns bytes written or -1.
 */
int secio_propose_encode(const secio_propose_t *p, uint8_t *buf, uint32_t buf_size);

/**
 * Decode a SecIO Propose from buf.
 * Returns bytes consumed or -1.
 */
int secio_propose_decode(const uint8_t *buf, uint32_t buf_size, secio_propose_t *out);

/* ── SecIO Exchange message ──
 *
 * Tentacle SecIO Exchange (Molecule Table, 2 fields):
 *   epubkey    Bytes — ephemeral public key (P-256: 65 bytes uncompressed)
 *   signature  Bytes — ECDSA signature of (local_prop || remote_prop || epubkey)
 */
typedef struct {
    uint8_t  epubkey[65];
    uint32_t epubkey_len;
    uint8_t  signature[72];   /* DER-encoded ECDSA, max 72 bytes */
    uint32_t signature_len;
} secio_exchange_t;

/**
 * Encode a SecIO Exchange into buf.
 * Returns bytes written or -1.
 */
int secio_exchange_encode(const secio_exchange_t *e, uint8_t *buf, uint32_t buf_size);

/**
 * Decode a SecIO Exchange from buf.
 * Returns bytes consumed or -1.
 */
int secio_exchange_decode(const uint8_t *buf, uint32_t buf_size, secio_exchange_t *out);

/* ── PublicKey wrapper ──
 *
 * Tentacle encodes pubkeys as:
 *   Molecule union { Secp256k1(Bytes) }
 * The union tag is a 4-byte LE item index (0 = Secp256k1).
 */

/**
 * Encode a raw secp256k1 pubkey as a Molecule PublicKey union.
 * Returns bytes written or -1.
 */
int mol_pubkey_encode(const uint8_t *pubkey, uint32_t pubkey_len,
                      uint8_t *buf, uint32_t buf_size);

/**
 * Decode a Molecule PublicKey union.
 * Sets *pubkey_out to point into buf, *len_out to key length.
 * Returns bytes consumed or -1.
 */
int mol_pubkey_decode(const uint8_t *buf, uint32_t buf_size,
                      const uint8_t **pubkey_out, uint32_t *len_out);

#ifdef __cplusplus
}
#endif

#endif /* CKB_MOLECULE_H */
