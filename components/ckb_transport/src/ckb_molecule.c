/*
 * ckb_molecule.c — Molecule codec implementation
 */

#include <inttypes.h>
#include "ckb_molecule.h"
#include <stdio.h>
#include <string.h>

/* ── Bytes ── */

int mol_encode_bytes(const uint8_t *data, uint32_t data_len,
                     uint8_t *buf, uint32_t buf_size) {
    uint32_t total = 4 + data_len;
    if (!buf || buf_size < total) return -1;
    mol_write_u32(buf, data_len);   /* Molecule Bytes: header = data length only */
    if (data && data_len) memcpy(buf + 4, data, data_len);
    return (int)total;
}

int mol_decode_bytes(const uint8_t *buf, uint32_t buf_size,
                     const uint8_t **data_out, uint32_t *len_out) {
    if (!buf || buf_size < 4) return -1;
    uint32_t data_len = mol_read_u32(buf);  /* header = data length only */
    if (4 + data_len > buf_size) return -1;
    if (data_out) *data_out = buf + 4;
    if (len_out)  *len_out  = data_len;
    return (int)(4 + data_len);
}

/* ── Table ── */

uint32_t mol_table_encoded_size(const mol_table_t *t) {
    if (!t) return 0;
    /* full_size(4) + offsets(4 * field_count) + all field data */
    uint32_t header = 4 + 4 * t->field_count;
    uint32_t data_size = 0;
    uint32_t i;
    for (i = 0; i < t->field_count; i++)
        data_size += t->field_len[i];
    return header + data_size;
}

int mol_table_encode(const mol_table_t *t, uint8_t *buf, uint32_t buf_size) {
    if (!t || !buf) return -1;
    uint32_t total = mol_table_encoded_size(t);
    if (buf_size < total) return -1;

    /* Molecule Table: [4-byte total_size][offset_0]...[offset_n-1][fields...] */
    uint32_t header_size = 4 + 4 * t->field_count;

    mol_write_u32(buf, total);

    /* Write offsets: offset of each field relative to start of table */
    uint32_t offset = header_size;
    uint32_t i;
    for (i = 0; i < t->field_count; i++) {
        mol_write_u32(buf + 4 + 4 * i, offset);
        offset += t->field_len[i];
    }

    /* Write field data */
    uint8_t *dst = buf + header_size;
    for (i = 0; i < t->field_count; i++) {
        if (t->field_data[i] && t->field_len[i])
            memcpy(dst, t->field_data[i], t->field_len[i]);
        dst += t->field_len[i];
    }

    return (int)total;
}

int mol_table_decode(const uint8_t *buf, uint32_t buf_size, mol_table_t *t) {
    if (!buf || !t || buf_size < 8) return -1;

    uint32_t full_size = mol_read_u32(buf);
    if (full_size > buf_size || full_size < 4) return -1;

    /* Molecule Table: [4-byte total_size][offset_0][offset_1]...[offset_n-1]
     * Field count derived from first offset: n = (offset_0 - 4) / 4
     * If full_size == 4, table is empty (0 fields).
     */
    if (full_size == 4) {
        t->field_count = 0;
        return (int)full_size;
    }
    if (full_size < 8) return -1;

    uint32_t first_offset = mol_read_u32(buf + 4);
    if (first_offset < 4 || first_offset > full_size) return -1;
    if ((first_offset - 4) % 4 != 0) return -1;

    uint32_t field_count = (first_offset - 4) / 4;
    if (field_count > MOL_MAX_FIELDS) return -1;

    uint32_t header_size = 4 + 4 * field_count;
    if (full_size < header_size) return -1;

    t->field_count = field_count;

    uint32_t i;
    for (i = 0; i < field_count; i++) {
        uint32_t offset = mol_read_u32(buf + 4 + 4 * i);
        uint32_t end;
        if (i + 1 < field_count)
            end = mol_read_u32(buf + 4 + 4 * (i + 1));
        else
            end = full_size;

        if (offset > full_size || end > full_size || end < offset) return -1;
        t->field_data[i] = buf + offset;
        t->field_len[i]  = end - offset;
    }

    return (int)full_size;
}

/* ── SecIO Propose ── */

int secio_propose_encode(const secio_propose_t *p, uint8_t *buf, uint32_t buf_size) {
    if (!p || !buf) return -1;

    /* Pre-encode each field */
    uint8_t f_rand[4 + 16];
    uint8_t f_pubkey[4 + 65];
    uint8_t f_exchanges[4 + 64];
    uint8_t f_ciphers[4 + 64];
    uint8_t f_hashes[4 + 64];

    int r_rand      = mol_encode_bytes(p->rand, 16, f_rand, sizeof(f_rand));
    int r_pubkey    = mol_encode_bytes(p->pubkey, p->pubkey_len, f_pubkey, sizeof(f_pubkey));
    int r_exchanges = mol_encode_bytes((const uint8_t *)p->exchanges, p->exchanges_len, f_exchanges, sizeof(f_exchanges));
    int r_ciphers   = mol_encode_bytes((const uint8_t *)p->ciphers,   p->ciphers_len,   f_ciphers,   sizeof(f_ciphers));
    int r_hashes    = mol_encode_bytes((const uint8_t *)p->hashes,    p->hashes_len,    f_hashes,    sizeof(f_hashes));

    if (r_rand < 0 || r_pubkey < 0 || r_exchanges < 0 || r_ciphers < 0 || r_hashes < 0) return -1;

    mol_table_t t;
    t.field_count    = 5;
    t.field_data[0]  = f_rand;      t.field_len[0] = (uint32_t)r_rand;
    t.field_data[1]  = f_pubkey;    t.field_len[1] = (uint32_t)r_pubkey;
    t.field_data[2]  = f_exchanges; t.field_len[2] = (uint32_t)r_exchanges;
    t.field_data[3]  = f_ciphers;   t.field_len[3] = (uint32_t)r_ciphers;
    t.field_data[4]  = f_hashes;    t.field_len[4] = (uint32_t)r_hashes;

    return mol_table_encode(&t, buf, buf_size);
}

int secio_propose_decode(const uint8_t *buf, uint32_t buf_size, secio_propose_t *out) {
    if (!buf || !out) return -1;
    mol_table_t t;
    int consumed = mol_table_decode(buf, buf_size, &t);
    fprintf(stderr, "[propose_decode] consumed=%d field_count=%"PRIu32"\n", consumed, t.field_count);
    if (consumed < 0 || t.field_count < 5) return -1;

    memset(out, 0, sizeof(*out));

    const uint8_t *data; uint32_t len;

    /* rand */
    int r = mol_decode_bytes(t.field_data[0], t.field_len[0], &data, &len);
    fprintf(stderr, "[propose_decode] rand decode=%d len=%"PRIu32"\n", r, len);
    if (r < 0) return -1;
    if (len > 16) return -1;
    memcpy(out->rand, data, len);

    /* pubkey */
    r = mol_decode_bytes(t.field_data[1], t.field_len[1], &data, &len);
    fprintf(stderr, "[propose_decode] pubkey_outer decode=%d len=%"PRIu32"\n", r, len);
    if (r < 0) return -1;
    if (len > 65) return -1;
    memcpy(out->pubkey, data, len);
    out->pubkey_len = len;

    /* exchanges */
    r = mol_decode_bytes(t.field_data[2], t.field_len[2], &data, &len);
    fprintf(stderr, "[propose_decode] exchanges decode=%d len=%"PRIu32" str='%.*s'\n", r, len, (int)len, data ? (const char*)data : "");
    if (r < 0) return -1;
    if (len >= sizeof(out->exchanges)) return -1;
    memcpy(out->exchanges, data, len);
    out->exchanges_len = len;

    /* ciphers */
    r = mol_decode_bytes(t.field_data[3], t.field_len[3], &data, &len);
    fprintf(stderr, "[propose_decode] ciphers decode=%d len=%"PRIu32" str='%.*s'\n", r, len, (int)len, data ? (const char*)data : "");
    if (r < 0) return -1;
    if (len >= sizeof(out->ciphers)) return -1;
    memcpy(out->ciphers, data, len);
    out->ciphers_len = len;

    /* hashes */
    r = mol_decode_bytes(t.field_data[4], t.field_len[4], &data, &len);
    fprintf(stderr, "[propose_decode] hashes decode=%d len=%"PRIu32" str='%.*s'\n", r, len, (int)len, data ? (const char*)data : "");
    if (r < 0) return -1;
    if (len >= sizeof(out->hashes)) return -1;
    memcpy(out->hashes, data, len);
    out->hashes_len = len;

    return consumed;
}

/* ── SecIO Exchange ── */

int secio_exchange_encode(const secio_exchange_t *e, uint8_t *buf, uint32_t buf_size) {
    if (!e || !buf) return -1;

    uint8_t f_epubkey[4 + 65];
    uint8_t f_signature[4 + 72];

    int r_epubkey   = mol_encode_bytes(e->epubkey,   e->epubkey_len,   f_epubkey,   sizeof(f_epubkey));
    int r_signature = mol_encode_bytes(e->signature, e->signature_len, f_signature, sizeof(f_signature));

    if (r_epubkey < 0 || r_signature < 0) return -1;

    mol_table_t t;
    t.field_count   = 2;
    t.field_data[0] = f_epubkey;   t.field_len[0] = (uint32_t)r_epubkey;
    t.field_data[1] = f_signature; t.field_len[1] = (uint32_t)r_signature;

    return mol_table_encode(&t, buf, buf_size);
}

int secio_exchange_decode(const uint8_t *buf, uint32_t buf_size, secio_exchange_t *out) {
    if (!buf || !out) return -1;
    mol_table_t t;
    int consumed = mol_table_decode(buf, buf_size, &t);
    if (consumed < 0 || t.field_count < 2) return -1;

    memset(out, 0, sizeof(*out));

    const uint8_t *data; uint32_t len;

    if (mol_decode_bytes(t.field_data[0], t.field_len[0], &data, &len) < 0) return -1;
    if (len > 65) return -1;
    memcpy(out->epubkey, data, len);
    out->epubkey_len = len;

    if (mol_decode_bytes(t.field_data[1], t.field_len[1], &data, &len) < 0) return -1;
    if (len > 72) return -1;
    memcpy(out->signature, data, len);
    out->signature_len = len;

    return consumed;
}

/* ── PublicKey Molecule union ──
 * union PublicKey { Secp256k1(Bytes) }
 * Wire: [4-byte item index LE][payload bytes]
 * item index 0 = Secp256k1
 */
int mol_pubkey_encode(const uint8_t *pubkey, uint32_t pubkey_len,
                      uint8_t *buf, uint32_t buf_size) {
    /* 4-byte union tag + 4-byte Bytes header + key data */
    uint32_t total = 4 + 4 + pubkey_len;
    if (!buf || buf_size < total) return -1;
    mol_write_u32(buf, 0); /* Secp256k1 = item 0 */
    mol_encode_bytes(pubkey, pubkey_len, buf + 4, buf_size - 4);
    return (int)total;
}

int mol_pubkey_decode(const uint8_t *buf, uint32_t buf_size,
                      const uint8_t **pubkey_out, uint32_t *len_out) {
    if (!buf || buf_size < 8) return -1;
    uint32_t tag = mol_read_u32(buf);
    if (tag != 0) return -1; /* only Secp256k1 supported */
    return mol_decode_bytes(buf + 4, buf_size - 4, pubkey_out, len_out);
}
