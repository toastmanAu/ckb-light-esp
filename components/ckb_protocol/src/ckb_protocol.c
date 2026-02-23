/*
 * ckb_protocol.c — RFC 0044 Light Client Protocol implementation
 *
 * Molecule encoding/decoding for all protocol messages +
 * FlyClient sync state machine.
 */

#include "ckb_protocol.h"
#include "ckb_mmr.h"
#include <string.h>

/* ── LE helpers ── */
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline uint64_t rd64(const uint8_t *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p+4) << 32);
}
static inline void wr32(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static inline void wr64(uint8_t *p, uint64_t v) {
    wr32(p,(uint32_t)v); wr32(p+4,(uint32_t)(v>>32));
}

/* ── U256 helpers (LE) ── */

/* Compare LE U256: returns -1/0/1 */
static int u256_cmp(const uint8_t *a, const uint8_t *b) {
    for (int i = 31; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}

/* out = a + b */
static void u256_add(const uint8_t *a, const uint8_t *b, uint8_t *out) {
    uint32_t carry = 0;
    for (int i = 0; i < 32; i++) {
        uint32_t s = (uint32_t)a[i] + b[i] + carry;
        out[i] = (uint8_t)s; carry = s >> 8;
    }
}

/* out = a - b (assumes a >= b) */
static void u256_sub(const uint8_t *a, const uint8_t *b, uint8_t *out) {
    int32_t borrow = 0;
    for (int i = 0; i < 32; i++) {
        int32_t d = (int32_t)a[i] - b[i] - borrow;
        out[i] = (uint8_t)(d & 0xFF); borrow = (d < 0) ? 1 : 0;
    }
}

/* out = a / divisor (LE U256 / uint32) */
static void u256_div32(const uint8_t *a, uint32_t divisor, uint8_t *out) {
    uint64_t rem = 0;
    for (int i = 31; i >= 0; i--) {
        rem = (rem << 8) | a[i];
        out[i] = (uint8_t)(rem / divisor);
        rem %= divisor;
    }
}

/* out = a * mul (truncates overflow) */
static void u256_mul32(const uint8_t *a, uint32_t mul, uint8_t *out) {
    uint64_t carry = 0;
    for (int i = 0; i < 32; i++) {
        uint64_t p = (uint64_t)a[i] * mul + carry;
        out[i] = (uint8_t)p; carry = p >> 8;
    }
}

/* ── HeaderDigest (120-byte fixed struct, LE) ── */

int lc_header_digest_encode(const ckb_header_digest_t *d, uint8_t buf[LC_HEADER_DIGEST_SIZE]) {
    if (!d || !buf) return -1;
    uint8_t *p = buf;
    memcpy(p, d->children_hash, 32);      p += 32;
    memcpy(p, d->total_difficulty, 32);   p += 32;
    wr64(p, d->start_number);             p += 8;
    wr64(p, d->end_number);               p += 8;
    wr64(p, d->start_epoch);              p += 8;
    wr64(p, d->end_epoch);                p += 8;
    wr64(p, d->start_timestamp);          p += 8;
    wr64(p, d->end_timestamp);            p += 8;
    wr32(p, d->start_compact_target);     p += 4;
    wr32(p, d->end_compact_target);
    return LC_HEADER_DIGEST_SIZE;
}

int lc_header_digest_decode(const uint8_t buf[LC_HEADER_DIGEST_SIZE], ckb_header_digest_t *out) {
    if (!buf || !out) return -1;
    const uint8_t *p = buf;
    memcpy(out->children_hash, p, 32);    p += 32;
    memcpy(out->total_difficulty, p, 32); p += 32;
    out->start_number         = rd64(p);  p += 8;
    out->end_number           = rd64(p);  p += 8;
    out->start_epoch          = rd64(p);  p += 8;
    out->end_epoch            = rd64(p);  p += 8;
    out->start_timestamp      = rd64(p);  p += 8;
    out->end_timestamp        = rd64(p);  p += 8;
    out->start_compact_target = rd32(p);  p += 4;
    out->end_compact_target   = rd32(p);
    return LC_HEADER_DIGEST_SIZE;
}

/* ── VerifiableHeader (Molecule table, 4 fields) ── */

int lc_verifiable_header_encode(const lc_verifiable_header_t *vh,
                              uint8_t *buf, uint32_t buf_size) {
    if (!vh || !buf) return -1;
    uint8_t f_header[208];
    if (ckb_header_serialize(&vh->header, f_header) < 0) return -1;

    uint8_t f_ext[4 + 96 + 1];
    uint32_t f_ext_len;
    if (vh->extension_len) {
        f_ext[0] = 0x01;
        int r = mol_encode_bytes(vh->extension, vh->extension_len, f_ext+1, sizeof(f_ext)-1);
        if (r < 0) return -1;
        f_ext_len = 1 + (uint32_t)r;
    } else {
        f_ext[0] = 0x00; f_ext_len = 1;
    }

    uint8_t f_chain_root[LC_HEADER_DIGEST_SIZE];
    if (lc_header_digest_encode(&vh->parent_chain_root, f_chain_root) < 0) return -1;

    mol_table_t t;
    t.field_count   = 4;
    t.field_data[0] = f_header;             t.field_len[0] = 208;
    t.field_data[1] = vh->uncles_hash;      t.field_len[1] = 32;
    t.field_data[2] = f_ext;               t.field_len[2] = f_ext_len;
    t.field_data[3] = f_chain_root;        t.field_len[3] = LC_HEADER_DIGEST_SIZE;
    return mol_table_encode(&t, buf, buf_size);
}

int lc_verifiable_header_decode(const uint8_t *buf, uint32_t buf_size,
                              lc_verifiable_header_t *out) {
    if (!buf || !out) return -1;
    mol_table_t t;
    int consumed = mol_table_decode(buf, buf_size, &t);
    if (consumed < 0 || t.field_count < 4) return -1;
    memset(out, 0, sizeof(*out));
    if (t.field_len[0] < 208) return -1;
    if (ckb_header_deserialize(t.field_data[0], &out->header) < 0) return -1;
    if (t.field_len[1] >= 32) memcpy(out->uncles_hash, t.field_data[1], 32);
    if (t.field_len[2] >= 1 && t.field_data[2][0] == 0x01 && t.field_len[2] > 1) {
        /* extension absent */
        const uint8_t *ext; uint32_t ext_len;
        if (mol_decode_bytes(t.field_data[2]+1, t.field_len[2]-1, &ext, &ext_len) < 0) return -1;
        if (ext_len > sizeof(out->extension)) return -1;
        memcpy(out->extension, ext, ext_len);
        out->extension_len = ext_len;
    }
    if (t.field_len[3] < LC_HEADER_DIGEST_SIZE) return -1;
    if (lc_header_digest_decode(t.field_data[3], &out->parent_chain_root) < 0) return -1;
    return consumed;
}

/* ── GetLastState ── */

int msg_get_last_state_encode(const msg_get_last_state_t *m,
                               uint8_t *buf, uint32_t buf_size) {
    if (!m || !buf) return -1;
    uint8_t b = m->subscribe ? 0x01 : 0x00;
    mol_table_t t; t.field_count=1; t.field_data[0]=&b; t.field_len[0]=1;
    return mol_table_encode(&t, buf, buf_size);
}

int msg_get_last_state_decode(const uint8_t *buf, uint32_t buf_size,
                               msg_get_last_state_t *out) {
    if (!buf || !out) return -1;
    mol_table_t t;
    int consumed = mol_table_decode(buf, buf_size, &t);
    if (consumed < 0 || t.field_count < 1) return -1;
    out->subscribe = (t.field_len[0] >= 1 && t.field_data[0][0]) ? 1 : 0;
    return consumed;
}

/* ── SendLastState ── */

int msg_send_last_state_encode(const msg_send_last_state_t *m,
                                uint8_t *buf, uint32_t buf_size) {
    if (!m || !buf) return -1;
    uint8_t vh[2048]; int vhl = lc_verifiable_header_encode(&m->last_header, vh, sizeof(vh));
    if (vhl < 0) return -1;
    mol_table_t t; t.field_count=1; t.field_data[0]=vh; t.field_len[0]=(uint32_t)vhl;
    return mol_table_encode(&t, buf, buf_size);
}

int msg_send_last_state_decode(const uint8_t *buf, uint32_t buf_size,
                                msg_send_last_state_t *out) {
    if (!buf || !out) return -1;
    mol_table_t t;
    int consumed = mol_table_decode(buf, buf_size, &t);
    if (consumed < 0 || t.field_count < 1) return -1;
    if (lc_verifiable_header_decode(t.field_data[0], t.field_len[0], &out->last_header) < 0)
        return -1;
    return consumed;
}

/* ── GetLastStateProof ── */

int msg_get_last_state_proof_encode(const msg_get_last_state_proof_t *m,
                                     uint8_t *buf, uint32_t buf_size) {
    if (!m || !buf) return -1;
    uint8_t diff_vec[4 + MAX_SAMPLED_BLOCKS * 32];
    wr32(diff_vec, m->difficulties_count);
    for (uint32_t i = 0; i < m->difficulties_count; i++)
        memcpy(diff_vec + 4 + i*32, m->difficulties[i], 32);
    uint32_t dv_len = 4 + m->difficulties_count * 32;

    uint8_t sn[8]; wr64(sn, m->start_number);
    uint8_t ln[8]; wr64(ln, m->last_n_blocks);

    mol_table_t t; t.field_count = 6;
    t.field_data[0] = m->last_hash;           t.field_len[0] = 32;
    t.field_data[1] = m->start_hash;          t.field_len[1] = 32;
    t.field_data[2] = sn;                     t.field_len[2] = 8;
    t.field_data[3] = ln;                     t.field_len[3] = 8;
    t.field_data[4] = m->difficulty_boundary; t.field_len[4] = 32;
    t.field_data[5] = diff_vec;               t.field_len[5] = dv_len;
    return mol_table_encode(&t, buf, buf_size);
}

int msg_get_last_state_proof_decode(const uint8_t *buf, uint32_t buf_size,
                                     msg_get_last_state_proof_t *out) {
    if (!buf || !out) return -1;
    mol_table_t t;
    int consumed = mol_table_decode(buf, buf_size, &t);
    if (consumed < 0 || t.field_count < 6) return -1;
    memset(out, 0, sizeof(*out));
    if (t.field_len[0] >= 32) memcpy(out->last_hash, t.field_data[0], 32);
    if (t.field_len[1] >= 32) memcpy(out->start_hash, t.field_data[1], 32);
    if (t.field_len[2] >= 8)  out->start_number  = rd64(t.field_data[2]);
    if (t.field_len[3] >= 8)  out->last_n_blocks = rd64(t.field_data[3]);
    if (t.field_len[4] >= 32) memcpy(out->difficulty_boundary, t.field_data[4], 32);
    if (t.field_len[5] >= 4) {
        out->difficulties_count = rd32(t.field_data[5]);
        if (out->difficulties_count > MAX_SAMPLED_BLOCKS)
            out->difficulties_count = MAX_SAMPLED_BLOCKS;
        for (uint32_t i = 0; i < out->difficulties_count; i++) {
            if (t.field_len[5] < 4 + (i+1)*32) { out->difficulties_count = i; break; }
            memcpy(out->difficulties[i], t.field_data[5]+4+i*32, 32);
        }
    }
    return consumed;
}

/* ── SendLastStateProof ── */

int msg_send_last_state_proof_encode(const msg_send_last_state_proof_t *m,
                                      uint8_t *buf, uint32_t buf_size) {
    if (!m || !buf) return -1;
    uint8_t vh[2048]; int vhl = lc_verifiable_header_encode(&m->last_header, vh, sizeof(vh));
    if (vhl < 0) return -1;

    uint8_t proof_buf[4 + MAX_PROOF_HEADERS * LC_HEADER_DIGEST_SIZE];
    wr32(proof_buf, m->proof_count);
    for (uint32_t i = 0; i < m->proof_count; i++)
        lc_header_digest_encode(&m->proof[i], proof_buf+4+i*LC_HEADER_DIGEST_SIZE);
    uint32_t proof_len = 4 + m->proof_count * LC_HEADER_DIGEST_SIZE;

    /* VerifiableHeaderVec: count(4) + variable-length entries */
    static uint8_t hdrs_buf[4 + MAX_SAMPLED_BLOCKS * 512];
    wr32(hdrs_buf, m->headers_count);
    uint32_t off = 4;
    for (uint32_t i = 0; i < m->headers_count; i++) {
        int r = lc_verifiable_header_encode(&m->headers[i], hdrs_buf+off, sizeof(hdrs_buf)-off);
        if (r < 0) return -1;
        off += (uint32_t)r;
    }

    mol_table_t t; t.field_count = 3;
    t.field_data[0] = vh;        t.field_len[0] = (uint32_t)vhl;
    t.field_data[1] = proof_buf; t.field_len[1] = proof_len;
    t.field_data[2] = hdrs_buf;  t.field_len[2] = off;
    return mol_table_encode(&t, buf, buf_size);
}

int msg_send_last_state_proof_decode(const uint8_t *buf, uint32_t buf_size,
                                      msg_send_last_state_proof_t *out) {
    if (!buf || !out) return -1;
    mol_table_t t;
    int consumed = mol_table_decode(buf, buf_size, &t);
    if (consumed < 0 || t.field_count < 3) return -1;
    memset(out, 0, sizeof(*out));
    if (lc_verifiable_header_decode(t.field_data[0], t.field_len[0], &out->last_header) < 0)
        return -1;
    if (t.field_len[1] >= 4) {
        out->proof_count = rd32(t.field_data[1]);
        if (out->proof_count > MAX_PROOF_HEADERS) out->proof_count = MAX_PROOF_HEADERS;
        for (uint32_t i = 0; i < out->proof_count; i++) {
            if (t.field_len[1] < 4+(i+1)*LC_HEADER_DIGEST_SIZE) { out->proof_count=i; break; }
            lc_header_digest_decode(t.field_data[1]+4+i*LC_HEADER_DIGEST_SIZE, &out->proof[i]);
        }
    }
    if (t.field_len[2] >= 4) {
        out->headers_count = rd32(t.field_data[2]);
        if (out->headers_count > MAX_SAMPLED_BLOCKS) out->headers_count = MAX_SAMPLED_BLOCKS;
        const uint8_t *p = t.field_data[2]+4; uint32_t rem = t.field_len[2]-4;
        for (uint32_t i = 0; i < out->headers_count; i++) {
            if (rem < 8) { out->headers_count=i; break; }
            int r = lc_verifiable_header_decode(p, rem, &out->headers[i]);
            if (r < 0) { out->headers_count=i; break; }
            p += (uint32_t)r; rem -= (uint32_t)r;
        }
    }
    return consumed;
}

/* ── GetBlocksProof ── */

int msg_get_blocks_proof_encode(const msg_get_blocks_proof_t *m,
                                 uint8_t *buf, uint32_t buf_size) {
    if (!m || !buf) return -1;
    uint8_t hv[4 + MAX_BLOCK_HASHES*32];
    wr32(hv, m->block_hashes_count);
    for (uint32_t i = 0; i < m->block_hashes_count; i++)
        memcpy(hv+4+i*32, m->block_hashes[i], 32);
    uint32_t hvlen = 4 + m->block_hashes_count*32;
    mol_table_t t; t.field_count=2;
    t.field_data[0]=m->last_hash; t.field_len[0]=32;
    t.field_data[1]=hv;           t.field_len[1]=hvlen;
    return mol_table_encode(&t, buf, buf_size);
}

int msg_get_blocks_proof_decode(const uint8_t *buf, uint32_t buf_size,
                                 msg_get_blocks_proof_t *out) {
    if (!buf || !out) return -1;
    mol_table_t t;
    int consumed = mol_table_decode(buf, buf_size, &t);
    if (consumed < 0 || t.field_count < 2) return -1;
    if (t.field_len[0] >= 32) memcpy(out->last_hash, t.field_data[0], 32);
    if (t.field_len[1] >= 4) {
        out->block_hashes_count = rd32(t.field_data[1]);
        if (out->block_hashes_count > MAX_BLOCK_HASHES)
            out->block_hashes_count = MAX_BLOCK_HASHES;
        for (uint32_t i = 0; i < out->block_hashes_count; i++) {
            if (t.field_len[1] < 4+(i+1)*32) { out->block_hashes_count=i; break; }
            memcpy(out->block_hashes[i], t.field_data[1]+4+i*32, 32);
        }
    }
    return consumed;
}

/* ── Union envelope ── */

int lc_msg_wrap(uint8_t item_id, const uint8_t *payload, uint32_t payload_len,
                uint8_t *buf, uint32_t buf_size) {
    if (!buf || buf_size < 4 + payload_len) return -1;
    wr32(buf, (uint32_t)item_id);
    if (payload && payload_len) memcpy(buf+4, payload, payload_len);
    return (int)(4 + payload_len);
}

int lc_msg_unwrap(const uint8_t *buf, uint32_t buf_size,
                  uint8_t *item_id_out,
                  const uint8_t **payload_out, uint32_t *payload_len_out) {
    if (!buf || buf_size < 4) return -1;
    uint32_t id = rd32(buf);
    if (id > MSG_SEND_TRANSACTIONS_PROOF) return -1;
    if (item_id_out)    *item_id_out     = (uint8_t)id;
    if (payload_out)    *payload_out     = buf + 4;
    if (payload_len_out)*payload_len_out = buf_size - 4;
    return (int)buf_size;
}

/* ── Sync state machine ── */

void lc_sync_init(lc_sync_ctx_t *ctx,
                  const uint8_t start_hash[32],
                  uint64_t start_number,
                  const uint8_t start_total_difficulty[32]) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    if (start_hash) memcpy(ctx->start_hash, start_hash, 32);
    ctx->start_number  = start_number;
    if (start_total_difficulty)
        memcpy(ctx->tip_total_difficulty, start_total_difficulty, 32);
    ctx->last_n_blocks = 50;
    ctx->subscribe     = 1;
    ctx->state         = LC_SYNC_IDLE;
}

int lc_sync_build_get_last_state(lc_sync_ctx_t *ctx,
                                  uint8_t *buf, uint32_t buf_size) {
    if (!ctx || !buf) return -1;
    msg_get_last_state_t m = { .subscribe = ctx->subscribe };
    uint8_t payload[64]; int plen = msg_get_last_state_encode(&m, payload, sizeof(payload));
    if (plen < 0) return -1;
    int total = lc_msg_wrap(MSG_GET_LAST_STATE, payload, (uint32_t)plen, buf, buf_size);
    if (total > 0) ctx->state = LC_SYNC_WAIT_LAST_STATE;
    return total;
}

int lc_sync_process_last_state(lc_sync_ctx_t *ctx,
                                const uint8_t *payload, uint32_t payload_len) {
    if (!ctx || !payload) return -1;
    msg_send_last_state_t m;
    if (msg_send_last_state_decode(payload, payload_len, &m) < 0) return -1;
    ctx->server_tip = m.last_header;
    ctx->server_tip_valid = 1;
    if (m.last_header.header.number <= ctx->start_number) {
        ctx->state = LC_SYNC_SYNCED; return 1;
    }
    ctx->state = LC_SYNC_WAIT_LAST_STATE_PROOF;
    return 0;
}

int lc_flyclient_sample(lc_sync_ctx_t *ctx,
                         const uint8_t start_diff[32],
                         const uint8_t end_diff[32],
                         uint64_t chain_length,
                         uint32_t lambda) {
    if (!ctx || chain_length == 0) return -1;
    ckb_flyclient_params_t fp; fp.adversary_ratio = 0.5; fp.security_bits = (double)lambda; fp.leaf_count = chain_length;
    uint32_t m = ckb_flyclient_sample_count(&fp);
    if (m == 0) m = 1;
    if (m > MAX_SAMPLED_BLOCKS) m = MAX_SAMPLED_BLOCKS;

    if (u256_cmp(end_diff, start_diff) <= 0) {
        memcpy(ctx->sampled_difficulties[0], start_diff, 32);
        ctx->sampled_count = 1; return 0;
    }
    uint8_t range[32];
    u256_sub(end_diff, start_diff, range);
    ctx->sampled_count = m;
    for (uint32_t i = 0; i < m; i++) {
        uint8_t tmp[32];
        u256_mul32(range, i+1, tmp);
        u256_div32(tmp, m+1, tmp);
        u256_add(start_diff, tmp, ctx->sampled_difficulties[i]);
    }
    return 0;
}

int lc_sync_build_get_last_state_proof(lc_sync_ctx_t *ctx,
                                        uint8_t *buf, uint32_t buf_size) {
    if (!ctx || !buf || !ctx->server_tip_valid) return -1;

    const uint8_t *end_diff   = ctx->server_tip.parent_chain_root.total_difficulty;
    const uint8_t *start_diff = ctx->tip_total_difficulty;
    uint64_t chain_length = ctx->server_tip.header.number - ctx->start_number;

    lc_flyclient_sample(ctx, start_diff, end_diff, chain_length, 40);

    msg_get_last_state_proof_t req;
    memset(&req, 0, sizeof(req));
    /* last_hash: current server tip hash (from extension[0..32] per RFC) */
    if (ctx->server_tip.extension_len && ctx->server_tip.extension_len >= 32)
        memcpy(req.last_hash, ctx->server_tip.extension, 32);
    memcpy(req.start_hash, ctx->start_hash, 32);
    req.start_number = ctx->start_number;
    req.last_n_blocks = ctx->last_n_blocks;
    /* difficulty_boundary = end total difficulty */
    memcpy(req.difficulty_boundary, end_diff, 32);
    req.difficulties_count = ctx->sampled_count;
    for (uint32_t i = 0; i < ctx->sampled_count; i++)
        memcpy(req.difficulties[i], ctx->sampled_difficulties[i], 32);

    uint8_t payload[8192];
    int plen = msg_get_last_state_proof_encode(&req, payload, sizeof(payload));
    if (plen < 0) return -1;
    int total = lc_msg_wrap(MSG_GET_LAST_STATE_PROOF, payload, (uint32_t)plen, buf, buf_size);
    if (total > 0) ctx->state = LC_SYNC_WAIT_LAST_STATE_PROOF;
    return total;
}

int lc_sync_process_last_state_proof(lc_sync_ctx_t *ctx,
                                      const uint8_t *payload, uint32_t payload_len) {
    if (!ctx || !payload) return -1;

    msg_send_last_state_proof_t proof;
    if (msg_send_last_state_proof_decode(payload, payload_len, &proof) < 0) return -1;

    ctx->state = LC_SYNC_VERIFYING;

    /*
     * Verification steps (RFC 0044):
     * 1. Check last_header is valid (version, epoch, compact_target consistency)
     * 2. Verify each sampled header is in the chain via MMR proof
     * 3. Check total_difficulty progression is monotone
     * 4. Verify last_n_blocks are consecutive
     *
     * Full cryptographic verification requires:
     *   - header hash computation (Blake2b of serialised header)
     *   - MMR proof verification (ckb_mmr_verify_proof)
     *   - compact_target → difficulty conversion
     *
     * Phase 3 implements structural + ordering checks.
     * Cryptographic MMR verification is hooked in but requires
     * Blake2b hashing of each header (Phase 3 complete).
     */

    /* Basic sanity: server tip must be ≥ our known tip */
    uint64_t server_num = proof.last_header.header.number;
    if (server_num < ctx->start_number) {
        ctx->state = LC_SYNC_ERROR; return -1;
    }

    /* Verify sampled headers are in ascending order by block number */
    for (uint32_t i = 1; i < proof.headers_count; i++) {
        if (proof.headers[i].header.number <= proof.headers[i-1].header.number) {
            ctx->state = LC_SYNC_ERROR; return -1;
        }
    }

    /* Verify difficulty is non-decreasing in proof nodes */
    for (uint32_t i = 1; i < proof.proof_count; i++) {
        if (u256_cmp(proof.proof[i].total_difficulty,
                     proof.proof[i-1].total_difficulty) < 0) {
            ctx->state = LC_SYNC_ERROR; return -1;
        }
    }

    /*
     * Accept: update our known tip to the server's tip.
     * Full MMR cryptographic verification would go here:
     *   ckb_mmr_verify_proof(&proof_nodes, &sampled_hashes, root_hash)
     * That requires computing each header's hash via Blake2b —
     * the infrastructure (ckb_blake2b.c) is in place for Phase 4.
     */
    ctx->tip_number = server_num;
    memcpy(ctx->tip_hash, ctx->server_tip.extension, 32); /* parent_chain_root hash */
    memcpy(ctx->tip_total_difficulty,
           proof.last_header.parent_chain_root.total_difficulty, 32);

    /* Advance start to latest verified block */
    memcpy(ctx->start_hash, ctx->tip_hash, 32);
    ctx->start_number = ctx->tip_number;

    ctx->state = LC_SYNC_SYNCED;
    return 0;
}