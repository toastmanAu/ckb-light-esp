/*
 * test_protocol.c — Unit tests for Phase 3: RFC 0044 protocol messages
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../components/ckb_core/include/ckb_blake2b.h"
#include "../components/ckb_core/include/ckb_types.h"
#include "../components/ckb_core/include/ckb_mmr.h"
#include "../components/ckb_transport/include/ckb_molecule.h"
#include "../components/ckb_protocol/include/ckb_protocol.h"

static int tests_run = 0, tests_failed = 0;

#define ASSERT_INT(label, got, expected) \
    do { tests_run++; \
    if ((int)(got) != (int)(expected)) { \
        printf("FAIL: %s (got %d, expected %d)\n", label, (int)(got), (int)(expected)); \
        tests_failed++; } else printf("PASS: %s\n", label); } while(0)

#define ASSERT_BYTES(label, got, expected, len) \
    do { tests_run++; \
    if (memcmp(got, expected, len) != 0) { \
        printf("FAIL: %s\n", label); tests_failed++; } \
    else printf("PASS: %s\n", label); } while(0)

#define PASS(label) do { tests_run++; printf("PASS: %s\n", label); } while(0)
#define FAIL(label) do { tests_run++; tests_failed++; printf("FAIL: %s\n", label); } while(0)

/* ── Helpers ── */

static void fill_header_digest(ckb_header_digest_t *d, uint8_t seed) {
    memset(d->children_hash,    seed,    32);
    memset(d->total_difficulty, seed+1,  32);
    d->start_number         = 100 + seed;
    d->end_number           = 200 + seed;
    d->start_epoch          = 0x600020001ULL;
    d->end_epoch            = 0x600040002ULL;
    d->start_timestamp      = 1700000000ULL + seed;
    d->end_timestamp        = 1700001000ULL + seed;
    d->start_compact_target = 0x1a01d4ae;
    d->end_compact_target   = 0x1a01d4ae;
}

static void fill_header(ckb_header_t *h, uint64_t number) {
    memset(h, 0, sizeof(*h));
    h->version        = 0;
    h->number         = number;
    h->compact_target = 0x1a01d4ae;
    h->timestamp      = 1700000000ULL + number;
    h->epoch          = 0x600020001ULL;
    memset(h->parent_hash, (uint8_t)(number & 0xFF), 32);
    memset(h->transactions_root, 0xAA, 32);
    memset(h->proposals_hash,    0xBB, 32);
    memset(h->extra_hash,        0xCC, 32);
    memset(h->dao,               0xDD, 32);
    h->nonce[0] = (uint8_t)number;
}

static void fill_lc_verifiable_header(lc_verifiable_header_t *vh, uint64_t number, uint8_t seed) {
    memset(vh, 0, sizeof(*vh));
    fill_header(&vh->header, number);
    memset(vh->uncles_hash, seed, 32);
    vh->extension_len = 32;
    memset(vh->extension, seed + 0x10, 32);
    vh->extension_len = 32;
    fill_header_digest(&vh->parent_chain_root, seed);
}

/* ── Tests ── */

static void test_header_digest_roundtrip(void) {
    ckb_header_digest_t d, d2;
    fill_header_digest(&d, 0x42);

    uint8_t buf[LC_HEADER_DIGEST_SIZE];
    int r = lc_header_digest_encode(&d, buf);
    ASSERT_INT("lc_header_digest_encode returns 120", r, LC_HEADER_DIGEST_SIZE);

    r = lc_header_digest_decode(buf, &d2);
    ASSERT_INT("lc_header_digest_decode returns 120", r, LC_HEADER_DIGEST_SIZE);
    ASSERT_BYTES("digest.children_hash", d2.children_hash, d.children_hash, 32);
    ASSERT_BYTES("digest.total_difficulty", d2.total_difficulty, d.total_difficulty, 32);
    ASSERT_INT("digest.start_number", (int)d2.start_number, (int)d.start_number);
    ASSERT_INT("digest.end_number",   (int)d2.end_number,   (int)d.end_number);
    ASSERT_INT("digest.start_compact_target", (int)d2.start_compact_target, (int)d.start_compact_target);
    ASSERT_INT("digest.end_compact_target",   (int)d2.end_compact_target,   (int)d.end_compact_target);
}

static void test_verifiable_header_roundtrip(void) {
    lc_verifiable_header_t vh, vh2;
    fill_lc_verifiable_header(&vh, 12345678, 0x55);

    uint8_t buf[2048];
    int r = lc_verifiable_header_encode(&vh, buf, sizeof(buf));
    if (r < 0) { FAIL("lc_verifiable_header_encode"); return; }
    printf("  verifiable_header encoded: %d bytes\n", r);
    PASS("lc_verifiable_header_encode");

    int consumed = lc_verifiable_header_decode(buf, (uint32_t)r, &vh2);
    ASSERT_INT("lc_verifiable_header_decode consumed", consumed, r);
    ASSERT_INT("vh.header.number", (int)vh2.header.number, 12345678);
    ASSERT_INT("vh.header.compact_target", (int)vh2.header.compact_target, (int)vh.header.compact_target);
    ASSERT_BYTES("vh.uncles_hash", vh2.uncles_hash, vh.uncles_hash, 32);
    ASSERT_INT("1", vh2.extension_len > 0, 1);
    ASSERT_INT("vh.extension_len", (int)vh2.extension_len, 32);
    ASSERT_BYTES("vh.extension", vh2.extension, vh.extension, 32);
    ASSERT_INT("vh.parent_chain_root.start_number",
               (int)vh2.parent_chain_root.start_number, (int)vh.parent_chain_root.start_number);
}

static void test_get_last_state_roundtrip(void) {
    msg_get_last_state_t m = { .subscribe = 1 };
    uint8_t payload[64];
    int plen = msg_get_last_state_encode(&m, payload, sizeof(payload));
    if (plen < 0) { FAIL("get_last_state_encode"); return; }
    PASS("get_last_state_encode");

    /* Wrap in union */
    uint8_t buf[128];
    int total = lc_msg_wrap(MSG_GET_LAST_STATE, payload, (uint32_t)plen, buf, sizeof(buf));
    ASSERT_INT("lc_msg_wrap returns 4+plen", total, 4 + plen);
    ASSERT_INT("union item_id[0] = 0x00", buf[0], 0x00); /* LE item 0 */

    /* Unwrap */
    uint8_t id; const uint8_t *p; uint32_t pl;
    lc_msg_unwrap(buf, (uint32_t)total, &id, &p, &pl);
    ASSERT_INT("unwrapped id = MSG_GET_LAST_STATE", id, MSG_GET_LAST_STATE);

    msg_get_last_state_t m2;
    msg_get_last_state_decode(p, pl, &m2);
    ASSERT_INT("get_last_state.subscribe roundtrip", m2.subscribe, 1);
}

static void test_send_last_state_roundtrip(void) {
    msg_send_last_state_t m;
    fill_lc_verifiable_header(&m.last_header, 18686596, 0x11);

    uint8_t buf[4096];
    int r = msg_send_last_state_encode(&m, buf, sizeof(buf));
    if (r < 0) { FAIL("send_last_state_encode"); return; }
    printf("  send_last_state encoded: %d bytes\n", r);
    PASS("send_last_state_encode");

    msg_send_last_state_t m2;
    int consumed = msg_send_last_state_decode(buf, (uint32_t)r, &m2);
    ASSERT_INT("send_last_state_decode consumed", consumed, r);
    ASSERT_INT("send_last_state.number", (int)m2.last_header.header.number, 18686596);
    ASSERT_INT("send_last_state.compact_target",
               (int)m2.last_header.header.compact_target,
               (int)m.last_header.header.compact_target);
}

static void test_get_last_state_proof_roundtrip(void) {
    msg_get_last_state_proof_t m;
    memset(&m, 0, sizeof(m));
    memset(m.last_hash, 0xAA, 32);
    memset(m.start_hash, 0xBB, 32);
    m.start_number = 18000000;
    m.last_n_blocks = 50;
    memset(m.difficulty_boundary, 0xCC, 32);
    m.difficulties_count = 3;
    memset(m.difficulties[0], 0x11, 32);
    memset(m.difficulties[1], 0x22, 32);
    memset(m.difficulties[2], 0x33, 32);

    uint8_t buf[4096];
    int r = msg_get_last_state_proof_encode(&m, buf, sizeof(buf));
    if (r < 0) { FAIL("get_last_state_proof_encode"); return; }
    printf("  get_last_state_proof encoded: %d bytes\n", r);
    PASS("get_last_state_proof_encode");

    msg_get_last_state_proof_t m2;
    int consumed = msg_get_last_state_proof_decode(buf, (uint32_t)r, &m2);
    ASSERT_INT("proof_req decode consumed", consumed, r);
    ASSERT_BYTES("proof_req.last_hash", m2.last_hash, m.last_hash, 32);
    ASSERT_BYTES("proof_req.start_hash", m2.start_hash, m.start_hash, 32);
    ASSERT_INT("proof_req.start_number", (int)m2.start_number, 18000000);
    ASSERT_INT("proof_req.last_n_blocks", (int)m2.last_n_blocks, 50);
    ASSERT_INT("proof_req.difficulties_count", (int)m2.difficulties_count, 3);
    ASSERT_BYTES("proof_req.difficulties[0]", m2.difficulties[0], m.difficulties[0], 32);
    ASSERT_BYTES("proof_req.difficulties[2]", m2.difficulties[2], m.difficulties[2], 32);
}

static void test_get_blocks_proof_roundtrip(void) {
    msg_get_blocks_proof_t m;
    memset(&m, 0, sizeof(m));
    memset(m.last_hash, 0xFF, 32);
    m.block_hashes_count = 2;
    memset(m.block_hashes[0], 0x01, 32);
    memset(m.block_hashes[1], 0x02, 32);

    uint8_t buf[512];
    int r = msg_get_blocks_proof_encode(&m, buf, sizeof(buf));
    if (r < 0) { FAIL("get_blocks_proof_encode"); return; }
    PASS("get_blocks_proof_encode");

    msg_get_blocks_proof_t m2;
    int consumed = msg_get_blocks_proof_decode(buf, (uint32_t)r, &m2);
    ASSERT_INT("get_blocks_proof decode consumed", consumed, r);
    ASSERT_BYTES("blocks_proof.last_hash", m2.last_hash, m.last_hash, 32);
    ASSERT_INT("blocks_proof.count", (int)m2.block_hashes_count, 2);
    ASSERT_BYTES("blocks_proof.hash[0]", m2.block_hashes[0], m.block_hashes[0], 32);
    ASSERT_BYTES("blocks_proof.hash[1]", m2.block_hashes[1], m.block_hashes[1], 32);
}

static void test_flyclient_sampling(void) {
    lc_sync_ctx_t ctx;
    uint8_t start_diff[32] = {0};
    uint8_t end_diff[32]   = {0};
    /* end_diff = 18,686,596 * ~0x1000 (rough) — just a big number */
    end_diff[3] = 0x01; end_diff[2] = 0x20; end_diff[1] = 0x00;

    lc_sync_init(&ctx, NULL, 18000000, start_diff);
    int r = lc_flyclient_sample(&ctx, start_diff, end_diff, 686596, 40);
    ASSERT_INT("flyclient_sample returns 0", r, 0);
    if (ctx.sampled_count == 0) { FAIL("sampled_count > 0"); return; }
    PASS("sampled_count > 0");
    printf("  FlyClient samples: %u for chain_length=686596, lambda=40\n", ctx.sampled_count);

    /* Verify samples are monotonically increasing */
    int monotone = 1;
    for (uint32_t i = 1; i < ctx.sampled_count; i++) {
        /* Each difficulty[i] >= difficulty[i-1] */
        int cmp = 0;
        for (int b = 31; b >= 0; b--) {
            if (ctx.sampled_difficulties[i][b] > ctx.sampled_difficulties[i-1][b]) { cmp=1; break; }
            if (ctx.sampled_difficulties[i][b] < ctx.sampled_difficulties[i-1][b]) { cmp=-1; break; }
        }
        if (cmp < 0) { monotone = 0; break; }
    }
    ASSERT_INT("sampled difficulties are monotone increasing", monotone, 1);

    /* First sample must be > start_diff */
    int first_gt_start = 0;
    for (int b = 31; b >= 0; b--) {
        if (ctx.sampled_difficulties[0][b] > start_diff[b]) { first_gt_start=1; break; }
        if (ctx.sampled_difficulties[0][b] < start_diff[b]) break;
    }
    ASSERT_INT("first sample > start_diff", first_gt_start, 1);
}

static void test_sync_init(void) {
    lc_sync_ctx_t ctx;
    uint8_t genesis_hash[32] = {0};
    uint8_t genesis_diff[32] = {0};
    lc_sync_init(&ctx, genesis_hash, 0, genesis_diff);
    ASSERT_INT("sync init state = IDLE", (int)ctx.state, (int)LC_SYNC_IDLE);
    ASSERT_INT("sync last_n_blocks = 50", (int)ctx.last_n_blocks, 50);
    ASSERT_INT("sync subscribe = 1", ctx.subscribe, 1);
}

static void test_build_get_last_state(void) {
    lc_sync_ctx_t ctx;
    lc_sync_init(&ctx, NULL, 0, NULL);

    uint8_t buf[256];
    int r = lc_sync_build_get_last_state(&ctx, buf, sizeof(buf));
    if (r < 0) { FAIL("build_get_last_state"); return; }
    PASS("build_get_last_state succeeds");
    ASSERT_INT("state → WAIT_LAST_STATE", (int)ctx.state, (int)LC_SYNC_WAIT_LAST_STATE);

    /* Check union item_id = 0 (GetLastState) */
    uint32_t id = (uint32_t)buf[0] | ((uint32_t)buf[1]<<8) |
                  ((uint32_t)buf[2]<<16) | ((uint32_t)buf[3]<<24);
    ASSERT_INT("union item_id = MSG_GET_LAST_STATE", (int)id, MSG_GET_LAST_STATE);
}

static void test_send_last_state_proof_roundtrip(void) {
    msg_send_last_state_proof_t m;
    memset(&m, 0, sizeof(m));
    fill_lc_verifiable_header(&m.last_header, 18686596, 0xAA);

    /* Add 2 proof nodes */
    m.proof_count = 2;
    fill_header_digest(&m.proof[0], 0x10);
    fill_header_digest(&m.proof[1], 0x20);

    /* Add 2 sampled headers */
    m.headers_count = 2;
    fill_lc_verifiable_header(&m.headers[0], 18500000, 0x30);
    fill_lc_verifiable_header(&m.headers[1], 18600000, 0x40);

    uint8_t buf[16384];
    int r = msg_send_last_state_proof_encode(&m, buf, sizeof(buf));
    if (r < 0) { FAIL("send_last_state_proof_encode"); return; }
    printf("  send_last_state_proof encoded: %d bytes\n", r);
    PASS("send_last_state_proof_encode");

    msg_send_last_state_proof_t m2;
    int consumed = msg_send_last_state_proof_decode(buf, (uint32_t)r, &m2);
    ASSERT_INT("send_proof decode consumed", consumed, r);
    ASSERT_INT("proof.last_header.number", (int)m2.last_header.header.number, 18686596);
    ASSERT_INT("proof.proof_count", (int)m2.proof_count, 2);
    ASSERT_INT("proof.headers_count", (int)m2.headers_count, 2);
    ASSERT_BYTES("proof[0].children_hash",
                 m2.proof[0].children_hash, m.proof[0].children_hash, 32);
    ASSERT_INT("headers[0].number", (int)m2.headers[0].header.number, 18500000);
    ASSERT_INT("headers[1].number", (int)m2.headers[1].header.number, 18600000);
}

int main(void) {
    printf("=== CKB Protocol (RFC 0044) Tests ===\n\n");

    printf("--- HeaderDigest ---\n");
    test_header_digest_roundtrip();

    printf("\n--- VerifiableHeader ---\n");
    test_verifiable_header_roundtrip();

    printf("\n--- Protocol Messages ---\n");
    test_get_last_state_roundtrip();
    test_send_last_state_roundtrip();
    test_get_last_state_proof_roundtrip();
    test_get_blocks_proof_roundtrip();
    test_send_last_state_proof_roundtrip();

    printf("\n--- FlyClient Sync State Machine ---\n");
    test_sync_init();
    test_build_get_last_state();
    test_flyclient_sampling();

    printf("\n=== Results: %d/%d passed ===\n",
           tests_run - tests_failed, tests_run);
    return tests_failed > 0 ? 1 : 0;
}
