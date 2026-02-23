/*
 * test_transport.c — Unit tests for Phase 2: Molecule, Yamux, SecIO
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../components/ckb_transport/include/ckb_molecule.h"
#include "../components/ckb_transport/include/ckb_yamux.h"
#include "../components/ckb_transport/include/ckb_secio.h"

static int tests_run = 0;
static int tests_failed = 0;

#define PASS(label) do { tests_run++; printf("PASS: %s\n", label); } while(0)
#define FAIL(label, ...) do { tests_run++; tests_failed++; printf("FAIL: " label "\n", ##__VA_ARGS__); } while(0)

#define ASSERT_INT(label, got, expected) \
    do { tests_run++; \
    if ((int)(got) != (int)(expected)) { \
        printf("FAIL: %s (got %d, expected %d)\n", label, (int)(got), (int)(expected)); \
        tests_failed++; } \
    else printf("PASS: %s\n", label); } while(0)

#define ASSERT_BYTES(label, got, expected, len) \
    do { tests_run++; \
    if (memcmp(got, expected, len) != 0) { \
        printf("FAIL: %s\n", label); tests_failed++; } \
    else printf("PASS: %s\n", label); } while(0)

#define ASSERT_STR(label, got, expected, len) \
    do { tests_run++; \
    if (memcmp(got, expected, len) != 0) { \
        printf("FAIL: %s (got '%.*s', expected '%s')\n", label, (int)(len), (char*)(got), expected); \
        tests_failed++; } \
    else printf("PASS: %s\n", label); } while(0)

/* ── Molecule tests ── */

static void test_mol_bytes_roundtrip(void) {
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0xAB, 0xCD};
    uint8_t buf[32];
    int written = mol_encode_bytes(data, sizeof(data), buf, sizeof(buf));
    ASSERT_INT("mol_encode_bytes returns 10", written, 10); /* 4 + 6 */

    /* Check header */
    uint32_t hdr = mol_read_u32(buf);
    ASSERT_INT("mol_bytes header = 10", (int)hdr, 6);  /* header = data_len only */

    /* Decode */
    const uint8_t *out; uint32_t out_len;
    int consumed = mol_decode_bytes(buf, (uint32_t)written, &out, &out_len);
    ASSERT_INT("mol_decode_bytes consumed 10", consumed, 10);
    ASSERT_INT("mol_decode_bytes len = 6", (int)out_len, 6);
    ASSERT_BYTES("mol_bytes roundtrip data", out, data, 6);
}

static void test_mol_empty_bytes(void) {
    uint8_t buf[8];
    int written = mol_encode_bytes(NULL, 0, buf, sizeof(buf));
    ASSERT_INT("mol_encode empty bytes = 4", written, 4);
    uint32_t hdr = mol_read_u32(buf);
    ASSERT_INT("mol_empty header = 4", (int)hdr, 0);  /* header = data_len = 0 for empty */
    const uint8_t *out; uint32_t out_len;
    mol_decode_bytes(buf, 4, &out, &out_len);
    ASSERT_INT("mol_decode empty len = 0", (int)out_len, 0);
}

static void test_mol_table_roundtrip(void) {
    uint8_t f0[] = {0x01, 0x02};
    uint8_t f1[] = {0xAA, 0xBB, 0xCC};
    uint8_t f2[] = {0xFF};

    mol_table_t t;
    t.field_count   = 3;
    t.field_data[0] = f0; t.field_len[0] = 2;
    t.field_data[1] = f1; t.field_len[1] = 3;
    t.field_data[2] = f2; t.field_len[2] = 1;

    uint32_t expected_size = 4 + 3*4 + 2 + 3 + 1; /* = 22: total(4) + offsets(12) + data(6) */
    ASSERT_INT("mol_table_encoded_size", (int)mol_table_encoded_size(&t), (int)expected_size);

    uint8_t buf[64];
    int written = mol_table_encode(&t, buf, sizeof(buf));
    ASSERT_INT("mol_table_encode returns 22", written, (int)expected_size);

    /* Decode back */
    mol_table_t t2;
    int consumed = mol_table_decode(buf, (uint32_t)written, &t2);
    ASSERT_INT("mol_table_decode consumed 22", consumed, (int)expected_size);
    ASSERT_INT("mol_table field_count = 3", (int)t2.field_count, 3);
    ASSERT_INT("mol_table f0 len = 2", (int)t2.field_len[0], 2);
    ASSERT_INT("mol_table f1 len = 3", (int)t2.field_len[1], 3);
    ASSERT_INT("mol_table f2 len = 1", (int)t2.field_len[2], 1);
    ASSERT_BYTES("mol_table f0 data", t2.field_data[0], f0, 2);
    ASSERT_BYTES("mol_table f1 data", t2.field_data[1], f1, 3);
    ASSERT_BYTES("mol_table f2 data", t2.field_data[2], f2, 1);
}

static void test_secio_propose_roundtrip(void) {
    secio_propose_t p;
    memset(&p, 0, sizeof(p));

    memset(p.rand, 0x42, 16);
    p.pubkey[0] = 0x02; /* compressed secp256k1 */
    memset(p.pubkey + 1, 0xAB, 32);
    p.pubkey_len = 33;

    const char *exch = "P-256";
    const char *ciph = "AES-128";
    const char *hash = "SHA-256";
    memcpy(p.exchanges, exch, strlen(exch)); p.exchanges_len = (uint32_t)strlen(exch);
    memcpy(p.ciphers,   ciph, strlen(ciph)); p.ciphers_len   = (uint32_t)strlen(ciph);
    memcpy(p.hashes,    hash, strlen(hash)); p.hashes_len    = (uint32_t)strlen(hash);

    uint8_t buf[1024];
    int written = secio_propose_encode(&p, buf, sizeof(buf));
    if (written < 0) { FAIL("secio_propose_encode"); return; }
    printf("  propose encoded: %d bytes\n", written);
    PASS("secio_propose_encode succeeds");

    secio_propose_t p2;
    int consumed = secio_propose_decode(buf, (uint32_t)written, &p2);
    ASSERT_INT("secio_propose_decode consumed", consumed, written);
    ASSERT_BYTES("propose.rand roundtrip", p2.rand, p.rand, 16);
    ASSERT_INT("propose.pubkey_len roundtrip", (int)p2.pubkey_len, (int)p.pubkey_len);
    ASSERT_BYTES("propose.pubkey roundtrip", p2.pubkey, p.pubkey, p.pubkey_len);
    ASSERT_STR("propose.exchanges", p2.exchanges, exch, p2.exchanges_len);
    ASSERT_STR("propose.ciphers",   p2.ciphers,   ciph, p2.ciphers_len);
    ASSERT_STR("propose.hashes",    p2.hashes,    hash, p2.hashes_len);
}

static void test_secio_exchange_roundtrip(void) {
    secio_exchange_t e;
    memset(&e, 0, sizeof(e));
    e.epubkey[0] = 0x04; /* uncompressed P-256 */
    memset(e.epubkey + 1, 0xCD, 64);
    e.epubkey_len = 65;
    memset(e.signature, 0x30, 70); /* fake DER signature */
    e.signature_len = 70;

    uint8_t buf[512];
    int written = secio_exchange_encode(&e, buf, sizeof(buf));
    if (written < 0) { FAIL("secio_exchange_encode"); return; }
    PASS("secio_exchange_encode succeeds");

    secio_exchange_t e2;
    int consumed = secio_exchange_decode(buf, (uint32_t)written, &e2);
    ASSERT_INT("secio_exchange_decode consumed", consumed, written);
    ASSERT_INT("exchange.epubkey_len", (int)e2.epubkey_len, 65);
    ASSERT_BYTES("exchange.epubkey", e2.epubkey, e.epubkey, 65);
    ASSERT_INT("exchange.sig_len", (int)e2.signature_len, 70);
    ASSERT_BYTES("exchange.signature", e2.signature, e.signature, 70);
}

/* ── Yamux tests ── */

static void test_yamux_header_roundtrip(void) {
    yamux_frame_t f;
    f.version   = 0;
    f.type      = YAMUX_TYPE_DATA;
    f.flags     = YAMUX_FLAG_SYN;
    f.stream_id = 0x00000001;
    f.length    = 0x00001234;

    uint8_t buf[YAMUX_HEADER_SIZE];
    yamux_encode_header(&f, buf);

    /* Verify big-endian encoding */
    ASSERT_INT("yamux version byte", buf[0], 0);
    ASSERT_INT("yamux type byte",    buf[1], YAMUX_TYPE_DATA);
    ASSERT_INT("yamux flags[0]",     buf[2], 0x00);
    ASSERT_INT("yamux flags[1]",     buf[3], YAMUX_FLAG_SYN);
    ASSERT_INT("yamux stream_id[3]", buf[7], 0x01);
    ASSERT_INT("yamux length[2]",    buf[10], 0x12);
    ASSERT_INT("yamux length[3]",    buf[11], 0x34);

    yamux_frame_t f2;
    int ret = yamux_decode_header(buf, &f2);
    ASSERT_INT("yamux_decode_header returns 0", ret, 0);
    ASSERT_INT("yamux roundtrip type",      (int)f2.type,      YAMUX_TYPE_DATA);
    ASSERT_INT("yamux roundtrip flags",     (int)f2.flags,     YAMUX_FLAG_SYN);
    ASSERT_INT("yamux roundtrip stream_id", (int)f2.stream_id, 1);
    ASSERT_INT("yamux roundtrip length",    (int)f2.length,    0x1234);
}

static void test_yamux_session(void) {
    yamux_session_t s;
    yamux_session_init(&s);
    ASSERT_INT("session next_stream_id starts at 1", (int)s.next_stream_id, 1);

    yamux_stream_t *st = yamux_open_stream(&s, CKB_PROTO_LIGHT_CLIENT);
    if (!st) { FAIL("yamux_open_stream returned NULL"); return; }
    ASSERT_INT("stream id = 1",       (int)st->id,       1);
    ASSERT_INT("stream state = SYN_SENT", (int)st->state, YAMUX_STREAM_SYN_SENT);
    ASSERT_INT("stream protocol",     (int)st->protocol_id, CKB_PROTO_LIGHT_CLIENT);
    ASSERT_INT("next stream_id = 3",  (int)s.next_stream_id, 3);

    /* Simulate SYN+ACK from remote */
    yamux_frame_t ack;
    yamux_frame_syn_ack(&ack, 1);
    int ret = yamux_process_frame(&s, &ack);
    ASSERT_INT("process SYN+ACK returns 0", ret, 0);
    ASSERT_INT("stream state = OPEN after ACK", (int)st->state, YAMUX_STREAM_OPEN);
}

static void test_yamux_ping(void) {
    yamux_frame_t ping, pong;
    yamux_frame_ping(&ping, 0xDEAD);
    ASSERT_INT("ping type = PING",    (int)ping.type,   YAMUX_TYPE_PING);
    ASSERT_INT("ping flags = SYN",    (int)ping.flags,  YAMUX_FLAG_SYN);
    ASSERT_INT("ping length = ping_id",(int)ping.length, 0xDEAD);
    ASSERT_INT("ping stream_id = 0",  (int)ping.stream_id, 0);

    yamux_frame_ping_ack(&pong, ping.length);
    ASSERT_INT("pong flags = ACK",    (int)pong.flags,  YAMUX_FLAG_ACK);
    ASSERT_INT("pong length = ping_id",(int)pong.length, 0xDEAD);
}

static void test_tentacle_header_roundtrip(void) {
    tentacle_frame_t f;
    f.protocol_id = CKB_PROTO_LIGHT_CLIENT;
    f.flags       = 0;
    f.payload_len = 256;

    uint8_t buf[TENTACLE_FRAME_HEADER_SIZE];
    tentacle_encode_header(&f, buf);

    /* LE length = 256 + 2 = 258 = 0x00000102 */
    ASSERT_INT("tentacle len[0]", buf[0], 0x02);
    ASSERT_INT("tentacle len[1]", buf[1], 0x01);
    ASSERT_INT("tentacle len[2]", buf[2], 0x00);
    ASSERT_INT("tentacle len[3]", buf[3], 0x00);
    ASSERT_INT("tentacle proto",  buf[4], CKB_PROTO_LIGHT_CLIENT);
    ASSERT_INT("tentacle flags",  buf[5], 0);

    tentacle_frame_t f2;
    int ret = tentacle_decode_header(buf, &f2);
    ASSERT_INT("tentacle decode returns 0", ret, 0);
    ASSERT_INT("tentacle roundtrip payload_len", (int)f2.payload_len, 256);
    ASSERT_INT("tentacle roundtrip proto",       (int)f2.protocol_id, CKB_PROTO_LIGHT_CLIENT);
}

static void test_secio_framing(void) {
    /* secio_write_frame_prefix writes 4-byte BE length */
    uint8_t buf[8];
    int ret = secio_write_frame_prefix(0x00ABCDEF, buf, sizeof(buf));
    ASSERT_INT("secio_write_prefix returns 4", ret, 4);
    ASSERT_INT("prefix[0]", buf[0], 0x00);
    ASSERT_INT("prefix[1]", buf[1], 0xAB);
    ASSERT_INT("prefix[2]", buf[2], 0xCD);
    ASSERT_INT("prefix[3]", buf[3], 0xEF);

    /* secio_read_framed */
    uint8_t frame[10];
    frame[0] = 0x00; frame[1] = 0x00; frame[2] = 0x00; frame[3] = 0x06;
    frame[4] = 0xAA; frame[5] = 0xBB; frame[6] = 0xCC;
    frame[7] = 0xDD; frame[8] = 0xEE; frame[9] = 0xFF;

    const uint8_t *payload; uint32_t plen;
    ret = secio_read_framed(frame, 10, &payload, &plen);
    ASSERT_INT("secio_read_framed consumed 10", ret, 10);
    ASSERT_INT("secio_read_framed plen = 6",    (int)plen, 6);
    ASSERT_INT("secio payload[0] = 0xAA",       payload[0], 0xAA);
}

static void test_mol_pubkey_roundtrip(void) {
    uint8_t pubkey[33];
    pubkey[0] = 0x02;
    memset(pubkey + 1, 0x55, 32);

    uint8_t buf[128];
    int written = mol_pubkey_encode(pubkey, 33, buf, sizeof(buf));
    if (written < 0) { FAIL("mol_pubkey_encode"); return; }
    PASS("mol_pubkey_encode succeeds");

    const uint8_t *pk_out; uint32_t pk_len;
    int consumed = mol_pubkey_decode(buf, (uint32_t)written, &pk_out, &pk_len);
    ASSERT_INT("mol_pubkey_decode consumed", consumed, written - 4); /* minus union tag */
    ASSERT_INT("mol_pubkey len = 33", (int)pk_len, 33);
    ASSERT_BYTES("mol_pubkey data", pk_out, pubkey, 33);
}

int main(void) {
    printf("=== CKB Transport Layer Tests ===\n\n");

    printf("--- Molecule ---\n");
    test_mol_bytes_roundtrip();
    test_mol_empty_bytes();
    test_mol_table_roundtrip();
    test_mol_pubkey_roundtrip();

    printf("\n--- SecIO Messages ---\n");
    test_secio_propose_roundtrip();
    test_secio_exchange_roundtrip();
    test_secio_framing();

    printf("\n--- Yamux ---\n");
    test_yamux_header_roundtrip();
    test_yamux_session();
    test_yamux_ping();
    test_tentacle_header_roundtrip();

    printf("\n=== Results: %d/%d passed ===\n",
           tests_run - tests_failed, tests_run);
    return tests_failed > 0 ? 1 : 0;
}
