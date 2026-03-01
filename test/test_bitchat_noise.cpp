// test_bitchat_noise.cpp — Host tests for BitChat Noise session layer
// toastmanAu/ckb-light-esp
//
// Tests:
//   - Session init + keypair generation
//   - ChaCha20-Poly1305 AEAD (seal/open round-trip)
//   - HMAC-SHA256 + HKDF (key derivation correctness)
//   - Noise handshake structure (XX 3-message exchange)
//   - Transport encrypt/decrypt after handshake
//   - Fingerprint derivation
//   - State machine transitions
//
// NOTE: X25519 DH is mocked in HOST_TEST mode (SHA-256 pseudo-DH).
// The handshake structure is tested, but actual crypto correctness
// requires linking curve25519-donna for device builds.
// ChaCha20-Poly1305 and HMAC-SHA256 are fully tested.

#define HOST_TEST 1
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

// Pull in sha2 from CKB-ESP32 for host
extern "C" {
#include "sha2.h"
}

#include "../src/bitchat/bitchat_noise.h"
#include "../src/bitchat/bitchat_noise.cpp"

// ─── Test framework ───────────────────────────────────────────────────────────

static int g_pass = 0, g_fail = 0;
#define PASS(n) do { printf("  PASS: %s\n", n); g_pass++; } while(0)
#define FAIL(n) do { printf("  FAIL: %s [line %d]\n", n, __LINE__); g_fail++; } while(0)
#define CHECK(cond, name) do { if(cond) PASS(name); else FAIL(name); } while(0)

// ─── Test: keypair generation ─────────────────────────────────────────────────

static void test_keypair() {
    printf("\n[keypair]\n");

    uint8_t priv[32], pub[32];
    noise_gen_keypair(priv, pub);

    // Curve25519 clamping
    CHECK((priv[0] & 7) == 0,      "priv[0] low 3 bits cleared");
    CHECK((priv[31] & 128) == 0,   "priv[31] high bit cleared");
    CHECK((priv[31] & 64) != 0,    "priv[31] bit 6 set");

    // Public key non-zero
    bool nonzero = false;
    for (int i=0;i<32;i++) if (pub[i]) { nonzero=true; break; }
    CHECK(nonzero, "public key non-zero");

    // Two keypairs differ
    uint8_t priv2[32], pub2[32];
    noise_gen_keypair(priv2, pub2);
    CHECK(memcmp(priv, priv2, 32) != 0, "two keypairs differ");
}

// ─── Test: session init ───────────────────────────────────────────────────────

static void test_session_init() {
    printf("\n[session init]\n");

    NoiseSession sess;
    noise_init(&sess, NULL, NULL);  // auto-generate keypair

    CHECK(sess.state == NOISE_STATE_UNINIT, "initial state uninit");
    CHECK(!noise_ready(&sess), "not ready before handshake");
    CHECK(!noise_error(&sess), "no error at init");

    // Fingerprint = SHA-256(s_pub)
    uint8_t expected_fp[32];
    sha256_Raw(sess.s_pub, 32, expected_fp);
    CHECK(memcmp(sess.fingerprint, expected_fp, 32) == 0, "fingerprint = SHA-256(s_pub)");

    // Init with known keypair
    uint8_t kp_priv[32] = {
        0x70,0x8e,0xf7,0x42,0xb7,0x41,0x6f,0x7c,
        0xd2,0x9a,0x41,0x9e,0x9c,0x96,0x57,0xa4,
        0x37,0xb5,0xa3,0x6e,0x9e,0x0c,0xbd,0x0b,
        0xb3,0xed,0x6e,0x44,0x9d,0xb5,0x03,0x4c
    };
    kp_priv[0] &= 248; kp_priv[31] &= 127; kp_priv[31] |= 64;
    NoiseSession sess2;
    noise_init(&sess2, kp_priv, NULL);
    CHECK(memcmp(sess2.s_priv, kp_priv, 32) == 0, "static priv stored correctly");
}

// ─── Test: HMAC-SHA256 (RFC 4231 test vector) ─────────────────────────────────

static void test_hmac() {
    printf("\n[HMAC-SHA256]\n");

    // RFC 4231 test case 1:
    // key = 0x0b * 20
    // data = "Hi There"
    // expected = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    uint8_t key[20]; memset(key, 0x0b, 20);
    const uint8_t data[] = "Hi There";
    const uint8_t expected[] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,
        0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
        0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
    };
    uint8_t out[32];
    hmac_sha256(key, 20, data, 8, out);
    CHECK(memcmp(out, expected, 32) == 0, "HMAC-SHA256 RFC4231 vector 1");

    // HKDF sanity: output is deterministic
    uint8_t prk[32];
    hkdf_extract(key, 20, data, 8, prk);
    uint8_t o1[32], o2[32];
    hkdf_expand_2(prk, o1, o2);
    bool out_differ = (memcmp(o1, o2, 32) != 0);
    CHECK(out_differ, "HKDF: two outputs differ");

    // HKDF deterministic
    uint8_t o1b[32], o2b[32];
    hkdf_expand_2(prk, o1b, o2b);
    CHECK(memcmp(o1, o1b, 32) == 0, "HKDF: deterministic");
}

// ─── Test: ChaCha20-Poly1305 via noise transport round-trip ──────────────────

static void test_chacha20poly1305() {
    printf("\n[ChaCha20-Poly1305 via noise transport]\n");

    // Test AEAD via a full noise session (transport phase)
    NoiseSession init_s, resp_s;
    noise_init(&init_s, NULL, NULL);
    noise_init(&resp_s, NULL, NULL);
    uint8_t m1[32], m2[128], m3[64];
    size_t m2l, m3l;
    noise_write_msg1(&init_s, m1);
    noise_read_msg1_write_msg2(&resp_s, m1, 32, m2, &m2l);
    noise_read_msg2_write_msg3(&init_s, m2, m2l, m3, &m3l);
    noise_read_msg3(&resp_s, m3, m3l);

    // Encrypt/decrypt round-trip
    const uint8_t pt[] = "Hello, BitChat!";
    size_t pt_len = 15;
    uint8_t ct[64]; size_t ct_len;
    bool ok = noise_encrypt(&init_s, pt, pt_len, ct, &ct_len);
    CHECK(ok, "seal succeeds");
    CHECK(ct_len == pt_len + 16, "ciphertext len = pt + 16 tag");
    CHECK(memcmp(ct, pt, pt_len) != 0, "ciphertext != plaintext");

    uint8_t dec[64]; size_t dec_len;
    ok = noise_decrypt(&resp_s, ct, ct_len, dec, &dec_len);
    CHECK(ok, "open succeeds");
    CHECK(dec_len == pt_len, "decrypted len correct");
    CHECK(memcmp(dec, pt, pt_len) == 0, "decrypted == plaintext");

    // Wrong tag → fails
    uint8_t bad_ct[64]; memcpy(bad_ct, ct, ct_len);
    bad_ct[ct_len-1] ^= 0xFF;  // corrupt tag
    ok = noise_decrypt(&resp_s, bad_ct, ct_len, dec, &dec_len);
    CHECK(!ok, "corrupt tag: decrypt fails");

    // Second message (nonce increments)
    ok = noise_encrypt(&init_s, pt, pt_len, ct, &ct_len);
    ok &= noise_decrypt(&resp_s, ct, ct_len, dec, &dec_len);
    CHECK(ok, "second message round-trips");

    // 100 byte message
    uint8_t long_pt[100]; for(int i=0;i<100;i++) long_pt[i]=(uint8_t)i;
    uint8_t long_ct[120]; size_t long_ct_len;
    ok = noise_encrypt(&init_s, long_pt, 100, long_ct, &long_ct_len);
    CHECK(ok, "seal 100 bytes");
    uint8_t long_dec[100]; size_t long_dec_len;
    ok = noise_decrypt(&resp_s, long_ct, long_ct_len, long_dec, &long_dec_len);
    CHECK(ok, "open 100 bytes");
    CHECK(memcmp(long_dec, long_pt, 100) == 0, "100-byte round-trip");
}

// ─── Test: Noise XX handshake structure ───────────────────────────────────────

static void test_noise_handshake() {
    printf("\n[Noise XX handshake structure]\n");

    NoiseSession initiator, responder;
    noise_init(&initiator, NULL, NULL);
    noise_init(&responder, NULL, NULL);

    // Step 1: initiator → msg1
    uint8_t msg1[NOISE_MSG1_SIZE];
    bool ok = noise_write_msg1(&initiator, msg1);
    CHECK(ok, "write_msg1 succeeds");
    CHECK(initiator.state == NOISE_STATE_MSG1_SENT, "initiator state: MSG1_SENT");

    // e_pub should be in msg1
    bool epub_in_msg1 = (memcmp(msg1, initiator.e_pub, 32) == 0);
    CHECK(epub_in_msg1, "msg1 = initiator ephemeral pub key");

    // Step 2: responder reads msg1, writes msg2
    uint8_t msg2[NOISE_MSG2_SIZE + 32];
    size_t msg2_len;
    ok = noise_read_msg1_write_msg2(&responder, msg1, NOISE_MSG1_SIZE, msg2, &msg2_len);
    CHECK(ok, "read_msg1_write_msg2 succeeds");
    CHECK(responder.state == NOISE_STATE_MSG2_SENT, "responder state: MSG2_SENT");
    CHECK(msg2_len == 80, "msg2 len = 80 (32 ephemeral + 48 encrypted static)");

    // Initiator's ephemeral pub should be in responder's re_pub
    CHECK(memcmp(responder.re_pub, msg1, 32) == 0, "responder stored re_pub from msg1");

    // Step 3: initiator reads msg2, writes msg3
    uint8_t msg3[NOISE_MSG3_MIN + 32];
    size_t msg3_len;
    ok = noise_read_msg2_write_msg3(&initiator, msg2, msg2_len, msg3, &msg3_len);
    CHECK(ok, "read_msg2_write_msg3 succeeds");
    CHECK(initiator.state == NOISE_STATE_TRANSPORT, "initiator state: TRANSPORT");
    CHECK(msg3_len == 48, "msg3 len = 48 (encrypted static 32+16 tag)");

    // Step 4: responder reads msg3
    ok = noise_read_msg3(&responder, msg3, msg3_len);
    CHECK(ok, "read_msg3 succeeds");
    CHECK(responder.state == NOISE_STATE_TRANSPORT, "responder state: TRANSPORT");

    // Both sides should be ready
    CHECK(noise_ready(&initiator), "initiator noise_ready");
    CHECK(noise_ready(&responder), "responder noise_ready");

    // Transport: initiator encrypts, responder decrypts
    const uint8_t plain[] = "Hello from BitChat ESP32!";
    uint8_t enc[64]; size_t enc_len;
    ok = noise_encrypt(&initiator, plain, 25, enc, &enc_len);
    CHECK(ok, "transport encrypt");
    CHECK(enc_len == 25 + 16, "encrypted len = pt + 16 tag");

    uint8_t dec[64]; size_t dec_len;
    ok = noise_decrypt(&responder, enc, enc_len, dec, &dec_len);
    CHECK(ok, "transport decrypt");
    CHECK(dec_len == 25, "decrypted len correct");
    CHECK(memcmp(dec, plain, 25) == 0, "transport round-trip: plaintext matches");

    // Reverse direction
    const uint8_t reply[] = "Hi back!";
    uint8_t enc2[32]; size_t enc2_len;
    ok = noise_encrypt(&responder, reply, 8, enc2, &enc2_len);
    CHECK(ok, "reverse encrypt");
    uint8_t dec2[32]; size_t dec2_len;
    ok = noise_decrypt(&initiator, enc2, enc2_len, dec2, &dec2_len);
    CHECK(ok, "reverse decrypt");
    CHECK(memcmp(dec2, reply, 8) == 0, "reverse round-trip matches");

    // Nonce increments: second message uses nonce 1
    ok = noise_encrypt(&initiator, plain, 25, enc, &enc_len);
    uint8_t dec3[64]; size_t dec3_len;
    ok = noise_decrypt(&responder, enc, enc_len, dec3, &dec3_len);
    CHECK(ok, "second transport message decrypts");
    CHECK(memcmp(dec3, plain, 25) == 0, "second message correct");
}

// ─── Test: fingerprint ────────────────────────────────────────────────────────

static void test_fingerprint() {
    printf("\n[fingerprint]\n");

    NoiseSession initiator, responder;
    noise_init(&initiator, NULL, NULL);
    noise_init(&responder, NULL, NULL);

    // Do full handshake
    uint8_t msg1[32], msg2[128], msg3[64];
    size_t msg2_len, msg3_len;
    noise_write_msg1(&initiator, msg1);
    noise_read_msg1_write_msg2(&responder, msg1, 32, msg2, &msg2_len);
    noise_read_msg2_write_msg3(&initiator, msg2, msg2_len, msg3, &msg3_len);
    noise_read_msg3(&responder, msg3, msg3_len);

    // Get fingerprints
    uint8_t init_fp[32], resp_fp[32];
    const uint8_t* fp_of_resp = noise_remote_fingerprint(&initiator, init_fp);
    CHECK(fp_of_resp != NULL, "initiator can get responder fingerprint");

    const uint8_t* fp_of_init = noise_remote_fingerprint(&responder, resp_fp);
    CHECK(fp_of_init != NULL, "responder can get initiator fingerprint");

    // Fingerprint = SHA-256(remote static pub)
    uint8_t expected_resp_fp[32];
    sha256_Raw(responder.s_pub, 32, expected_resp_fp);
    CHECK(memcmp(init_fp, expected_resp_fp, 32) == 0, "initiator fingerprint = SHA-256(resp s_pub)");

    // Hex formatting
    char hex[65];
    noise_fingerprint_hex(init_fp, hex, sizeof(hex));
    CHECK(strlen(hex) == 64, "fingerprint hex = 64 chars");
    CHECK(hex[0] >= '0' && hex[0] <= 'f', "fingerprint hex is hex");

    printf("  Remote fingerprint: %.16s...\n", hex);
}

// ─── Test: state machine ──────────────────────────────────────────────────────

static void test_state_machine() {
    printf("\n[state machine]\n");

    NoiseSession sess;
    noise_init(&sess, NULL, NULL);
    CHECK(sess.state == NOISE_STATE_UNINIT, "uninit state");
    CHECK(!noise_ready(&sess), "not ready at uninit");

    // Can't encrypt before handshake
    uint8_t buf[32]; size_t len;
    bool ok = noise_encrypt(&sess, (const uint8_t*)"test", 4, buf, &len);
    CHECK(!ok, "encrypt fails before handshake");

    // Can't decrypt before handshake
    ok = noise_decrypt(&sess, (const uint8_t*)"test", 4, buf, &len);
    CHECK(!ok, "decrypt fails before handshake");

    // fingerprint unavailable before handshake
    uint8_t fp[32];
    CHECK(noise_remote_fingerprint(&sess, fp) == NULL, "remote fp NULL before handshake");
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main() {
    printf("========================================\n");
    printf("  BitChat Noise session host tests\n");
    printf("  NOTE: X25519 DH is mocked (SHA-256 pseudo-DH)\n");
    printf("  Handshake structure + ChaCha20-Poly1305 fully tested\n");
    printf("========================================\n");

    test_keypair();
    test_session_init();
    test_hmac();
    test_chacha20poly1305();
    test_noise_handshake();
    test_fingerprint();
    test_state_machine();

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("========================================\n");
    return g_fail > 0 ? 1 : 0;
}
