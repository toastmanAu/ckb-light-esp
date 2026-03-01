// bitchat_noise.h — Noise_XX_25519_ChaChaPoly_SHA256 for ESP32
// toastmanAu/ckb-light-esp
//
// Implements the Noise Protocol Framework XX handshake pattern as specified in:
//   https://noiseprotocol.org/noise.html
//   BitChat whitepaper §5: Noise_XX_25519_ChaChaPoly_SHA256
//
// XX handshake (3 messages, mutual auth, no pre-shared keys):
//   → e                      (initiator sends ephemeral pub key)
//   ← e, ee, s, es           (responder sends ephemeral + static, DH mixes)
//   → s, se                  (initiator sends static + final DH mix)
//   [transport phase: bidirectional encrypted messages]
//
// Crypto primitives (all from trezor_crypto / curve25519-donna / rfc7539):
//   DH:     X25519 (curve25519_scalarmult from ed25519-donna)
//   CIPHER: ChaCha20-Poly1305 (rfc7539 from trezor chacha20poly1305/)
//   HASH:   SHA-256 (sha2 from trezor_crypto)
//   HKDF:   HMAC-SHA256 based
//
// Usage:
//   // Initiator:
//   NoiseSession sess;
//   noise_init(&sess, my_static_priv, my_static_pub);
//   uint8_t msg1[32];
//   noise_write_msg1(&sess, msg1);          // → e
//   // ... send msg1 to responder via BLE ...
//   uint8_t msg2[96]; size_t msg2_len;
//   noise_read_msg2(&sess, msg2, msg2_len); // ← e,ee,s,es
//   uint8_t msg3[64]; size_t msg3_len;
//   noise_write_msg3(&sess, msg3, &msg3_len); // → s,se
//   // handshake complete: sess.send_key, sess.recv_key ready
//
//   // Transport:
//   uint8_t ct[256]; size_t ct_len;
//   noise_encrypt(&sess, plaintext, pt_len, ct, &ct_len);
//   noise_decrypt(&sess, ct, ct_len, plaintext, &pt_len);
//
// Fingerprint (for out-of-band verification):
//   SHA256(static_public_key) — 32 bytes, display as hex
//
// Host test: all primitives are pure C — compiles on Linux with g++

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define NOISE_KEY_SIZE      32   // Curve25519 key size
#define NOISE_TAG_SIZE      16   // ChaCha20-Poly1305 authentication tag
#define NOISE_HASH_SIZE     32   // SHA-256 output
#define NOISE_BLOCK_SIZE    64   // SHA-256 block size (for HMAC)

// Noise_XX handshake message sizes
#define NOISE_MSG1_SIZE     32   // → e  (just ephemeral pub key)
#define NOISE_MSG2_SIZE     96   // ← e(32), ee-mixed, s(32+16 encrypted), es-mixed
#define NOISE_MSG3_SIZE     64   // → s(32+16 encrypted), se-mixed
#define NOISE_MSG3_MIN      48   // minimum (32 + 16 tag, no payload)

// Maximum transport message overhead
#define NOISE_OVERHEAD      16   // 16-byte Poly1305 tag per message

// Noise protocol name for this variant
#define NOISE_PROTOCOL_NAME "Noise_XX_25519_ChaChaPoly_SHA256"
#define NOISE_PROTOCOL_NAME_LEN 32

// ─── CipherState ──────────────────────────────────────────────────────────────
// Tracks the symmetric state for one direction of encrypted transport.

typedef struct {
    uint8_t  k[NOISE_KEY_SIZE];  // ChaCha20-Poly1305 key
    uint64_t n;                  // nonce counter (increments per message)
    bool     has_key;
} NoiseCipherState;

// ─── NoiseSession ─────────────────────────────────────────────────────────────
// Full session state through handshake and transport phases.

typedef enum {
    NOISE_STATE_UNINIT   = 0,
    NOISE_STATE_MSG1_SENT,      // initiator: sent msg1, waiting for msg2
    NOISE_STATE_MSG1_RECV,      // responder: received msg1, ready to send msg2
    NOISE_STATE_MSG2_SENT,      // responder: sent msg2, waiting for msg3
    NOISE_STATE_MSG2_RECV,      // initiator: received msg2, ready to send msg3
    NOISE_STATE_TRANSPORT,      // handshake complete, transport phase
    NOISE_STATE_ERROR           // unrecoverable error
} NoiseState;

typedef struct {
    // State
    NoiseState state;
    bool       is_initiator;

    // Long-term static keypair (persisted across sessions)
    uint8_t    s_priv[NOISE_KEY_SIZE];
    uint8_t    s_pub[NOISE_KEY_SIZE];

    // Ephemeral keypair (generated fresh per handshake)
    uint8_t    e_priv[NOISE_KEY_SIZE];
    uint8_t    e_pub[NOISE_KEY_SIZE];

    // Remote peer's static public key (learned during handshake)
    uint8_t    rs_pub[NOISE_KEY_SIZE];   // remote static
    uint8_t    re_pub[NOISE_KEY_SIZE];   // remote ephemeral

    // Symmetric state (ck = chaining key, h = handshake hash)
    uint8_t    ck[NOISE_HASH_SIZE];      // chaining key
    uint8_t    h[NOISE_HASH_SIZE];       // running hash (handshake hash)

    // Transport ciphers (split from ck after handshake)
    NoiseCipherState send_cs;  // for encrypting outbound
    NoiseCipherState recv_cs;  // for decrypting inbound

    // Fingerprint cache (SHA-256 of s_pub)
    uint8_t    fingerprint[NOISE_HASH_SIZE];
} NoiseSession;

// ─── API ──────────────────────────────────────────────────────────────────────

// Initialise a session with our static keypair.
// static_priv: 32-byte Curve25519 private key (clamped on gen)
// static_pub:  32-byte Curve25519 public key  (= curve25519_scalarmult_basepoint(priv))
// Pass NULL for both to generate a fresh keypair.
void noise_init(NoiseSession* sess, const uint8_t* static_priv, const uint8_t* static_pub);

// Generate a fresh Curve25519 keypair into priv[32] + pub[32].
void noise_gen_keypair(uint8_t* priv, uint8_t* pub);

// ── Handshake ────────────────────────────────────────────────────────────────

// INITIATOR step 1: write message 1 (→ e) into buf[32].
// Returns true on success.
bool noise_write_msg1(NoiseSession* sess, uint8_t buf[NOISE_MSG1_SIZE]);

// RESPONDER step 1: process message 1 (→ e) from initiator.
// RESPONDER step 2: write message 2 (← e,ee,s,es) into buf.
// out_len set to actual bytes written (always NOISE_MSG2_SIZE = 96).
bool noise_read_msg1_write_msg2(NoiseSession* sess,
                                 const uint8_t* msg1, size_t msg1_len,
                                 uint8_t* buf, size_t* out_len);

// INITIATOR step 2: process message 2 (← e,ee,s,es).
// INITIATOR step 3: write message 3 (→ s,se) into buf.
// out_len set to actual bytes written (always NOISE_MSG3_MIN = 48).
bool noise_read_msg2_write_msg3(NoiseSession* sess,
                                 const uint8_t* msg2, size_t msg2_len,
                                 uint8_t* buf, size_t* out_len);

// RESPONDER step 2: process message 3 (→ s,se). Handshake complete.
bool noise_read_msg3(NoiseSession* sess, const uint8_t* msg3, size_t msg3_len);

// ── Transport (after handshake complete) ────────────────────────────────────

// Encrypt plaintext → ciphertext + 16-byte tag.
// ct must be at least pt_len + NOISE_OVERHEAD bytes.
// Returns false on error.
bool noise_encrypt(NoiseSession* sess,
                   const uint8_t* pt, size_t pt_len,
                   uint8_t* ct, size_t* ct_len);

// Decrypt ciphertext → plaintext. Returns false if tag invalid.
// pt must be at least ct_len bytes.
bool noise_decrypt(NoiseSession* sess,
                   const uint8_t* ct, size_t ct_len,
                   uint8_t* pt, size_t* pt_len);

// ── Utilities ────────────────────────────────────────────────────────────────

// Get remote peer's fingerprint (SHA-256 of their static pub key).
// Returns pointer to sess->rs_pub or NULL if handshake not complete.
const uint8_t* noise_remote_fingerprint(const NoiseSession* sess, uint8_t out[32]);

// Format fingerprint as hex string (64 chars + null = 65 bytes needed).
void noise_fingerprint_hex(const uint8_t fingerprint[32], char* out, size_t out_size);

// Is the session in transport phase (handshake complete)?
static inline bool noise_ready(const NoiseSession* sess) {
    return sess && sess->state == NOISE_STATE_TRANSPORT;
}

// Session error?
static inline bool noise_error(const NoiseSession* sess) {
    return sess && sess->state == NOISE_STATE_ERROR;
}
