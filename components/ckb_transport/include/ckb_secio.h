/*
 * ckb_secio.h — SecIO handshake for CKB/Tentacle
 *
 * SecIO is Tentacle's transport security protocol (similar to TLS).
 * After a raw TCP connection, both sides perform a 3-step handshake:
 *
 *   1. Propose: exchange capabilities and public keys
 *      Wire: [4-byte BE length][molecule(Propose)]
 *
 *   2. Exchange: exchange ephemeral public keys + signatures
 *      Wire: [4-byte BE length][molecule(Exchange)]
 *
 *   3. Key stretching: derive symmetric keys from ECDH shared secret
 *      Using HMAC-SHA256 key stretching
 *
 * After handshake, all data is encrypted:
 *   AES-128-CTR + HMAC-SHA256 (16-byte HMAC appended to each frame)
 *
 * For the ESP32-P4, we use mbedTLS which provides:
 *   - secp256k1 / P-256 ECDH
 *   - AES-128-CTR
 *   - HMAC-SHA256
 * On POSIX (test host), we use OpenSSL.
 *
 * CKB nodes negotiate:
 *   - Exchange: P-256 (NIST curve, not secp256k1 — important!)
 *   - Cipher:   AES-128 (CTR mode)
 *   - Hash:     SHA-256
 */

#ifndef CKB_SECIO_H
#define CKB_SECIO_H

#include <stdint.h>
#include <stddef.h>
#include "ckb_molecule.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AES-128-CTR key + IV sizes */
#define SECIO_KEY_SIZE    16
#define SECIO_IV_SIZE     12    /* GCM uses 96-bit (12-byte) nonce */
#define SECIO_HMAC_SIZE   0     /* AES-GCM is AEAD — no separate MAC key */
#define SECIO_NONCE_SIZE  16

/* Stretched key material per direction */
typedef struct {
    uint8_t iv[SECIO_IV_SIZE];
    uint8_t key[SECIO_KEY_SIZE];
    uint8_t mac_key[SECIO_HMAC_SIZE];
} secio_key_set_t;

/*
 * SecIO handshake state.
 * Caller drives the state machine step by step.
 */
typedef enum {
    SECIO_STATE_IDLE = 0,
    SECIO_STATE_PROPOSE_SENT,
    SECIO_STATE_PROPOSE_RECV,
    SECIO_STATE_EXCHANGE_SENT,
    SECIO_STATE_EXCHANGE_RECV,
    SECIO_STATE_ESTABLISHED,
    SECIO_STATE_FAILED,
} secio_state_t;

typedef struct {
    secio_state_t state;

    /* Our static secp256k1 identity key (33-byte compressed) */
    uint8_t local_static_pubkey[33];
    uint8_t local_static_privkey[32];

    /* Our ephemeral P-256 key (for this session) */
    uint8_t local_ephem_pubkey[65];   /* uncompressed */
    uint8_t local_ephem_privkey[32];

    /* Remote's keys (received during handshake) */
    uint8_t remote_static_pubkey[65];
    uint32_t remote_static_pubkey_len;
    uint8_t remote_ephem_pubkey[65];
    uint32_t remote_ephem_pubkey_len;

    /* Nonces */
    uint8_t local_nonce[SECIO_NONCE_SIZE];
    uint8_t remote_nonce[SECIO_NONCE_SIZE];

    /* Encoded propose messages (saved for signature verification) */
    uint8_t local_propose_bytes[512];
    uint32_t local_propose_len;
    uint8_t remote_propose_bytes[512];
    uint32_t remote_propose_len;

    /* Negotiated algorithms */
    char chosen_exchange[16];  /* "P-256" */
    char chosen_cipher[16];    /* "AES-128" */
    char chosen_hash[16];      /* "SHA-256" */

    /* Derived keys (after key stretching) */
    secio_key_set_t local_keys;  /* for encrypting outbound */
    secio_key_set_t remote_keys; /* for decrypting inbound */

    /* Whether we have the "higher" ordering (determines key halves) */
    int we_are_higher;
} secio_ctx_t;

/* ── Crypto callbacks ──
 *
 * Platform-specific crypto is injected via callbacks so the core
 * secio code doesn't depend on any particular crypto library.
 * On ESP32-P4: mbedTLS. On POSIX: OpenSSL.
 */
typedef struct {
    /**
     * Generate a random secp256k1 key pair.
     * privkey: 32-byte output, pubkey: 33-byte compressed output.
     */
    int (*generate_static_keypair)(uint8_t privkey[32], uint8_t pubkey[33]);

    /**
     * Generate an ephemeral P-256 key pair for ECDH.
     * privkey: 32-byte output, pubkey: 65-byte uncompressed output.
     */
    int (*generate_ephemeral_keypair)(uint8_t privkey[32], uint8_t pubkey[65]);

    /**
     * Fill buf with len random bytes.
     */
    int (*random_bytes)(uint8_t *buf, size_t len);

    /**
     * ECDH P-256: derive shared secret from our privkey and remote pubkey.
     * shared_secret: 32-byte output (x-coordinate of shared point).
     */
    int (*ecdh_p256)(const uint8_t privkey[32],
                     const uint8_t remote_pubkey[65],
                     uint8_t shared_secret[32]);

    /**
     * Sign data with secp256k1 privkey using ECDSA.
     * data is a SHA-256 hash (32 bytes).
     * sig_buf: output buffer (max 72 bytes DER), sig_len: actual length written.
     */
    int (*ecdsa_sign)(const uint8_t privkey[32],
                      const uint8_t data_hash[32],
                      uint8_t *sig_buf, uint32_t *sig_len);

    /**
     * Verify secp256k1 ECDSA signature.
     * pubkey: 33-byte compressed or 65-byte uncompressed.
     * Returns 0 if valid, -1 if invalid.
     */
    int (*ecdsa_verify)(const uint8_t *pubkey, uint32_t pubkey_len,
                        const uint8_t data_hash[32],
                        const uint8_t *sig, uint32_t sig_len);

    /**
     * SHA-256 hash.
     */
    int (*sha256)(const uint8_t *data, size_t len, uint8_t out[32]);

    /**
     * HMAC-SHA256 for key stretching.
     */
    int (*hmac_sha256)(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[32]);
} secio_crypto_t;

/* ── Handshake steps ── */

/**
 * Initialise SecIO context.
 * Generates the static keypair and ephemeral P-256 keypair.
 */
int secio_init(secio_ctx_t *ctx, const secio_crypto_t *crypto);

/**
 * Step 1: Build our Propose message.
 * Writes a length-prefixed molecule(Propose) into buf.
 * Returns bytes to send, or -1 on error.
 */
int secio_build_propose(secio_ctx_t *ctx, const secio_crypto_t *crypto,
                        uint8_t *buf, uint32_t buf_size);

/**
 * Step 2: Process the remote's Propose message.
 * buf points to the molecule(Propose) payload (after the 4-byte length prefix).
 * Updates ctx with remote capabilities and chooses algorithms.
 * Returns 0 on success, -1 on error.
 */
int secio_process_propose(secio_ctx_t *ctx, const uint8_t *buf, uint32_t buf_len);

/**
 * Step 3: Build our Exchange message.
 * Must be called after secio_process_propose().
 * Signs (local_propose || remote_propose || local_ephem_pubkey) with our static key.
 * Returns bytes to send, or -1.
 */
int secio_build_exchange(secio_ctx_t *ctx, const secio_crypto_t *crypto,
                         uint8_t *buf, uint32_t buf_size);

/**
 * Step 4: Process the remote's Exchange message.
 * Verifies signature, performs ECDH, stretches keys.
 * After this succeeds, ctx->state == SECIO_STATE_ESTABLISHED and
 * ctx->local_keys / ctx->remote_keys are ready for use.
 * Returns 0 on success, -1 on error.
 */
int secio_process_exchange(secio_ctx_t *ctx, const secio_crypto_t *crypto,
                           const uint8_t *buf, uint32_t buf_len);

/**
 * Key stretching: given shared secret material, derive two key sets.
 * Called internally by secio_process_exchange.
 */
int secio_stretch_keys(const secio_crypto_t *crypto,
                       const uint8_t *key_material, size_t key_material_len,
                       const char *cipher,
                       const char *hash,
                       secio_key_set_t *k1, secio_key_set_t *k2);

/**
 * Determine ordering of two peers (for key assignment).
 * Returns 1 if local > remote (by nonce+pubkey comparison), 0 otherwise.
 */
int secio_ordering(const secio_ctx_t *ctx);

/**
 * Read a length-prefixed SecIO message from a buffer.
 * The 4-byte big-endian length prefix is consumed.
 * *payload_out points into buf (no copy), *payload_len is set.
 * Returns total bytes consumed (4 + payload), or -1.
 */
int secio_read_framed(const uint8_t *buf, uint32_t buf_size,
                      const uint8_t **payload_out, uint32_t *payload_len);

/**
 * Write a 4-byte BE length prefix before the payload in buf.
 * payload_len: length of payload (not including prefix).
 * Returns 4 (bytes of prefix written), or -1 if buf_size < 4.
 */
int secio_write_frame_prefix(uint32_t payload_len, uint8_t *buf, uint32_t buf_size);

#ifdef __cplusplus
}
#endif

#endif /* CKB_SECIO_H */
