/*
 * ckb_secio.c — SecIO handshake state machine
 *
 * Platform crypto is injected via secio_crypto_t callbacks.
 * This file contains no direct crypto calls — pure protocol logic.
 */

#include "ckb_secio.h"
#include "ckb_molecule.h"
#include <string.h>

/* Preferred algorithms — what we offer (CKB nodes accept these) */
#define SECIO_OFFER_EXCHANGES  "P-256"
#define SECIO_OFFER_CIPHERS    "AES-128"
#define SECIO_OFFER_HASHES     "SHA-256"

/* Big-endian 4-byte helpers */
static inline uint32_t read_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}
static inline void write_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)(v);
}

/* ── Init ── */

int secio_init(secio_ctx_t *ctx, const secio_crypto_t *crypto) {
    if (!ctx || !crypto) return -1;
    memset(ctx, 0, sizeof(*ctx));

    if (crypto->generate_static_keypair(ctx->local_static_privkey,
                                         ctx->local_static_pubkey) < 0) return -1;
    if (crypto->generate_ephemeral_keypair(ctx->local_ephem_privkey,
                                            ctx->local_ephem_pubkey) < 0) return -1;
    if (crypto->random_bytes(ctx->local_nonce, SECIO_NONCE_SIZE) < 0) return -1;

    ctx->state = SECIO_STATE_IDLE;
    return 0;
}

/* ── Step 1: Build Propose ── */

int secio_build_propose(secio_ctx_t *ctx, const secio_crypto_t *crypto,
                        uint8_t *buf, uint32_t buf_size) {
    (void)crypto;
    if (!ctx || !buf || buf_size < 8) return -1;

    /* Encode pubkey as Molecule PublicKey union (secp256k1) */
    uint8_t pubkey_mol[4 + 4 + 33]; /* union tag + Bytes header + 33 bytes */
    int pubkey_mol_len = mol_pubkey_encode(ctx->local_static_pubkey, 33,
                                            pubkey_mol, sizeof(pubkey_mol));
    if (pubkey_mol_len < 0) return -1;

    secio_propose_t propose;
    memset(&propose, 0, sizeof(propose));
    memcpy(propose.rand, ctx->local_nonce, 16);

    /* pubkey field = the PublicKey union bytes */
    memcpy(propose.pubkey, pubkey_mol, (uint32_t)pubkey_mol_len);
    propose.pubkey_len = (uint32_t)pubkey_mol_len;

    const char *exch = SECIO_OFFER_EXCHANGES;
    const char *ciph = SECIO_OFFER_CIPHERS;
    const char *hash = SECIO_OFFER_HASHES;

    memcpy(propose.exchanges, exch, strlen(exch));
    propose.exchanges_len = (uint32_t)strlen(exch);
    memcpy(propose.ciphers, ciph, strlen(ciph));
    propose.ciphers_len = (uint32_t)strlen(ciph);
    memcpy(propose.hashes, hash, strlen(hash));
    propose.hashes_len = (uint32_t)strlen(hash);

    /* Encode propose into a temp buffer so we can save it for signing */
    uint8_t propose_mol[1024];
    int propose_len = secio_propose_encode(&propose, propose_mol, sizeof(propose_mol));
    if (propose_len < 0) return -1;

    /* Save encoded propose for later signature computation */
    if ((uint32_t)propose_len > sizeof(ctx->local_propose_bytes)) return -1;
    memcpy(ctx->local_propose_bytes, propose_mol, (uint32_t)propose_len);
    ctx->local_propose_len = (uint32_t)propose_len;

    /* Write 4-byte BE length prefix + payload */
    uint32_t total = 4 + (uint32_t)propose_len;
    if (buf_size < total) return -1;
    write_u32_be(buf, (uint32_t)propose_len);
    memcpy(buf + 4, propose_mol, (uint32_t)propose_len);

    ctx->state = SECIO_STATE_PROPOSE_SENT;
    return (int)total;
}

/* ── Step 2: Process remote Propose ── */

/* Check if `offer` contains `want` (comma-separated list) */
static int algo_in_list(const char *offer, uint32_t offer_len, const char *want) {
    uint32_t want_len = (uint32_t)strlen(want);
    uint32_t i = 0;
    while (i < offer_len) {
        uint32_t j = i;
        while (j < offer_len && offer[j] != ',') j++;
        /* trim spaces */
        uint32_t s = i, e = j;
        while (s < e && offer[s] == ' ') s++;
        while (e > s && offer[e-1] == ' ') e--;
        if ((e - s) == want_len && memcmp(offer + s, want, want_len) == 0)
            return 1;
        i = j + 1;
    }
    return 0;
}

int secio_process_propose(secio_ctx_t *ctx, const uint8_t *buf, uint32_t buf_len) {
    if (!ctx || !buf) return -1;

    /* Save raw propose bytes for signature verification */
    if (buf_len > sizeof(ctx->remote_propose_bytes)) return -1;
    memcpy(ctx->remote_propose_bytes, buf, buf_len);
    ctx->remote_propose_len = buf_len;

    secio_propose_t remote;
    if (secio_propose_decode(buf, buf_len, &remote) < 0) return -1;

    /* Save remote nonce */
    memcpy(ctx->remote_nonce, remote.rand, 16);

    /* Decode remote pubkey from Molecule PublicKey union */
    const uint8_t *pk; uint32_t pk_len;
    if (mol_pubkey_decode(remote.pubkey, remote.pubkey_len, &pk, &pk_len) < 0) return -1;
    if (pk_len > sizeof(ctx->remote_static_pubkey)) return -1;
    memcpy(ctx->remote_static_pubkey, pk, pk_len);
    ctx->remote_static_pubkey_len = pk_len;

    /* Negotiate algorithms: use our preferences if remote supports them */
    if (algo_in_list(remote.exchanges, remote.exchanges_len, SECIO_OFFER_EXCHANGES)) {
        memcpy(ctx->chosen_exchange, SECIO_OFFER_EXCHANGES, strlen(SECIO_OFFER_EXCHANGES)+1);
    } else {
        return -1; /* no common exchange algorithm */
    }

    if (algo_in_list(remote.ciphers, remote.ciphers_len, SECIO_OFFER_CIPHERS)) {
        memcpy(ctx->chosen_cipher, SECIO_OFFER_CIPHERS, strlen(SECIO_OFFER_CIPHERS)+1);
    } else {
        return -1;
    }

    if (algo_in_list(remote.hashes, remote.hashes_len, SECIO_OFFER_HASHES)) {
        memcpy(ctx->chosen_hash, SECIO_OFFER_HASHES, strlen(SECIO_OFFER_HASHES)+1);
    } else {
        return -1;
    }

    ctx->state = SECIO_STATE_PROPOSE_RECV;
    return 0;
}

/* ── Ordering ── */

int secio_ordering(const secio_ctx_t *ctx) {
    /*
     * Ordering is determined by comparing:
     *   SHA256(remote_pubkey || local_nonce)  vs  SHA256(local_pubkey || remote_nonce)
     * If local > remote, we are "higher" and use the first half of stretched keys.
     * In practice for the key-split, the side with higher ordering gets keys[0..n/2],
     * the lower side gets keys[n/2..n].
     *
     * Without SHA256 available here (no crypto callbacks), we do a simple lexicographic
     * comparison of (pubkey XOR nonce) as a deterministic ordering.
     * The actual implementation uses crypto->sha256 — this is called from secio_process_exchange.
     */
    int i;
    for (i = 0; i < 16; i++) {
        uint8_t local_v  = ctx->local_static_pubkey[i]  ^ ctx->local_nonce[i];
        uint8_t remote_v = ctx->remote_static_pubkey[i] ^ ctx->remote_nonce[i];
        if (local_v > remote_v) return 1;
        if (local_v < remote_v) return 0;
    }
    return 0;
}

/* ── Step 3: Build Exchange ── */

int secio_build_exchange(secio_ctx_t *ctx, const secio_crypto_t *crypto,
                         uint8_t *buf, uint32_t buf_size) {
    if (!ctx || !crypto || !buf) return -1;
    if (ctx->state != SECIO_STATE_PROPOSE_RECV) return -1;

    /* data_to_sign = local_propose || remote_propose || local_ephem_pubkey */
    uint8_t to_sign[512 + 512 + 65];
    uint32_t sign_len = 0;

    memcpy(to_sign + sign_len, ctx->local_propose_bytes, ctx->local_propose_len);
    sign_len += ctx->local_propose_len;
    memcpy(to_sign + sign_len, ctx->remote_propose_bytes, ctx->remote_propose_len);
    sign_len += ctx->remote_propose_len;
    memcpy(to_sign + sign_len, ctx->local_ephem_pubkey, 65);
    sign_len += 65;

    /* SHA-256 the data to sign */
    uint8_t data_hash[32];
    if (crypto->sha256(to_sign, sign_len, data_hash) < 0) return -1;

    /* Sign with our static secp256k1 private key */
    secio_exchange_t exchange;
    memset(&exchange, 0, sizeof(exchange));
    memcpy(exchange.epubkey, ctx->local_ephem_pubkey, 65);
    exchange.epubkey_len = 65;

    if (crypto->ecdsa_sign(ctx->local_static_privkey, data_hash,
                           exchange.signature, &exchange.signature_len) < 0) return -1;

    /* Encode exchange */
    uint8_t exchange_mol[1024];
    int exchange_len = secio_exchange_encode(&exchange, exchange_mol, sizeof(exchange_mol));
    if (exchange_len < 0) return -1;

    /* Write 4-byte BE length prefix + payload */
    uint32_t total = 4 + (uint32_t)exchange_len;
    if (buf_size < total) return -1;
    write_u32_be(buf, (uint32_t)exchange_len);
    memcpy(buf + 4, exchange_mol, (uint32_t)exchange_len);

    ctx->state = SECIO_STATE_EXCHANGE_SENT;
    return (int)total;
}

/* ── Step 4: Process remote Exchange + key stretching ── */

int secio_stretch_keys(const secio_crypto_t *crypto,
                       const uint8_t *key_material, size_t km_len,
                       const char *cipher,
                       const char *hash,
                       secio_key_set_t *k1, secio_key_set_t *k2) {
    (void)cipher; (void)hash; /* currently only AES-128+SHA-256 */

    /*
     * Key stretching per Tentacle/SecIO:
     * seed = HMAC-SHA256(key_material, "")
     * Generate 2*(iv_size + key_size + mac_size) bytes by repeated HMAC:
     *   a_1 = HMAC(key_material, seed)
     *   a_2 = HMAC(key_material, a_1)
     *   output_1 = HMAC(key_material, a_1 || seed)
     *   output_2 = HMAC(key_material, a_2 || seed)
     *   ...
     * Split output in half for k1 (local if higher) and k2 (remote if lower).
     *
     * Total needed: 2 * (16 + 16 + 20) = 104 bytes
     */
    const uint8_t seed[] = "key expansion";
    const size_t  seed_len = 13;
    const size_t  need = 2 * (SECIO_IV_SIZE + SECIO_KEY_SIZE + SECIO_HMAC_SIZE);

    uint8_t longer[256];
    uint8_t a[32], b[32];
    size_t  pos = 0;

    /* a_1 = HMAC(km, seed) */
    if (crypto->hmac_sha256(key_material, km_len, seed, seed_len, a) < 0) return -1;

    while (pos < need) {
        /* output_i = HMAC(km, a_i || seed) */
        uint8_t concat[32 + 13];
        memcpy(concat, a, 32);
        memcpy(concat + 32, seed, seed_len);
        if (crypto->hmac_sha256(key_material, km_len, concat, 32 + seed_len, b) < 0) return -1;

        size_t chunk = (need - pos < 32) ? (need - pos) : 32;
        memcpy(longer + pos, b, chunk);
        pos += chunk;

        /* a_{i+1} = HMAC(km, a_i) */
        if (crypto->hmac_sha256(key_material, km_len, a, 32, a) < 0) return -1;
    }

    /* Split in half */
    const uint8_t *h1 = longer;
    const uint8_t *h2 = longer + need / 2;

    memcpy(k1->iv,      h1,                           SECIO_IV_SIZE);
    memcpy(k1->key,     h1 + SECIO_IV_SIZE,           SECIO_KEY_SIZE);
    memcpy(k1->mac_key, h1 + SECIO_IV_SIZE + SECIO_KEY_SIZE, SECIO_HMAC_SIZE);

    memcpy(k2->iv,      h2,                           SECIO_IV_SIZE);
    memcpy(k2->key,     h2 + SECIO_IV_SIZE,           SECIO_KEY_SIZE);
    memcpy(k2->mac_key, h2 + SECIO_IV_SIZE + SECIO_KEY_SIZE, SECIO_HMAC_SIZE);

    return 0;
}

int secio_process_exchange(secio_ctx_t *ctx, const secio_crypto_t *crypto,
                           const uint8_t *buf, uint32_t buf_len) {
    if (!ctx || !crypto || !buf) return -1;
    if (ctx->state != SECIO_STATE_EXCHANGE_SENT) return -1;

    secio_exchange_t remote_exchange;
    if (secio_exchange_decode(buf, buf_len, &remote_exchange) < 0) return -1;

    memcpy(ctx->remote_ephem_pubkey, remote_exchange.epubkey, remote_exchange.epubkey_len);
    ctx->remote_ephem_pubkey_len = remote_exchange.epubkey_len;

    /* Verify remote's signature */
    /* data_to_verify = remote_propose || local_propose || remote_ephem_pubkey */
    uint8_t to_verify[512 + 512 + 65];
    uint32_t verify_len = 0;
    memcpy(to_verify + verify_len, ctx->remote_propose_bytes, ctx->remote_propose_len);
    verify_len += ctx->remote_propose_len;
    memcpy(to_verify + verify_len, ctx->local_propose_bytes, ctx->local_propose_len);
    verify_len += ctx->local_propose_len;
    memcpy(to_verify + verify_len, remote_exchange.epubkey, remote_exchange.epubkey_len);
    verify_len += remote_exchange.epubkey_len;

    uint8_t verify_hash[32];
    if (crypto->sha256(to_verify, verify_len, verify_hash) < 0) return -1;

    if (crypto->ecdsa_verify(ctx->remote_static_pubkey, ctx->remote_static_pubkey_len,
                              verify_hash,
                              remote_exchange.signature, remote_exchange.signature_len) < 0) {
        ctx->state = SECIO_STATE_FAILED;
        return -1;
    }

    /* ECDH: derive shared secret from our ephemeral privkey + remote ephemeral pubkey */
    uint8_t shared_secret[32];
    if (crypto->ecdh_p256(ctx->local_ephem_privkey, ctx->remote_ephem_pubkey,
                           shared_secret) < 0) {
        ctx->state = SECIO_STATE_FAILED;
        return -1;
    }

    /* Determine ordering for key assignment */
    ctx->we_are_higher = secio_ordering(ctx);

    /* Stretch keys */
    secio_key_set_t k1, k2;
    if (secio_stretch_keys(crypto, shared_secret, 32,
                            ctx->chosen_cipher, ctx->chosen_hash, &k1, &k2) < 0) {
        ctx->state = SECIO_STATE_FAILED;
        return -1;
    }

    /* Assign: higher peer gets k1 for local, k2 for remote */
    if (ctx->we_are_higher) {
        ctx->local_keys  = k1;
        ctx->remote_keys = k2;
    } else {
        ctx->local_keys  = k2;
        ctx->remote_keys = k1;
    }

    /* Clear sensitive material */
    memset(shared_secret, 0, sizeof(shared_secret));

    ctx->state = SECIO_STATE_ESTABLISHED;
    return 0;
}

/* ── Framing helpers ── */

int secio_read_framed(const uint8_t *buf, uint32_t buf_size,
                      const uint8_t **payload_out, uint32_t *payload_len) {
    if (!buf || buf_size < 4) return -1;
    uint32_t len = read_u32_be(buf);
    if (len > buf_size - 4) return -1;
    if (payload_out) *payload_out = buf + 4;
    if (payload_len) *payload_len = len;
    return (int)(4 + len);
}

int secio_write_frame_prefix(uint32_t payload_len, uint8_t *buf, uint32_t buf_size) {
    if (!buf || buf_size < 4) return -1;
    write_u32_be(buf, payload_len);
    return 4;
}
