/*
 * crypto_openssl.c — OpenSSL + libsecp256k1 implementation of secio_crypto_t
 *
 * Used for POSIX host testing (Phase 4).
 * On ESP32-P4, replace with mbedTLS equivalents.
 */

#include "crypto_openssl.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>

/* ── secp256k1 context (global, not thread-safe for test purposes) ── */
static secp256k1_context *s_secp_ctx = NULL;

static secp256k1_context *get_secp_ctx(void) {
    if (!s_secp_ctx) {
        s_secp_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
    return s_secp_ctx;
}

/* ── random_bytes ── */
static int cb_random_bytes(uint8_t *buf, size_t len) {
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

/* ── generate_static_keypair (secp256k1) ── */
static int cb_generate_static_keypair(uint8_t privkey[32], uint8_t pubkey[33]) {
    secp256k1_context *ctx = get_secp_ctx();
    secp256k1_pubkey pub;

    /* Generate random privkey, retry until valid */
    for (int attempts = 0; attempts < 100; attempts++) {
        if (RAND_bytes(privkey, 32) != 1) return -1;
        if (secp256k1_ec_seckey_verify(ctx, privkey)) {
            if (secp256k1_ec_pubkey_create(ctx, &pub, privkey)) {
                size_t publen = 33;
                secp256k1_ec_pubkey_serialize(ctx, pubkey, &publen, &pub,
                                              SECP256K1_EC_COMPRESSED);
                return 0;
            }
        }
    }
    return -1;
}

/* ── generate_ephemeral_keypair (P-256, uncompressed 65 bytes) ── */
static int cb_generate_ephemeral_keypair(uint8_t privkey[32], uint8_t pubkey[65]) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return -1;

    if (EC_KEY_generate_key(key) != 1) {
        EC_KEY_free(key);
        return -1;
    }

    /* Export private key */
    const BIGNUM *priv_bn = EC_KEY_get0_private_key(key);
    int priv_bytes = BN_num_bytes(priv_bn);
    memset(privkey, 0, 32);
    BN_bn2bin(priv_bn, privkey + (32 - priv_bytes));

    /* Export public key uncompressed (04 || x || y) */
    const EC_GROUP *grp = EC_KEY_get0_group(key);
    const EC_POINT *pub_pt = EC_KEY_get0_public_key(key);
    size_t publen = EC_POINT_point2oct(grp, pub_pt,
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       pubkey, 65, NULL);
    EC_KEY_free(key);
    return (publen == 65) ? 0 : -1;
}

/* ── ecdh_p256 ── */
static int cb_ecdh_p256(const uint8_t privkey[32],
                         const uint8_t remote_pubkey[65],
                         uint8_t shared_secret[32]) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return -1;

    int ret = -1;
    EC_POINT *pub_pt = NULL;
    const EC_GROUP *grp = EC_KEY_get0_group(key);

    /* Set our private key */
    BIGNUM *priv_bn = BN_bin2bn(privkey, 32, NULL);
    if (!priv_bn) goto cleanup;
    if (EC_KEY_set_private_key(key, priv_bn) != 1) goto cleanup;

    /* Compute public key from private (needed for ECDH) */
    {
        EC_POINT *our_pub = EC_POINT_new(grp);
        if (!our_pub) goto cleanup;
        EC_POINT_mul(grp, our_pub, priv_bn, NULL, NULL, NULL);
        EC_KEY_set_public_key(key, our_pub);
        EC_POINT_free(our_pub);
    }

    /* Parse remote public key */
    pub_pt = EC_POINT_new(grp);
    if (!pub_pt) goto cleanup;
    if (EC_POINT_oct2point(grp, pub_pt, remote_pubkey, 65, NULL) != 1) goto cleanup;

    /* ECDH: compute shared point, take x-coordinate */
    {
        
        size_t shared_pt_len = EC_POINT_point2oct(grp, pub_pt,
                                                   POINT_CONVERSION_UNCOMPRESSED,
                                                   NULL, 0, NULL);
        if (shared_pt_len != 65) goto cleanup;

        /* Manual scalar multiply: shared = priv * remote_pub */
        EC_POINT *shared = EC_POINT_new(grp);
        if (!shared) goto cleanup;
        if (EC_POINT_mul(grp, shared, NULL, pub_pt, priv_bn, NULL) != 1) {
            EC_POINT_free(shared);
            goto cleanup;
        }

        /* Extract x-coordinate as shared secret */
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        if (!x || !y) {
            EC_POINT_free(shared);
            BN_free(x); BN_free(y);
            goto cleanup;
        }
        EC_POINT_get_affine_coordinates_GFp(grp, shared, x, y, NULL);
        int xbytes = BN_num_bytes(x);
        memset(shared_secret, 0, 32);
        BN_bn2bin(x, shared_secret + (32 - xbytes));
        BN_free(x); BN_free(y);
        EC_POINT_free(shared);
        ret = 0;
    }

cleanup:
    if (pub_pt) EC_POINT_free(pub_pt);
    if (priv_bn) BN_free(priv_bn);
    EC_KEY_free(key);
    return ret;
}

/* ── sha256 ── */
static int cb_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256(data, len, out);
    return 0;
}

/* ── hmac_sha256 ── */
static int cb_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t out[32]) {
    uint32_t outlen = 32;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &outlen);
    return (outlen == 32) ? 0 : -1;
}

/* ── ecdsa_sign (secp256k1 DER) ── */
static int cb_ecdsa_sign(const uint8_t privkey[32],
                          const uint8_t data_hash[32],
                          uint8_t *sig_buf, uint32_t *sig_len) {
    secp256k1_context *ctx = get_secp_ctx();
    secp256k1_ecdsa_signature sig;

    if (!secp256k1_ecdsa_sign(ctx, &sig, data_hash, privkey, NULL, NULL))
        return -1;

    /* Normalise to low-S form (required by Tentacle) */
    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

    /* Serialize as DER */
    size_t der_len = 72;
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, sig_buf, &der_len, &sig))
        return -1;

    *sig_len = (uint32_t)der_len;
    return 0;
}

/* ── ecdsa_verify (secp256k1) ── */
static int cb_ecdsa_verify(const uint8_t *pubkey, uint32_t pubkey_len,
                            const uint8_t data_hash[32],
                            const uint8_t *sig, uint32_t sig_len) {
    secp256k1_context *ctx = get_secp_ctx();
    secp256k1_pubkey pub;
    secp256k1_ecdsa_signature parsed_sig;

    if (!secp256k1_ec_pubkey_parse(ctx, &pub, pubkey, pubkey_len))
        return -1;

    if (!secp256k1_ecdsa_signature_parse_der(ctx, &parsed_sig, sig, sig_len))
        return -1;

    /* Normalise (accept both high and low S) */
    secp256k1_ecdsa_signature_normalize(ctx, &parsed_sig, &parsed_sig);

    return secp256k1_ecdsa_verify(ctx, &parsed_sig, data_hash, &pub) ? 0 : -1;
}

/* ── Public: fill in the crypto table ── */
void crypto_openssl_init(secio_crypto_t *c) {
    c->random_bytes             = cb_random_bytes;
    c->generate_static_keypair  = cb_generate_static_keypair;
    c->generate_ephemeral_keypair = cb_generate_ephemeral_keypair;
    c->ecdh_p256                = cb_ecdh_p256;
    c->sha256                   = cb_sha256;
    c->hmac_sha256              = cb_hmac_sha256;
    c->ecdsa_sign               = cb_ecdsa_sign;
    c->ecdsa_verify             = cb_ecdsa_verify;
}
