// bitchat_noise.cpp — Noise_XX_25519_ChaChaPoly_SHA256
// toastmanAu/ckb-light-esp
//
// Crypto backends:
//   SHA-256:           trezor sha2.c (CKB-ESP32/src/trezor_crypto/)
//   ChaCha20-Poly1305: trezor rfc7539 (CKB-ESP32/src/chacha20poly1305/)
//   X25519 DH:         libsodium (HOST_TEST) / portable C (device) via x25519.h
//   HMAC-SHA256/HKDF:  built on sha2.c

#include "bitchat_noise.h"
#include "curve25519/x25519.h"  // X25519: libsodium (HOST_TEST) or portable C (device)

#ifdef HOST_TEST
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <stdint.h>
#else
  #include <Arduino.h>
  #include <esp_random.h>
#endif

extern "C" {
  #include "trezor_crypto/sha2.h"         // sha256_Raw() — trezor_crypto
  #include "chacha20poly1305/rfc7539.h"      // rfc7539_init/auth/finish — chacha20poly1305/
  #include "chacha20poly1305/chacha20poly1305.h"
}

// ─── Nonce encoding ───────────────────────────────────────────────────────────
// RFC 7539 nonce: [4-byte counter=0][8-byte nonce big-endian]
static void _make_nonce12(uint8_t nonce12[12], uint64_t n) {
    nonce12[0]=nonce12[1]=nonce12[2]=nonce12[3]=0;
    for (int i=0;i<8;i++) nonce12[4+i]=(uint8_t)((n>>(56-i*8))&0xFF);
}

// ─── AEAD (trezor rfc7539) ────────────────────────────────────────────────────
// chacha20poly1305_encrypt/decrypt automatically feed CT into Poly1305.
// So: init → auth(AAD) → encrypt/decrypt(data) → finish(tag)

static bool aead_seal(const uint8_t key[32], uint64_t nonce_n,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* pt, size_t pt_len,
                       uint8_t* ct, uint8_t tag[16]) {
    uint8_t nonce12[12]; _make_nonce12(nonce12, nonce_n);
    chacha20poly1305_ctx ctx;
    rfc7539_init(&ctx, key, nonce12);
    if (aad && aad_len) rfc7539_auth(&ctx, aad, aad_len);
    chacha20poly1305_encrypt(&ctx, pt, ct, pt_len);
    rfc7539_finish(&ctx, (int64_t)aad_len, (int64_t)pt_len, tag);
    return true;
}

static bool aead_open(const uint8_t key[32], uint64_t nonce_n,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* ct, size_t ct_len,
                       const uint8_t tag[16], uint8_t* pt) {
    uint8_t nonce12[12]; _make_nonce12(nonce12, nonce_n);
    chacha20poly1305_ctx ctx;
    // Decrypt and accumulate CT into Poly1305 in one pass
    rfc7539_init(&ctx, key, nonce12);
    if (aad && aad_len) rfc7539_auth(&ctx, aad, aad_len);
    chacha20poly1305_decrypt(&ctx, ct, pt, ct_len);
    uint8_t computed[16];
    rfc7539_finish(&ctx, (int64_t)aad_len, (int64_t)ct_len, computed);
    // Constant-time compare
    uint8_t diff = 0;
    for (int i=0;i<16;i++) diff |= (computed[i]^tag[i]);
    if (diff) { if (pt && ct_len) memset(pt, 0, ct_len); return false; }
    return true;
}

// ─── HMAC-SHA256 + HKDF ───────────────────────────────────────────────────────

static void hmac_sha256(const uint8_t* key, size_t key_len,
                         const uint8_t* data, size_t data_len,
                         uint8_t out[32]) {
    uint8_t k_block[64]; memset(k_block, 0, 64);
    if (key_len > 64) sha256_Raw(key, key_len, k_block);
    else memcpy(k_block, key, key_len);
    uint8_t ipad[64], opad[64];
    for (int i=0;i<64;i++) { ipad[i]=k_block[i]^0x36; opad[i]=k_block[i]^0x5C; }
    // inner = SHA-256(ipad || data)
    uint8_t* inner_buf = (uint8_t*)malloc(64 + data_len);
    if (!inner_buf) return;
    memcpy(inner_buf, ipad, 64);
    memcpy(inner_buf+64, data, data_len);
    uint8_t inner[32];
    sha256_Raw(inner_buf, 64+data_len, inner);
    free(inner_buf);
    // outer = SHA-256(opad || inner)
    uint8_t outer_buf[96];
    memcpy(outer_buf, opad, 64);
    memcpy(outer_buf+64, inner, 32);
    sha256_Raw(outer_buf, 96, out);
}

static void hkdf_extract(const uint8_t* salt, size_t salt_len,
                           const uint8_t* ikm, size_t ikm_len,
                           uint8_t prk[32]) {
    if (!salt || !salt_len) {
        uint8_t zero[32]={0};
        hmac_sha256(zero, 32, ikm, ikm_len, prk);
    } else {
        hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }
}

static void hkdf_expand_2(const uint8_t prk[32], uint8_t out1[32], uint8_t out2[32]) {
    hmac_sha256(prk, 32, (const uint8_t*)"\x01", 1, out1);
    uint8_t t2[33]; memcpy(t2, out1, 32); t2[32]=0x02;
    hmac_sha256(prk, 32, t2, 33, out2);
}

// ─── Noise internal helpers ───────────────────────────────────────────────────

static void _mix_hash(NoiseSession* s, const uint8_t* data, size_t len) {
    uint8_t* buf = (uint8_t*)malloc(NOISE_HASH_SIZE + len);
    if (!buf) return;
    memcpy(buf, s->h, NOISE_HASH_SIZE);
    memcpy(buf+NOISE_HASH_SIZE, data, len);
    sha256_Raw(buf, NOISE_HASH_SIZE+len, s->h);
    free(buf);
}

static void _mix_key(NoiseSession* s, const uint8_t* input, size_t len) {
    uint8_t prk[32], new_ck[32], temp_k[32];
    hkdf_extract(s->ck, NOISE_HASH_SIZE, input, len, prk);
    hkdf_expand_2(prk, new_ck, temp_k);
    memcpy(s->ck, new_ck, 32);
    // Store temp_k in both cipher states (handshake phase uses send_cs.k for encrypt)
    memcpy(s->send_cs.k, temp_k, 32); s->send_cs.n=0; s->send_cs.has_key=true;
    memcpy(s->recv_cs.k, temp_k, 32); s->recv_cs.n=0; s->recv_cs.has_key=true;
}

static bool _encrypt_and_hash(NoiseSession* s,
                                const uint8_t* pt, size_t pt_len,
                                uint8_t* ct, size_t* ct_len) {
    if (!s->send_cs.has_key) {
        memcpy(ct, pt, pt_len); *ct_len=pt_len;
        _mix_hash(s, pt, pt_len); return true;
    }
    uint8_t tag[16];
    if (!aead_seal(s->send_cs.k, s->send_cs.n, s->h, NOISE_HASH_SIZE,
                   pt, pt_len, ct, tag)) return false;
    s->send_cs.n++;
    memcpy(ct+pt_len, tag, 16); *ct_len=pt_len+16;
    _mix_hash(s, ct, *ct_len);
    return true;
}

static bool _decrypt_and_hash(NoiseSession* s,
                                const uint8_t* ct, size_t ct_len,
                                uint8_t* pt, size_t* pt_len) {
    if (!s->recv_cs.has_key) {
        memcpy(pt, ct, ct_len); *pt_len=ct_len;
        _mix_hash(s, ct, ct_len); return true;
    }
    if (ct_len < 16) return false;
    const uint8_t* tag = ct+(ct_len-16);
    size_t data_len = ct_len-16;
    if (!aead_open(s->recv_cs.k, s->recv_cs.n, s->h, NOISE_HASH_SIZE,
                   ct, data_len, tag, pt)) { s->state=NOISE_STATE_ERROR; return false; }
    s->recv_cs.n++;
    *pt_len=data_len;
    _mix_hash(s, ct, ct_len);
    return true;
}

static void _split(NoiseSession* s) {
    uint8_t prk[32], k1[32], k2[32];
    hkdf_extract(s->ck, 32, (const uint8_t*)"", 0, prk);
    hkdf_expand_2(prk, k1, k2);
    if (s->is_initiator) {
        memcpy(s->send_cs.k,k1,32); s->send_cs.n=0; s->send_cs.has_key=true;
        memcpy(s->recv_cs.k,k2,32); s->recv_cs.n=0; s->recv_cs.has_key=true;
    } else {
        memcpy(s->send_cs.k,k2,32); s->send_cs.n=0; s->send_cs.has_key=true;
        memcpy(s->recv_cs.k,k1,32); s->recv_cs.n=0; s->recv_cs.has_key=true;
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

void noise_gen_keypair(uint8_t* priv, uint8_t* pub) {
#ifdef HOST_TEST
    FILE* f = fopen("/dev/urandom","rb");
    if (f) { fread(priv,1,32,f); fclose(f); }
    else { for(int i=0;i<32;i++) priv[i]=(uint8_t)(rand()&0xFF); }
#else
    esp_fill_random(priv, 32);
#endif
    x25519_clamp(priv);
    x25519_base(pub, priv);
}

void noise_init(NoiseSession* sess, const uint8_t* static_priv, const uint8_t* static_pub) {
    memset(sess, 0, sizeof(*sess));
    sess->state = NOISE_STATE_UNINIT;
    if (static_priv) {
        memcpy(sess->s_priv, static_priv, 32);
        if (static_pub) memcpy(sess->s_pub, static_pub, 32);
        else x25519_base(sess->s_pub, static_priv);
    } else {
        noise_gen_keypair(sess->s_priv, sess->s_pub);
    }
    sha256_Raw(sess->s_pub, 32, sess->fingerprint);
}

static void _proto_init(NoiseSession* sess, bool is_initiator) {
    sess->is_initiator = is_initiator;
    sess->send_cs.has_key=false; sess->send_cs.n=0;
    sess->recv_cs.has_key=false; sess->recv_cs.n=0;
    // h = protocol_name padded to 32 bytes (name is 32 chars exactly)
    memset(sess->h, 0, 32);
    const char* name = NOISE_PROTOCOL_NAME;
    size_t nlen = strlen(name);
    if (nlen <= 32) memcpy(sess->h, name, nlen);
    else sha256_Raw((const uint8_t*)name, nlen, sess->h);
    memcpy(sess->ck, sess->h, 32);
    _mix_hash(sess, (const uint8_t*)"", 0);  // empty prologue
    noise_gen_keypair(sess->e_priv, sess->e_pub);
}

// ─── Handshake messages ───────────────────────────────────────────────────────

bool noise_write_msg1(NoiseSession* sess, uint8_t buf[NOISE_MSG1_SIZE]) {
    _proto_init(sess, true);
    sess->state = NOISE_STATE_MSG1_SENT;
    memcpy(buf, sess->e_pub, 32);
    _mix_hash(sess, sess->e_pub, 32);
    return true;
}

bool noise_read_msg1_write_msg2(NoiseSession* sess,
                                 const uint8_t* msg1, size_t msg1_len,
                                 uint8_t* buf, size_t* out_len) {
    if (msg1_len < NOISE_MSG1_SIZE) return false;
    _proto_init(sess, false);
    sess->state = NOISE_STATE_MSG2_SENT;
    // Read re
    memcpy(sess->re_pub, msg1, 32);
    _mix_hash(sess, sess->re_pub, 32);
    size_t off = 0;
    // Send e
    memcpy(buf+off, sess->e_pub, 32); _mix_hash(sess, sess->e_pub, 32); off+=32;
    // DH ee = DH(e_resp, e_init)
    uint8_t dh[32]; x25519(dh, sess->e_priv, sess->re_pub); _mix_key(sess, dh, 32);
    // Send s (encrypted)
    uint8_t enc_s[48]; size_t enc_s_len;
    if (!_encrypt_and_hash(sess, sess->s_pub, 32, enc_s, &enc_s_len)) return false;
    memcpy(buf+off, enc_s, enc_s_len); off+=enc_s_len;
    // DH es = DH(s_resp, e_init)
    x25519(dh, sess->s_priv, sess->re_pub); _mix_key(sess, dh, 32);
    *out_len = off;
    return true;
}

bool noise_read_msg2_write_msg3(NoiseSession* sess,
                                 const uint8_t* msg2, size_t msg2_len,
                                 uint8_t* buf, size_t* out_len) {
    if (msg2_len < 80 || sess->state != NOISE_STATE_MSG1_SENT) return false;
    sess->state = NOISE_STATE_MSG2_RECV;
    size_t off = 0;
    // Read re
    memcpy(sess->re_pub, msg2+off, 32); _mix_hash(sess, sess->re_pub, 32); off+=32;
    // DH ee = DH(e_init, e_resp)
    uint8_t dh[32]; x25519(dh, sess->e_priv, sess->re_pub); _mix_key(sess, dh, 32);
    // Decrypt rs
    uint8_t dec_rs[48]; size_t dec_rs_len;
    if (msg2_len-off < 48) return false;
    if (!_decrypt_and_hash(sess, msg2+off, 48, dec_rs, &dec_rs_len)) return false;
    if (dec_rs_len < 32) return false;
    memcpy(sess->rs_pub, dec_rs, 32); off+=48;
    // DH es = DH(e_init, s_resp)
    x25519(dh, sess->e_priv, sess->rs_pub); _mix_key(sess, dh, 32);
    // Write msg3: send s encrypted
    uint8_t enc_s[48]; size_t enc_s_len;
    if (!_encrypt_and_hash(sess, sess->s_pub, 32, enc_s, &enc_s_len)) return false;
    memcpy(buf, enc_s, enc_s_len); *out_len=enc_s_len;
    // DH se = DH(s_init, e_resp)
    x25519(dh, sess->s_priv, sess->re_pub); _mix_key(sess, dh, 32);
    _split(sess);
    sess->state = NOISE_STATE_TRANSPORT;
    return true;
}

bool noise_read_msg3(NoiseSession* sess, const uint8_t* msg3, size_t msg3_len) {
    if (msg3_len < NOISE_MSG3_MIN || sess->state != NOISE_STATE_MSG2_SENT) return false;
    uint8_t dec_is[48]; size_t dec_is_len;
    if (!_decrypt_and_hash(sess, msg3, 48, dec_is, &dec_is_len)) return false;
    if (dec_is_len < 32) return false;
    memcpy(sess->rs_pub, dec_is, 32);
    uint8_t dh[32];
    x25519(dh, sess->e_priv, sess->rs_pub); _mix_key(sess, dh, 32);
    _split(sess);
    sess->state = NOISE_STATE_TRANSPORT;
    return true;
}

// ─── Transport ────────────────────────────────────────────────────────────────

bool noise_encrypt(NoiseSession* sess, const uint8_t* pt, size_t pt_len,
                   uint8_t* ct, size_t* ct_len) {
    if (!noise_ready(sess)) return false;
    uint8_t tag[16];
    if (!aead_seal(sess->send_cs.k, sess->send_cs.n, NULL, 0, pt, pt_len, ct, tag)) return false;
    memcpy(ct+pt_len, tag, 16); *ct_len=pt_len+16;
    sess->send_cs.n++;
    return true;
}

bool noise_decrypt(NoiseSession* sess, const uint8_t* ct, size_t ct_len,
                   uint8_t* pt, size_t* pt_len) {
    if (!noise_ready(sess) || ct_len < 16) return false;
    const uint8_t* tag = ct+(ct_len-16);
    size_t data_len = ct_len-16;
    if (!aead_open(sess->recv_cs.k, sess->recv_cs.n, NULL, 0, ct, data_len, tag, pt)) return false;
    *pt_len=data_len; sess->recv_cs.n++;
    return true;
}

// ─── Utilities ────────────────────────────────────────────────────────────────

const uint8_t* noise_remote_fingerprint(const NoiseSession* sess, uint8_t out[32]) {
    if (!sess || sess->state != NOISE_STATE_TRANSPORT) return NULL;
    sha256_Raw(sess->rs_pub, 32, out);
    return out;
}

void noise_fingerprint_hex(const uint8_t fp[32], char* out, size_t out_size) {
    for (int i=0;i<32&&(size_t)(i*2+2)<out_size;i++) snprintf(out+i*2,3,"%02x",fp[i]);
}
