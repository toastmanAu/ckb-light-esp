/*
 * connect_live.c — Phase 4: Live TCP connection to CKB node
 *
 * Full SecIO handshake + Yamux + GetLastState over CKB P2P.
 * Usage: ./connect_live [host] [port]
 *   Default: 192.168.68.87 8115
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/evp.h>

#include "ckb_secio.h"
#include "ckb_yamux.h"
#include "ckb_protocol.h"
#include "crypto_openssl.h"

#define BUF_SIZE     (64 * 1024)
#define PROTO_LC     100   /* CKB light client protocol ID */
#define GCM_TAG_SIZE 16    /* AES-128-GCM authentication tag */
#define GCM_IV_SIZE  12    /* 96-bit nonce for GCM */
#define GCM_KEY_SIZE 16    /* AES-128 key */

/* ── TCP helpers ── */

static int tcp_connect(const char *host, int port) {
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);

    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "gethostbyname(%s) failed\n", host);
        close(fd); return -1;
    }
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); close(fd); return -1;
    }
    printf("[tcp] connected to %s:%d (fd=%d)\n", host, port, fd);
    return fd;
}

static int tcp_send_all(int fd, const uint8_t *buf, uint32_t len) {
    uint32_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) { perror("write"); return -1; }
        sent += (uint32_t)n;
    }
    return 0;
}

static int tcp_recv_exact(int fd, uint8_t *buf, uint32_t len) {
    uint32_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n == 0) { fprintf(stderr, "[tcp] connection closed\n"); return -1; }
        if (n < 0) { perror("read"); return -1; }
        got += (uint32_t)n;
    }
    return 0;
}

/* Read a 4-byte BE length-prefixed SecIO frame */
static int recv_framed(int fd, uint8_t *buf, uint32_t buf_size, uint32_t *out_len) {
    uint8_t prefix[4];
    if (tcp_recv_exact(fd, prefix, 4) < 0) return -1;
    uint32_t plen = ((uint32_t)prefix[0] << 24) | ((uint32_t)prefix[1] << 16) |
                    ((uint32_t)prefix[2] <<  8) |  (uint32_t)prefix[3];
    if (plen > buf_size) {
        fprintf(stderr, "[frame] frame too large: %u bytes\n", plen);
        return -1;
    }
    if (tcp_recv_exact(fd, buf, plen) < 0) return -1;
    *out_len = plen;
    return 0;
}

/* ── AES-128-GCM encrypt: returns ciphertext_len + GCM_TAG_SIZE ── */
/* Nonce increments (little-endian) on each call */
static int aes128_gcm_encrypt(const uint8_t key[GCM_KEY_SIZE], uint8_t nonce[GCM_IV_SIZE],
                               const uint8_t *plaintext, uint32_t plen,
                               uint8_t *out) {
    /* Increment nonce (LE) before each use */
    for (int i = 0; i < GCM_IV_SIZE; i++) {
        if (++nonce[i]) break;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, outl = 0, outl2 = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, out, &outl, plaintext, (int)plen) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, out + outl, &outl2) != 1) goto done;
    /* Append GCM tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, out + outl + outl2) != 1) goto done;
    ret = outl + outl2 + GCM_TAG_SIZE;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ── AES-128-GCM decrypt: returns plaintext_len or -1 on auth failure ── */
static int aes128_gcm_decrypt(const uint8_t key[GCM_KEY_SIZE], uint8_t nonce[GCM_IV_SIZE],
                               const uint8_t *ciphertext, uint32_t clen,
                               uint8_t *out) {
    if (clen < GCM_TAG_SIZE) return -1;
    uint32_t ct_len = clen - GCM_TAG_SIZE;
    const uint8_t *tag = ciphertext + ct_len;

    /* Increment nonce (LE) before each use */
    for (int i = 0; i < GCM_IV_SIZE; i++) {
        if (++nonce[i]) break;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, outl = 0, outl2 = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, out, &outl, ciphertext, (int)ct_len) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, out + outl, &outl2) != 1) {
        fprintf(stderr, "[gcm] authentication tag mismatch!\n");
        goto done;
    }
    ret = outl + outl2;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ── Encrypted frame send: [4-byte BE len][ciphertext+GCM_TAG] ── */
static int send_encrypted(int fd, secio_ctx_t *sctx,
                           const uint8_t *plaintext, uint32_t plen) {
    static uint8_t sbuf[BUF_SIZE];
    int enc_len = aes128_gcm_encrypt(sctx->local_keys.key, sctx->local_keys.iv,
                                      plaintext, plen, sbuf + 4);
    if (enc_len < 0) return -1;

    uint32_t total = (uint32_t)enc_len;
    sbuf[0] = (total >> 24) & 0xFF;
    sbuf[1] = (total >> 16) & 0xFF;
    sbuf[2] = (total >>  8) & 0xFF;
    sbuf[3] =  total        & 0xFF;

    return tcp_send_all(fd, sbuf, 4 + total);
}

/* ── Encrypted frame recv + GCM decrypt + verify ── */
static int recv_encrypted(int fd, secio_ctx_t *sctx,
                           uint8_t *plaintext, uint32_t buf_size) {
    static uint8_t rbuf[BUF_SIZE];
    uint32_t frame_len;

    if (recv_framed(fd, rbuf, sizeof(rbuf), &frame_len) < 0) return -1;

    int dec_len = aes128_gcm_decrypt(sctx->remote_keys.key, sctx->remote_keys.iv,
                                      rbuf, frame_len, plaintext);
    if (dec_len < 0) return -1;
    if ((uint32_t)dec_len > buf_size) return -1;
    return dec_len;
}

/* ── Encode a Tentacle frame manually (header + payload) ── */
static int tentacle_build(uint8_t *out, uint32_t out_size,
                           uint8_t proto_id, uint8_t flags,
                           const uint8_t *payload, uint32_t payload_len) {
    /* Tentacle: [4-byte LE total_inner][proto_id 1B][flags 1B][payload] */
    /* total_inner = 1 (proto) + 1 (flags) + payload_len */
    uint32_t inner = 2 + payload_len;
    if (inner + 4 > out_size) return -1;
    out[0] = (inner)       & 0xFF;
    out[1] = (inner >>  8) & 0xFF;
    out[2] = (inner >> 16) & 0xFF;
    out[3] = (inner >> 24) & 0xFF;
    out[4] = proto_id;
    out[5] = flags;
    if (payload && payload_len > 0)
        memcpy(out + 6, payload, payload_len);
    return (int)(6 + payload_len);
}

/* ── Parse a Tentacle frame ── */
static int tentacle_parse(const uint8_t *buf, uint32_t buf_len,
                           uint8_t *proto_id, uint8_t *flags,
                           const uint8_t **payload, uint32_t *payload_len) {
    if (buf_len < 6) return -1;
    uint32_t inner = (uint32_t)buf[0] | ((uint32_t)buf[1]<<8) |
                     ((uint32_t)buf[2]<<16) | ((uint32_t)buf[3]<<24);
    if (inner < 2 || 4 + inner > buf_len) return -1;
    *proto_id    = buf[4];
    *flags       = buf[5];
    *payload     = buf + 6;
    *payload_len = inner - 2;
    return (int)(4 + inner);
}

/* ── Main ── */

int main(int argc, char *argv[]) {
    const char *host = (argc > 1) ? argv[1] : "192.168.68.87";
    int         port = (argc > 2) ? atoi(argv[2]) : 8115;

    static uint8_t sbuf[BUF_SIZE];
    static uint8_t rbuf[BUF_SIZE];
    static uint8_t dbuf[BUF_SIZE];

    printf("\n=== CKB Light Client — Phase 4 Live Handshake ===\n");
    printf("Target: %s:%d\n\n", host, port);

    /* ── 1. TCP ── */
    int fd = tcp_connect(host, port);
    if (fd < 0) return 1;

    /* ── 2. Crypto ── */
    secio_crypto_t crypto;
    crypto_openssl_init(&crypto);

    /* ── 3. SecIO init ── */
    secio_ctx_t sctx;
    memset(&sctx, 0, sizeof(sctx));
    if (secio_init(&sctx, &crypto) < 0) {
        fprintf(stderr, "[secio] init failed\n"); close(fd); return 1;
    }
    printf("[secio] local pubkey: ");
    for (int i = 0; i < 6; i++) printf("%02x", sctx.local_static_pubkey[i]);
    printf("...\n");

    /* ── 4. Send Propose ── */
    int n = secio_build_propose(&sctx, &crypto, sbuf, sizeof(sbuf));
    if (n < 0) { fprintf(stderr, "[secio] build_propose failed\n"); close(fd); return 1; }
    printf("[secio] → Propose (%d bytes)\n", n);
    if (tcp_send_all(fd, sbuf, n) < 0) { close(fd); return 1; }

    /* ── 5. Recv Propose ── */
    uint32_t rlen;
    if (recv_framed(fd, rbuf, sizeof(rbuf), &rlen) < 0) { close(fd); return 1; }
    printf("[secio] ← Propose (%u bytes):\n  ", rlen);
    for (uint32_t i = 0; i < rlen; i++) {
        printf("%02x ", rbuf[i]);
        if ((i+1) % 16 == 0) printf("\n  ");
    }
    printf("\n");
    if (secio_process_propose(&sctx, rbuf, rlen) < 0) {
        fprintf(stderr, "[secio] process_propose failed\n"); close(fd); return 1;
    }
    printf("[secio]   cipher=%s hash=%s\n", sctx.chosen_cipher, sctx.chosen_hash);

    /* ── 6. Send Exchange ── */
    n = secio_build_exchange(&sctx, &crypto, sbuf, sizeof(sbuf));
    if (n < 0) { fprintf(stderr, "[secio] build_exchange failed\n"); close(fd); return 1; }
    printf("[secio] → Exchange (%d bytes)\n", n);
    if (tcp_send_all(fd, sbuf, n) < 0) { close(fd); return 1; }

    /* ── 7. Recv Exchange ── */
    if (recv_framed(fd, rbuf, sizeof(rbuf), &rlen) < 0) { close(fd); return 1; }
    printf("[secio] ← Exchange (%u bytes)\n", rlen);
    if (secio_process_exchange(&sctx, &crypto, rbuf, rlen) < 0) {
        fprintf(stderr, "[secio] process_exchange failed\n"); close(fd); return 1;
    }
    printf("[secio] *** ESTABLISHED *** 🎉 (ordering: local %s remote)\n",
           secio_ordering(&sctx) ? ">" : "<");

    /* GCM nonce starts at zero */
    memset(sctx.local_keys.iv,  0, SECIO_IV_SIZE);
    memset(sctx.remote_keys.iv, 0, SECIO_IV_SIZE);

    printf("[secio] local  key: ");
    for (int i=0;i<8;i++) printf("%02x",sctx.local_keys.key[i]); printf("...\n");
    printf("[secio] remote key: ");
    for (int i=0;i<8;i++) printf("%02x",sctx.remote_keys.key[i]); printf("...\n\n");

    /* ── 8. Nonce verification exchange (Tentacle requires this) ── */
    /* Both sides simultaneously: send remote's nonce, receive local nonce back */
    printf("[secio] → sending remote nonce (verification)\n");
    if (send_encrypted(fd, &sctx, sctx.remote_nonce, SECIO_NONCE_SIZE) < 0) {
        fprintf(stderr, "[secio] failed to send nonce\n"); close(fd); return 1;
    }

    printf("[secio] ← receiving local nonce (verification)\n");
    int nonce_recv = recv_encrypted(fd, &sctx, rbuf, sizeof(rbuf));
    if (nonce_recv < 0 ||
        (uint32_t)nonce_recv != SECIO_NONCE_SIZE ||
        memcmp(rbuf, sctx.local_nonce, SECIO_NONCE_SIZE) != 0) {
        fprintf(stderr, "[secio] nonce verification failed (got %d bytes)\n", nonce_recv);
        close(fd); return 1;
    }
    printf("[secio] nonce verified ✓\n\n");

    /* ── 9. Yamux: open Identify (stream 1) + Ping (stream 3) simultaneously ──
 * CKB's ProtocolTypeCheckerService requires both to open within a short window.
 * We pack all SYNs + ProtocolInfos into a single encrypted send so the node
 * sees them atomically and doesn't RST us for "incomplete open protocols".
 */
    yamux_session_t ysess;
    yamux_session_init(&ysess);

    /* Allocate streams: id=1 (Identify), id=3 (Ping), id=7 (DisconnectMsg) */
    yamux_stream_t *id_stream   = yamux_open_stream(&ysess, 2);
    yamux_stream_t *ping_stream = yamux_open_stream(&ysess, 3);
    yamux_stream_t *disc_stream = yamux_open_stream(&ysess, 4);
    if (!id_stream || !ping_stream || !disc_stream) { fprintf(stderr, "[yamux] stream alloc failed\n"); close(fd); return 1; }
    printf("[yamux] streams: id=%u (identify), id=%u (ping), id=%u (disconnectmsg)\n",
           id_stream->id, ping_stream->id, disc_stream->id);

    /* ── Helper: append a Yamux SYN frame to a buffer ── */
#define APPEND_SYN(buf, off, sid) do { \
    yamux_frame_t _f; yamux_frame_syn(&_f, (sid)); \
    yamux_encode_header(&_f, (buf)+(off)); (off) += YAMUX_HEADER_SIZE; \
} while(0)

    /* ── Helper: append a Tentacle-framed proto msg to a buffer ── */
#define APPEND_PROTO_MSG(buf, off, sid, payload, plen) do { \
    yamux_frame_t _yf; uint8_t _yh[YAMUX_HEADER_SIZE]; \
    yamux_frame_data(&_yf, (sid), 0, 4+(uint32_t)(plen)); \
    yamux_encode_header(&_yf, _yh); \
    memcpy((buf)+(off), _yh, YAMUX_HEADER_SIZE); (off) += YAMUX_HEADER_SIZE; \
    (buf)[(off)++] = ((uint32_t)(plen)>>24)&0xFF; \
    (buf)[(off)++] = ((uint32_t)(plen)>>16)&0xFF; \
    (buf)[(off)++] = ((uint32_t)(plen)>>8)&0xFF;  \
    (buf)[(off)++] = (uint32_t)(plen)&0xFF;        \
    memcpy((buf)+(off), (payload), (plen)); (off) += (plen); \
} while(0)

    /* ── Helper: send Tentacle-framed message on its own (used post-handshake) ── */
#define SEND_PROTO_MSG(sid, payload, plen) do { \
    uint8_t _tmp[2048]; uint32_t _off=0; \
    APPEND_PROTO_MSG(_tmp, _off, (sid), (payload), (plen)); \
    if(send_encrypted(fd,&sctx,_tmp,_off)<0){close(fd);return 1;} \
} while(0)

    /* ── Helper: send a post-select protocol data message (with CKB compress flag byte)
     * CKB uses LengthDelimitedCodecWithCompress on protocol streams.
     * Format: [BE32 = 1+plen][0x00 flag][plen bytes payload]
     * The 0x00 flag = UNCOMPRESS_FLAG (data is raw, not snappy-compressed).
     * Compression only applies when data.len() > 1024; small messages skip it.
     * Without this flag byte, the node drops the first byte of payload → decode failure → RST.
     */
#define APPEND_PROTO_DATA(buf, off, sid, payload, plen) do { \
    yamux_frame_t _yf; uint8_t _yh[YAMUX_HEADER_SIZE]; \
    yamux_frame_data(&_yf, (sid), 0, 4+1+(uint32_t)(plen)); \
    yamux_encode_header(&_yf, _yh); \
    memcpy((buf)+(off), _yh, YAMUX_HEADER_SIZE); (off) += YAMUX_HEADER_SIZE; \
    (buf)[(off)++] = ((uint32_t)(1+(plen))>>24)&0xFF; \
    (buf)[(off)++] = ((uint32_t)(1+(plen))>>16)&0xFF; \
    (buf)[(off)++] = ((uint32_t)(1+(plen))>>8)&0xFF;  \
    (buf)[(off)++] = (uint32_t)(1+(plen))&0xFF;        \
    (buf)[(off)++] = 0x00; /* UNCOMPRESS_FLAG */       \
    memcpy((buf)+(off), (payload), (plen)); (off) += (plen); \
} while(0)

#define SEND_PROTO_DATA(sid, payload, plen) do { \
    uint8_t _tmp[4096]; uint32_t _off=0; \
    APPEND_PROTO_DATA(_tmp, _off, (sid), (payload), (plen)); \
    if(send_encrypted(fd,&sctx,_tmp,_off)<0){close(fd);return 1;} \
} while(0)

    /* ProtocolInfo for /ckb/identify (42 bytes, version "3")
     * Molecule Table { name: String("/ckb/identify"), support_versions: StringVec(["3"]) }
     * Generated by: encode_protocol_info("/ckb/identify", ["3"])
     */
    static const uint8_t proto_identify_mol[] = {
        /* Table header: total=42, off[0]=12(name), off[1]=29(versions) */
        0x2a,0x00,0x00,0x00, 0x0c,0x00,0x00,0x00, 0x1d,0x00,0x00,0x00,
        /* name: FixVec<Byte> len=13, "/ckb/identify" */
        0x0d,0x00,0x00,0x00, 0x2f,0x63,0x6b,0x62,0x2f,0x69,0x64,0x65,0x6e,0x74,0x69,0x66,0x79,
        /* support_versions: DynVec<FixVec<Byte>> total=13, off[0]=8, item="3" */
        0x0d,0x00,0x00,0x00, 0x08,0x00,0x00,0x00,
        0x01,0x00,0x00,0x00, 0x33  /* "3" */
    };

    /* ProtocolInfo for /ckb/ping (38 bytes, version "3")
     * Molecule Table { name: String("/ckb/ping"), support_versions: StringVec(["3"]) }
     */
    static const uint8_t proto_ping_mol[] = {
        /* Table header: total=38, off[0]=12(name), off[1]=25(versions) */
        0x26,0x00,0x00,0x00, 0x0c,0x00,0x00,0x00, 0x19,0x00,0x00,0x00,
        /* name: FixVec<Byte> len=9, "/ckb/ping" */
        0x09,0x00,0x00,0x00, 0x2f,0x63,0x6b,0x62,0x2f,0x70,0x69,0x6e,0x67,
        /* support_versions: DynVec total=13, off[0]=8, item="3" */
        0x0d,0x00,0x00,0x00, 0x08,0x00,0x00,0x00,
        0x01,0x00,0x00,0x00, 0x33  /* "3" */
    };

    /* ProtocolInfo for /ckb/disconnectmsg (47 bytes, version "3") */
    static const uint8_t proto_disc_mol[] = {
        /* Table header: total=47, off[0]=12(name), off[1]=34(versions) */
        0x2f,0x00,0x00,0x00, 0x0c,0x00,0x00,0x00, 0x22,0x00,0x00,0x00,
        /* name: FixVec<Byte> len=18, "/ckb/disconnectmsg" */
        0x12,0x00,0x00,0x00,
        0x2f,0x63,0x6b,0x62,0x2f,0x64,0x69,0x73,0x63,0x6f,0x6e,0x6e,0x65,0x63,0x74,0x6d,0x73,0x67,
        /* support_versions: DynVec total=13, off[0]=8, item="3" */
        0x0d,0x00,0x00,0x00, 0x08,0x00,0x00,0x00,
        0x01,0x00,0x00,0x00, 0x33  /* "3" */
    };

    /* Pack: SYN(1)+PI(identify) + SYN(3)+PI(ping) + SYN(5)+PI(disconnectmsg) — all in ONE send */
    {
        uint8_t burst[1024]; uint32_t boff = 0;
        APPEND_SYN(burst, boff, id_stream->id);
        APPEND_PROTO_MSG(burst, boff, id_stream->id,   proto_identify_mol, sizeof(proto_identify_mol));
        APPEND_SYN(burst, boff, ping_stream->id);
        APPEND_PROTO_MSG(burst, boff, ping_stream->id, proto_ping_mol,     sizeof(proto_ping_mol));
        APPEND_SYN(burst, boff, disc_stream->id);
        APPEND_PROTO_MSG(burst, boff, disc_stream->id, proto_disc_mol,     sizeof(proto_disc_mol));
        printf("[yamux] → burst: SYN(%u)+PI(identify) + SYN(%u)+PI(ping) + SYN(%u)+PI(disconnectmsg) [%u bytes]\n",
               id_stream->id, ping_stream->id, disc_stream->id, boff);
        if (send_encrypted(fd, &sctx, burst, boff) < 0) { close(fd); return 1; }
    }

    /* ── Wait for SYN+ACK on all three streams + protocol echoes ── */
    printf("[proto] waiting for ACKs on identify(%u) ping(%u) disconnectmsg(%u)...\n",
           id_stream->id, ping_stream->id, disc_stream->id);
    int got_identify_ack = 0, got_ping_ack = 0, got_identify_proto = 0, got_ping_proto = 0;
    int got_disc_ack = 0, got_disc_proto = 0;
    for (int attempt = 0; attempt < 20 && !(got_identify_ack && got_ping_ack && got_disc_ack &&
                                             got_identify_proto && got_ping_proto && got_disc_proto); attempt++) {
        int recv_n = recv_encrypted(fd, &sctx, rbuf, sizeof(rbuf));
        if (recv_n < 0) { fprintf(stderr, "[proto] recv failed\n"); close(fd); return 1; }
        printf("[proto] raw frame (%d bytes):", recv_n);
        for (int _di=0; _di<recv_n && _di<80; _di++) printf(" %02x", rbuf[_di]);
        if (recv_n > 80) printf(" ...");
        printf("\n");
        uint32_t offset = 0;
        while ((uint32_t)offset + YAMUX_HEADER_SIZE <= (uint32_t)recv_n) {
            yamux_frame_t rf;
            if (yamux_decode_header(rbuf + offset, &rf) != 0) break;
            offset += YAMUX_HEADER_SIZE;
            printf("[yamux] ← type=%u flags=0x%04x stream=%u len=%u\n",
                   rf.type, rf.flags, rf.stream_id, rf.length);
            if (rf.type == YAMUX_TYPE_DATA && rf.length > 0) {
                printf("[yamux]   data:");
                for (uint32_t _di=0; _di < rf.length && _di < 32; _di++) printf(" %02x", rbuf[offset+_di]);
                printf("\n");
            }
            if (rf.flags & YAMUX_FLAG_RST) {
                fprintf(stderr, "[proto] RST on stream %u!\n", rf.stream_id);
                /* Log but don't bail — continue draining to see full picture */
            }
            if (rf.stream_id == id_stream->id) {
                if (rf.flags & YAMUX_FLAG_ACK) { got_identify_ack = 1; printf("[proto] ✓ identify ACK\n"); }
                if (rf.type == YAMUX_TYPE_DATA && rf.length > 0) {
                    got_identify_proto = 1;
                    printf("[proto] ← identify proto echo (%u bytes)\n", rf.length);
                }
            }
            if (rf.stream_id == ping_stream->id) {
                if (rf.flags & YAMUX_FLAG_ACK) { got_ping_ack = 1; printf("[proto] ✓ ping ACK\n"); }
                if (rf.type == YAMUX_TYPE_DATA && rf.length > 0) {
                    got_ping_proto = 1;
                    printf("[proto] ← ping proto echo (%u bytes)\n", rf.length);
                }
            }
            if (rf.stream_id == disc_stream->id) {
                if (rf.flags & YAMUX_FLAG_ACK) { got_disc_ack = 1; printf("[proto] ✓ disconnectmsg ACK\n"); }
                if (rf.type == YAMUX_TYPE_DATA && rf.length > 0) {
                    got_disc_proto = 1;
                    printf("[proto] ← disconnectmsg proto echo (%u bytes)\n", rf.length);
                }
            }
            offset += rf.length;
        }
    }
    printf("[proto] identify: ack=%d proto=%d  ping: ack=%d proto=%d  disc: ack=%d proto=%d\n",
           got_identify_ack, got_identify_proto, got_ping_ack, got_ping_proto, got_disc_ack, got_disc_proto);
    if (!got_identify_ack) { fprintf(stderr, "[proto] no identify ACK — aborting\n"); close(fd); return 1; }

    /* Send window update for identify stream */
    { yamux_frame_t wu; uint8_t wb[YAMUX_HEADER_SIZE];
      yamux_frame_window_update(&wu, id_stream->id, 0, 256*1024);
      yamux_encode_header(&wu, wb); send_encrypted(fd, &sctx, wb, YAMUX_HEADER_SIZE); }

    /* Now send IdentifyMessage
     * Schema (molecule Table, 3 outer fields):
     *   listen_addrs : BytesVec  (empty dynvec = 4 bytes)
     *   observed_addr: Bytes     (empty fixvec = 4 bytes)
     *   identify     : Bytes     (inner IdentifyMessage — 86 bytes fixvec payload)
     *
     * Inner IdentifyMessage (4 fields):
     *   flag         : Bytes (8 bytes LE uint64) = 0x11 = COMPATIBILITY|LIGHT_CLIENT
     *   name         : Bytes = "ckb"
     *   client_version: Bytes = "0.204.0"
     *   network_id   : Bytes = mainnet genesis hash (32 bytes)
     *
     * CRITICAL: network_id must be the genesis hash or node will RST
     * ("The nodes are not on the same network")
     */
    /* Correct IdentifyMessage (93 bytes):
     * Outer table (IdentifyMessage): 3 fields:
     *   [0] listen_addrs: AddressVec (DynVec<Address>) = empty
     *   [1] observed_addr: Address = /ip4/0.0.0.0
     *   [2] identify: Bytes = inner Identify table
     *
     * Inner Identify table (52 bytes): 3 fields (STRICTLY 3 - from_slice is NOT compatible!):
     *   [0] flag: Uint64 (8 bytes, LE) = 0x2F
     *   [1] name: Bytes = "/ckb/92b197aa" (mainnet genesis prefix)
     *   [2] client_version: Bytes = "0.204.0"
     *
     * CRITICAL: The identify name is consensus.identify_name():
     *   format!("/{}/{}", consensus.id, &genesis_hash[..8])
     *   = "/ckb/92b197aa" for mainnet
     *   NOT "ckb" — that fails the name check and causes a ban!
     *
     * Flags: 0x2F = COMPATIBILITY(1)|DISCOVERY(2)|SYNC(4)|RELAY(8)|LIGHT_CLIENT(16)|BLOCK_FILTER(32)
     * required_flags_filter(SYNC|DISCOVERY|RELAY, 0x2F) = true (COMPATIBILITY bit)
     */
    static const uint8_t identify_msg_mol[] = {
        /* ── Outer Table: total=93, 3 fields ── */
        0x5d,0x00,0x00,0x00,              /* total_size = 93 */
        0x10,0x00,0x00,0x00,              /* offset[0] = 16 (listen_addrs) */
        0x14,0x00,0x00,0x00,              /* offset[1] = 20 (observed_addr) */
        0x25,0x00,0x00,0x00,              /* offset[2] = 37 (identify Bytes field) */
        /* Field 0: listen_addrs = empty AddressVec DynVec (total=4, no items) */
        0x04,0x00,0x00,0x00,
        /* Field 1: observed_addr = Address Table { bytes: /ip4/0.0.0.0 } */
        0x11,0x00,0x00,0x00,              /* total_size = 17 */
        0x08,0x00,0x00,0x00,              /* offset[0] = 8 */
        0x05,0x00,0x00,0x00,              /* Bytes fixvec len=5 */
        0x04,0x00,0x00,0x00,0x00,         /* /ip4/0.0.0.0 */
        /* Field 2: identify = Bytes fixvec(52) wrapping inner Identify table */
        0x34,0x00,0x00,0x00,              /* fixvec length = 52 */
        /* ── Inner Identify Table: total=52, 3 fields ── */
        0x34,0x00,0x00,0x00,              /* total_size = 52 */
        0x10,0x00,0x00,0x00,              /* offset[0] = 16 (flag: Uint64) */
        0x18,0x00,0x00,0x00,              /* offset[1] = 24 (name: Bytes) */
        0x29,0x00,0x00,0x00,              /* offset[2] = 41 (client_version: Bytes) */
        /* flag: Uint64 (8 bytes, LE) = 0x2F */
        0x2f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        /* name: Bytes fixvec(13) = "/ckb/92b197aa" (consensus.identify_name()) */
        0x0d,0x00,0x00,0x00, 0x2f,0x63,0x6b,0x62,0x2f,0x39,0x32,0x62,0x31,0x39,0x37,0x61,0x61,
        /* client_version: Bytes fixvec(7) = "0.204.0" */
        0x07,0x00,0x00,0x00, 0x30,0x2e,0x32,0x30,0x34,0x2e,0x30,
    };
    SEND_PROTO_MSG(id_stream->id, identify_msg_mol, sizeof(identify_msg_mol));
    printf("[identify] → IdentifyMessage (%zu bytes): ", sizeof(identify_msg_mol));
    for (size_t _i=0; _i<sizeof(identify_msg_mol) && _i<32; _i++) printf("%02x ", identify_msg_mol[_i]);
    printf("...\n");

    /* Wait for node's IdentifyMessage — dump everything received */
    printf("[identify] waiting for node's IdentifyMessage...\n");
    int got_identify_msg = 0;
    for (int attempt = 0; attempt < 10 && !got_identify_msg; attempt++) {
        int recv_n = recv_encrypted(fd, &sctx, rbuf, sizeof(rbuf));
        if (recv_n < 0) { fprintf(stderr, "[identify] recv failed\n"); close(fd); return 1; }
        printf("[identify] raw recv (%d bytes):", recv_n);
        for (int _i=0; _i<recv_n && _i<96; _i++) printf(" %02x", rbuf[_i]);
        if (recv_n > 96) printf(" ...");
        printf("\n");
        uint32_t offset = 0;
        while ((uint32_t)offset + YAMUX_HEADER_SIZE <= (uint32_t)recv_n) {
            yamux_frame_t rf;
            if (yamux_decode_header(rbuf + offset, &rf) != 0) break;
            offset += YAMUX_HEADER_SIZE;
            printf("[yamux] ← type=%u flags=0x%04x stream=%u len=%u\n",
                   rf.type, rf.flags, rf.stream_id, rf.length);
            if (rf.type == YAMUX_TYPE_DATA && rf.length > 0) {
                printf("[yamux]   data (%u):", rf.length);
                for (uint32_t _i=0; _i<rf.length && _i<48; _i++) printf(" %02x", rbuf[offset+_i]);
                printf("\n");
            }
            if (rf.stream_id == id_stream->id && (rf.flags & YAMUX_FLAG_RST)) {
                fprintf(stderr, "[identify] RST after sending IdentifyMessage\n");
                /* drain and show any more frames */
                offset += rf.length;
                while ((uint32_t)offset + YAMUX_HEADER_SIZE <= (uint32_t)recv_n) {
                    yamux_frame_t rf2;
                    if (yamux_decode_header(rbuf + offset, &rf2) != 0) break;
                    offset += YAMUX_HEADER_SIZE;
                    printf("[yamux] (drain) ← type=%u flags=0x%04x stream=%u len=%u\n",
                           rf2.type, rf2.flags, rf2.stream_id, rf2.length);
                    offset += rf2.length;
                }
                /* one more read */
                int rx2 = recv_encrypted(fd, &sctx, rbuf, sizeof(rbuf));
                if (rx2 > 0) { printf("[identify] (extra):");
                    for (int _i=0; _i<rx2 && _i<64; _i++) printf(" %02x", rbuf[_i]); printf("\n"); }
                close(fd); return 1;
            }
            if (rf.type == YAMUX_TYPE_DATA && rf.length > 0 && rf.stream_id == id_stream->id) {
                got_identify_msg = 1;
                printf("[identify] ← IdentifyMessage received (%u bytes) ✓\n", rf.length);
            }
            offset += rf.length;
        }
    }
    printf("[identify] %s\n", got_identify_msg ? "Identify complete ✓" : "no IdentifyMessage received");

    /* ─── STREAM 5: /ckb/lightclient ─── */
    yamux_stream_t *lc_stream = yamux_open_stream(&ysess, PROTO_LC);
    if (!lc_stream) { fprintf(stderr, "[yamux] open lc_stream failed\n"); close(fd); return 1; }
    printf("\n[yamux] opening stream id=%u for /ckb/lightclient\n", lc_stream->id);
    { uint8_t lc_syn_buf[1024]; uint32_t lc_off = 0;
      APPEND_SYN(lc_syn_buf, lc_off, lc_stream->id);
      send_encrypted(fd, &sctx, lc_syn_buf, lc_off); }
    printf("[yamux] → SYN stream=%u\n", lc_stream->id);

    /* ProtocolInfo for /ckb/lightclient (45 bytes, version "3")
     * Molecule Table { name: String("/ckb/lightclient"), support_versions: StringVec(["3"]) }
     */
    static const uint8_t proto_lc_mol[] = {
        /* Table header: total=45, off[0]=12(name), off[1]=32(versions) */
        0x2d,0x00,0x00,0x00, 0x0c,0x00,0x00,0x00, 0x20,0x00,0x00,0x00,
        /* name: FixVec<Byte> len=16, "/ckb/lightclient" */
        0x10,0x00,0x00,0x00,
        0x2f,0x63,0x6b,0x62,0x2f,0x6c,0x69,0x67,0x68,0x74,0x63,0x6c,0x69,0x65,0x6e,0x74,
        /* support_versions: DynVec total=13, off[0]=8, item="3" */
        0x0d,0x00,0x00,0x00, 0x08,0x00,0x00,0x00,
        0x01,0x00,0x00,0x00, 0x33  /* version "3" */
    };
    SEND_PROTO_MSG(lc_stream->id, proto_lc_mol, sizeof(proto_lc_mol));
    printf("[proto_select] → ProtocolInfo(/ckb/lightclient) sent\n");

    printf("[proto_select] waiting for LC ACK + ProtocolInfo echo...\n");
    int got_lc_ack = 0;
    int got_lc_proto_echo = 0;
    for (int attempt = 0; attempt < 20 && (!got_lc_ack || !got_lc_proto_echo); attempt++) {
        int recv_n = recv_encrypted(fd, &sctx, rbuf, sizeof(rbuf));
        if (recv_n < 0) break;
        uint32_t offset = 0;
        while ((uint32_t)offset + YAMUX_HEADER_SIZE <= (uint32_t)recv_n) {
            yamux_frame_t rf;
            if (yamux_decode_header(rbuf + offset, &rf) != 0) break;
            offset += YAMUX_HEADER_SIZE;
            printf("[yamux] ← type=%u flags=0x%04x stream=%u len=%u\n",
                   rf.type, rf.flags, rf.stream_id, rf.length);
            if (rf.stream_id == lc_stream->id) {
                if (rf.flags & YAMUX_FLAG_ACK) { got_lc_ack = 1; printf("[lc] ACK ✓\n"); }
                if (rf.flags & YAMUX_FLAG_RST) { fprintf(stderr,"[lc] RST on stream\n"); close(fd); return 1; }
            }
            if (rf.type == YAMUX_TYPE_DATA && rf.length > 0 && rf.stream_id == lc_stream->id) {
                /* This is the ProtocolInfo echo */
                printf("[lc] ProtocolInfo echo (%u bytes): ", rf.length);
                for(uint32_t i=0;i<rf.length&&i<32;i++) printf("%02x ",rbuf[offset+i]);
                printf("\n");
                got_lc_proto_echo = 1;
            } else if (rf.type == YAMUX_TYPE_DATA && rf.length > 0) {
                printf("[proto] data on stream %u: ", rf.stream_id);
                for(uint32_t i=0;i<rf.length&&i<16;i++) printf("%02x ",rbuf[offset+i]);
                printf("\n");
            }
            offset += rf.length;
        }
    }
    if (!got_lc_ack || !got_lc_proto_echo)
        printf("[lc] WARNING: ack=%d proto_echo=%d\n", got_lc_ack, got_lc_proto_echo);
    else
        printf("[lc] stream OPEN ✓ (ACK + echo received)\n\n");

    /* Send window update to lc stream */
    { yamux_frame_t wu; uint8_t wb[YAMUX_HEADER_SIZE];
      yamux_frame_window_update(&wu, lc_stream->id, 0, 256*1024);
      yamux_encode_header(&wu, wb); send_encrypted(fd, &sctx, wb, YAMUX_HEADER_SIZE); }

    /* ── 10. GetLastState (subscribe=true for ongoing updates) ── */
    static uint8_t zeros[32] = {0};
    lc_sync_ctx_t sync;
    lc_sync_init(&sync, zeros, 0, zeros);
    sync.subscribe = 1;  /* request subscription/ongoing updates */
    static uint8_t msg_buf[512];
    int msg_n = lc_sync_build_get_last_state(&sync, msg_buf, sizeof(msg_buf));
    if (msg_n < 0) { fprintf(stderr,"[proto] build failed\n"); close(fd); return 1; }
    printf("[proto] GetLastState (%d bytes): ", msg_n);
    for (int i=0;i<msg_n;i++) printf("%02x ",msg_buf[i]); printf("\n");
    SEND_PROTO_DATA(lc_stream->id, msg_buf, msg_n);
    printf("[proto] → GetLastState sent 🚀\n\n");

    /* ── 11. Wait for SendLastState ── */
    printf("[proto] waiting for SendLastState...\n");
    int got_ack = 0; /* unused, kept for summary */
    for (int attempt = 0; attempt < 30; attempt++) {
        int recv_n = recv_encrypted(fd, &sctx, rbuf, sizeof(rbuf));
        if (recv_n < 0) break;
        uint32_t offset = 0;
        while ((uint32_t)offset + YAMUX_HEADER_SIZE <= (uint32_t)recv_n) {
            yamux_frame_t rf;
            if (yamux_decode_header(rbuf + offset, &rf) != 0) break;
            offset += YAMUX_HEADER_SIZE;
            printf("[proto] ← type=%u flags=0x%04x stream=%u len=%u\n",
                   rf.type, rf.flags, rf.stream_id, rf.length);
            if (rf.stream_id == lc_stream->id && (rf.flags & YAMUX_FLAG_RST)) {
                fprintf(stderr, "[lc] stream RST after GetLastState\n"); goto done;
            }
            if (rf.type == YAMUX_TYPE_WINDOW_UPDATE) {
                yamux_frame_t wu; uint8_t wb[YAMUX_HEADER_SIZE];
                yamux_frame_window_update(&wu, lc_stream->id, 0, 256*1024);
                yamux_encode_header(&wu, wb); send_encrypted(fd, &sctx, wb, YAMUX_HEADER_SIZE);
            }
            if (rf.type != YAMUX_TYPE_DATA || rf.length == 0 || rf.stream_id != lc_stream->id) {
                offset += rf.length; continue;
            }
            const uint8_t *lc_data = rbuf + offset;
            uint32_t lc_len = rf.length;
            offset += lc_len;
            printf("[proto] DATA len=%u raw: ", lc_len);
            for (uint32_t i=0;i<lc_len&&i<20;i++) printf("%02x ",lc_data[i]); printf("\n");
            /* Parse LengthDelimitedCodecWithCompress format:
             * [BE32 = 1+msglen][flag_byte][msglen bytes]
             * flag_byte: 0x00 = uncompressed, 0x80 = snappy compressed */
            if (lc_len < 6) continue;  /* need at least 4+1+1 */
            uint32_t framed_len = ((uint32_t)lc_data[0]<<24)|((uint32_t)lc_data[1]<<16)|
                                  ((uint32_t)lc_data[2]<<8)|(uint32_t)lc_data[3];
            lc_data += 4; lc_len = framed_len;
            uint8_t flag = lc_data[0];
            lc_data += 1; lc_len -= 1;  /* skip flag byte */
            if (flag & 0x80) {
                printf("[proto] WARNING: snappy-compressed data (flag=0x%02x), skipping\n", flag);
                continue;
            }
            /* Now lc_data points to raw LightClientMessage bytes, lc_len = msglen */
            uint8_t mid; const uint8_t *mpay; uint32_t mplen;
            if (lc_msg_unwrap(lc_data, lc_len, &mid, &mpay, &mplen) > 0) {
                printf("[proto] msg_id=0x%02x payload=%u bytes\n", mid, mplen);
                if (mid == MSG_SEND_LAST_STATE) {
                    msg_send_last_state_t sls;
                    int dec_rc = msg_send_last_state_decode(mpay, mplen, &sls);
                    printf("[proto] msg_send_last_state_decode rc=%d\n", dec_rc);
                    if (dec_rc > 0) {
                        printf("\n[proto] *** SendLastState received! ***\n");
                        printf("[proto]   block_number   = %llu\n",
                               (unsigned long long)sls.last_header.header.number);
                        printf("[proto]   compact_target = 0x%08x\n",
                               sls.last_header.header.compact_target);
                        printf("\n=== Phase 4 COMPLETE ✅ ===\n");
                        printf("=== Light client is talking to the CKB network! ===\n\n");
                        close(fd); return 0;
                    }
                }
            }
        }
    }

done:
    printf("\n[info] Partial success:\n");
    printf("[info]   TCP:       OK\n");
    printf("[info]   SecIO:     OK\n");
    printf("[info]   Identify:  %s\n", (got_identify_ack && got_identify_msg) ? "OK" : "sent");
    printf("[info]   Yamux LC:  %s\n", got_lc_ack ? "OK" : "opened");
    printf("[info]   Proto:     GetLastState sent\n");
    close(fd);
    return 0;
}
