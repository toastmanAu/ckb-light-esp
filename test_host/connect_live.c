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

    /* ── 9. Yamux SYN + protocol negotiation ── */
    yamux_session_t ysess;
    yamux_session_init(&ysess);

    yamux_stream_t *stream = yamux_open_stream(&ysess, PROTO_LC);
    if (!stream) { fprintf(stderr, "[yamux] open_stream failed\n"); close(fd); return 1; }
    printf("[yamux] opening stream id=%u\n", stream->id);

    /* Build SYN frame */
    yamux_frame_t yf;
    yamux_frame_syn(&yf, stream->id);
    uint8_t yframe[YAMUX_HEADER_SIZE];
    yamux_encode_header(&yf, yframe);

    if (send_encrypted(fd, &sctx, yframe, YAMUX_HEADER_SIZE) < 0) { close(fd); return 1; }
    printf("[yamux] → SYN sent\n");

    /* ── Wait for node's SYN+ACK first ── */
    printf("[yamux] waiting for SYN+ACK...\n");
    int got_ack = 0;
    for (int attempt = 0; attempt < 8 && !got_ack; attempt++) {
        int recv_n = recv_encrypted(fd, &sctx, rbuf, sizeof(rbuf));
        if (recv_n < 0) { fprintf(stderr, "[yamux] recv failed\n"); close(fd); return 1; }
        printf("[yamux] ← %d bytes: ", recv_n);
        for (int i = 0; i < recv_n && i < 24; i++) printf("%02x ", rbuf[i]);
        printf("\n");

        uint32_t offset = 0;
        while ((uint32_t)offset + YAMUX_HEADER_SIZE <= (uint32_t)recv_n) {
            yamux_frame_t rf;
            if (yamux_decode_header(rbuf + offset, &rf) != 0) break;
            offset += YAMUX_HEADER_SIZE;
            printf("[yamux]   type=%u flags=0x%04x stream=%u len=%u\n",
                   rf.type, rf.flags, rf.stream_id, rf.length);
            if (rf.flags & YAMUX_FLAG_ACK) got_ack = 1;
            offset += rf.length;
        }
    }
    if (!got_ack) printf("[yamux] no ACK — proceeding anyway\n");
    else printf("[yamux] stream OPEN ✓\n\n");

    /* Send Yamux WINDOW_UPDATE to signal we can receive 256KB */
    {
        yamux_frame_t wuf;
        uint8_t wuframe[YAMUX_HEADER_SIZE];
        yamux_frame_window_update(&wuf, stream->id, 0, 256 * 1024);
        yamux_encode_header(&wuf, wuframe);
        send_encrypted(fd, &sctx, wuframe, YAMUX_HEADER_SIZE);
        printf("[yamux] → window update sent (256KB)\n");
    }

    /* ── Protocol negotiation on the new stream ──
     * Tentacle sends a Molecule-encoded ProtocolInfo after stream opens:
     *   Table { name: "/ckb/lightclient", support_versions: ["1"] }
     * Wrapped in a Yamux DATA frame, payload length-prefixed (4-byte BE).
     */
    static const uint8_t proto_info_mol[] = {
        0x2d,0x00,0x00,0x00, 0x0c,0x00,0x00,0x00, 0x20,0x00,0x00,0x00,
        0x10,0x00,0x00,0x00,
        0x2f,0x63,0x6b,0x62,0x2f,0x6c,0x69,0x67,0x68,0x74,0x63,0x6c,0x69,0x65,0x6e,0x74,
        0x0d,0x00,0x00,0x00, 0x08,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, 0x31
    };
    uint32_t pi_len = sizeof(proto_info_mol);

    yamux_frame_data(&yf, stream->id, 0, 4 + pi_len);
    yamux_encode_header(&yf, yframe);
    uint8_t proto_frame[YAMUX_HEADER_SIZE + 4 + sizeof(proto_info_mol)];
    memcpy(proto_frame, yframe, YAMUX_HEADER_SIZE);
    proto_frame[YAMUX_HEADER_SIZE + 0] = (pi_len >> 24) & 0xFF;
    proto_frame[YAMUX_HEADER_SIZE + 1] = (pi_len >> 16) & 0xFF;
    proto_frame[YAMUX_HEADER_SIZE + 2] = (pi_len >>  8) & 0xFF;
    proto_frame[YAMUX_HEADER_SIZE + 3] =  pi_len        & 0xFF;
    memcpy(proto_frame + YAMUX_HEADER_SIZE + 4, proto_info_mol, pi_len);

    if (send_encrypted(fd, &sctx, proto_frame, sizeof(proto_frame)) < 0) { close(fd); return 1; }
    printf("[proto_select] → sent ProtocolInfo(/ckb/lightclient, [\"1\"])\n");

    /* ── Wait for peer's ProtocolInfo response ── */
    printf("[proto_select] waiting for peer's protocol response...\n");
    for (int attempt = 0; attempt < 5; attempt++) {
        int recv_n = recv_encrypted(fd, &sctx, rbuf, sizeof(rbuf));
        if (recv_n < 0) { fprintf(stderr, "[proto_select] recv failed\n"); close(fd); return 1; }
        printf("[proto_select] ← %d bytes: ", recv_n);
        for (int i = 0; i < recv_n && i < 32; i++) printf("%02x ", rbuf[i]);
        printf("\n");
        /* If we get any DATA frame with payload, protocol negotiation succeeded */
        uint32_t offset = 0;
        while ((uint32_t)offset + YAMUX_HEADER_SIZE <= (uint32_t)recv_n) {
            yamux_frame_t rf;
            if (yamux_decode_header(rbuf + offset, &rf) != 0) break;
            offset += YAMUX_HEADER_SIZE;
            printf("[yamux]   type=%u flags=0x%04x stream=%u len=%u\n",
                   rf.type, rf.flags, rf.stream_id, rf.length);
            if (rf.type == YAMUX_TYPE_DATA && rf.length > 0) {
                printf("[proto_select] ← protocol response payload (%u bytes)\n", rf.length);
                /* Print payload */
                for (uint32_t i = 0; i < rf.length && i < 32; i++)
                    printf("%02x ", rbuf[offset + i]);
                printf("\n");
            }
            offset += rf.length;
        }
        if (recv_n > 0) break; /* got something */
    }

    /* ── 10. Build GetLastState ── */
    static uint8_t zeros[32] = {0};
    lc_sync_ctx_t sync;
    lc_sync_init(&sync, zeros, 0, zeros);

    static uint8_t msg_buf[512];
    int msg_n = lc_sync_build_get_last_state(&sync, msg_buf, sizeof(msg_buf));
    if (msg_n < 0) { fprintf(stderr, "[proto] build_get_last_state failed\n"); close(fd); return 1; }
    printf("[proto] GetLastState built (%d bytes): ", msg_n);
    for (int i = 0; i < msg_n && i < 8; i++) printf("%02x ", msg_buf[i]);
    printf("\n");

    /* Wrap in Yamux data frame — Tentacle uses 4-byte BE length-prefix inside Yamux data */
    yamux_frame_data(&yf, stream->id, 0, 4 + (uint32_t)msg_n);
    yamux_encode_header(&yf, yframe);

    uint32_t doff = 0;
    memcpy(dbuf, yframe, YAMUX_HEADER_SIZE);
    doff += YAMUX_HEADER_SIZE;
    /* 4-byte BE length prefix */
    dbuf[doff++] = ((uint32_t)msg_n >> 24) & 0xFF;
    dbuf[doff++] = ((uint32_t)msg_n >> 16) & 0xFF;
    dbuf[doff++] = ((uint32_t)msg_n >>  8) & 0xFF;
    dbuf[doff++] =  (uint32_t)msg_n        & 0xFF;
    memcpy(dbuf + doff, msg_buf, msg_n);
    doff += msg_n;

    if (send_encrypted(fd, &sctx, dbuf, doff) < 0) { close(fd); return 1; }
    printf("[proto] → GetLastState sent 🚀\n\n");

    /* ── 11. Wait for SendLastState ── */
    printf("[proto] waiting for SendLastState response...\n");
    for (int attempt = 0; attempt < 30; attempt++) {
        int recv_n = recv_encrypted(fd, &sctx, rbuf, sizeof(rbuf));
        if (recv_n < 0) break;

        uint32_t offset = 0;
        while ((uint32_t)offset + YAMUX_HEADER_SIZE <= (uint32_t)recv_n) {
            yamux_frame_t rf;
            if (yamux_decode_header(rbuf + offset, &rf) != 0) break;
            offset += YAMUX_HEADER_SIZE;

            printf("[proto] ← Yamux type=%u flags=0x%04x stream=%u len=%u\n",
                   rf.type, rf.flags, rf.stream_id, rf.length);

            if (rf.type != YAMUX_TYPE_DATA || rf.length == 0) {
                /* Window update or ping — send our own window update in reply */
                if (rf.type == YAMUX_TYPE_WINDOW_UPDATE) {
                    yamux_frame_t wu;
                    uint8_t wuf[YAMUX_HEADER_SIZE];
                    yamux_frame_window_update(&wu, stream->id, 0, 256 * 1024);
                    yamux_encode_header(&wu, wuf);
                    send_encrypted(fd, &sctx, wuf, YAMUX_HEADER_SIZE);
                    printf("[proto]   → sent window update\n");
                }
                offset += rf.length;
                continue;
            }

            const uint8_t *lc_data = rbuf + offset;
            uint32_t lc_len = rf.length;
            offset += lc_len;

            printf("[proto]   Yamux DATA stream=%u len=%u raw: ", rf.stream_id, lc_len);
            for (uint32_t i = 0; i < lc_len && i < 16; i++) printf("%02x ", lc_data[i]);
            printf("\n");

            /* Strip 4-byte BE length prefix (Tentacle framing inside Yamux) */
            if (lc_len < 4) continue;
            uint32_t inner_len = ((uint32_t)lc_data[0] << 24) | ((uint32_t)lc_data[1] << 16) |
                                 ((uint32_t)lc_data[2] << 8)  |  (uint32_t)lc_data[3];
            lc_data += 4; lc_len = inner_len;

            /* Unwrap light client message */
            uint8_t msg_id;
            const uint8_t *msg_payload;
            uint32_t msg_payload_len;
            if (lc_msg_unwrap(lc_data, lc_len, &msg_id, &msg_payload, &msg_payload_len) == 0) {
                printf("[proto]   msg_id=0x%02x payload=%u bytes\n", msg_id, msg_payload_len);

                if (msg_id == MSG_SEND_LAST_STATE) {
                    msg_send_last_state_t sls;
                    if (msg_send_last_state_decode(msg_payload, msg_payload_len, &sls) == 0) {
                        printf("\n[proto] *** SendLastState received! ***\n");
                        printf("[proto]   block_number    = %llu\n",
                               (unsigned long long)sls.last_header.header.number);
                        printf("[proto]   compact_target  = 0x%08x\n",
                               sls.last_header.header.compact_target);
                        printf("\n=== Phase 4 COMPLETE ✅ ===\n");
                        printf("=== Light client is talking to the CKB network! ===\n\n");
                        close(fd);
                        return 0;
                    }
                }
            }
        }
    }

    printf("\n[info] Partial success:\n");
    printf("[info]   TCP:    OK\n");
    printf("[info]   SecIO:  %s\n", sctx.state == SECIO_STATE_ESTABLISHED ? "OK" : "FAILED");
    printf("[info]   Yamux:  %s\n", got_ack ? "OK" : "SYN sent");
    printf("[info]   Proto:  GetLastState sent (no response yet)\n");
    printf("[info] Check node logs or try again — node may need time to respond.\n");

    close(fd);
    return 0;
}
