/*
 * ckb_protocol.h — RFC 0044 CKB Light Client Protocol messages
 *
 * All messages are Molecule-encoded and exchanged over a Yamux stream
 * (protocol_id = 100) on top of SecIO-encrypted TCP.
 *
 * Message union item IDs:
 *   0  GetLastState          client → server
 *   1  SendLastState         server → client
 *   2  GetLastStateProof     client → server
 *   3  SendLastStateProof    server → client
 *   4  GetBlocksProof        client → server
 *   5  SendBlocksProof       server → client
 *   6  GetTransactionsProof  client → server
 *   7  SendTransactionsProof server → client
 *
 * Reference: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0044-ckb-light-client/0044-ckb-light-client.md
 */

#ifndef CKB_PROTOCOL_H
#define CKB_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "ckb_types.h"
#include "ckb_mmr.h"
#include "ckb_molecule.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Message IDs ── */
#define MSG_GET_LAST_STATE            0
#define MSG_SEND_LAST_STATE           1
#define MSG_GET_LAST_STATE_PROOF      2
#define MSG_SEND_LAST_STATE_PROOF     3
#define MSG_GET_BLOCKS_PROOF          4
#define MSG_SEND_BLOCKS_PROOF         5
#define MSG_GET_TRANSACTIONS_PROOF    6
#define MSG_SEND_TRANSACTIONS_PROOF   7

/* Memory limits (ESP32-P4 constraint) */
#define MAX_SAMPLED_BLOCKS   64
#define MAX_BLOCK_HASHES     32
#define MAX_PROOF_HEADERS    64

/*
 * Protocol-layer VerifiableHeader (RFC 0044).
 *
 * This extends ckb_verifiable_header_t from ckb_mmr.h by storing a full
 * HeaderDigest (not just a hash) for the parent chain root, as required
 * by the wire format. We keep extension inline (not pointer) for ESP32
 * stack safety.
 */
typedef struct {
    ckb_header_t        header;
    ckb_hash_t          uncles_hash;
    uint8_t             extension[96];   /* inline; extension_len=0 → absent */
    uint32_t            extension_len;
    ckb_header_digest_t parent_chain_root; /* full HeaderDigest, not just hash */
} lc_verifiable_header_t;

/* ── HeaderDigest encode/decode (120-byte fixed struct, LE) ── */
#define LC_HEADER_DIGEST_SIZE  CKB_HEADER_DIGEST_SIZE  /* 120 */

int lc_header_digest_encode(const ckb_header_digest_t *d, uint8_t buf[LC_HEADER_DIGEST_SIZE]);
int lc_header_digest_decode(const uint8_t buf[LC_HEADER_DIGEST_SIZE], ckb_header_digest_t *out);

/* ── VerifiableHeader encode/decode ── */
int lc_verifiable_header_encode(const lc_verifiable_header_t *vh,
                                 uint8_t *buf, uint32_t buf_size);
int lc_verifiable_header_decode(const uint8_t *buf, uint32_t buf_size,
                                 lc_verifiable_header_t *out);

/* ── Message structs ── */

typedef struct { uint8_t subscribe; }               msg_get_last_state_t;
typedef struct { lc_verifiable_header_t last_header; } msg_send_last_state_t;

typedef struct {
    uint8_t  last_hash[32];
    uint8_t  start_hash[32];
    uint64_t start_number;
    uint64_t last_n_blocks;
    uint8_t  difficulty_boundary[32];
    uint8_t  difficulties[MAX_SAMPLED_BLOCKS][32];
    uint32_t difficulties_count;
} msg_get_last_state_proof_t;

typedef struct {
    lc_verifiable_header_t last_header;
    ckb_header_digest_t    proof[MAX_PROOF_HEADERS];
    uint32_t               proof_count;
    lc_verifiable_header_t headers[MAX_SAMPLED_BLOCKS];
    uint32_t               headers_count;
} msg_send_last_state_proof_t;

typedef struct {
    uint8_t  last_hash[32];
    uint8_t  block_hashes[MAX_BLOCK_HASHES][32];
    uint32_t block_hashes_count;
} msg_get_blocks_proof_t;

/* ── Message encode/decode ── */
int msg_get_last_state_encode(const msg_get_last_state_t *m, uint8_t *buf, uint32_t sz);
int msg_get_last_state_decode(const uint8_t *buf, uint32_t sz, msg_get_last_state_t *out);

int msg_send_last_state_encode(const msg_send_last_state_t *m, uint8_t *buf, uint32_t sz);
int msg_send_last_state_decode(const uint8_t *buf, uint32_t sz, msg_send_last_state_t *out);

int msg_get_last_state_proof_encode(const msg_get_last_state_proof_t *m, uint8_t *buf, uint32_t sz);
int msg_get_last_state_proof_decode(const uint8_t *buf, uint32_t sz, msg_get_last_state_proof_t *out);

int msg_send_last_state_proof_encode(const msg_send_last_state_proof_t *m, uint8_t *buf, uint32_t sz);
int msg_send_last_state_proof_decode(const uint8_t *buf, uint32_t sz, msg_send_last_state_proof_t *out);

int msg_get_blocks_proof_encode(const msg_get_blocks_proof_t *m, uint8_t *buf, uint32_t sz);
int msg_get_blocks_proof_decode(const uint8_t *buf, uint32_t sz, msg_get_blocks_proof_t *out);

/* ── Union envelope ── */
int lc_msg_wrap(uint8_t item_id, const uint8_t *payload, uint32_t payload_len,
                uint8_t *buf, uint32_t buf_size);
int lc_msg_unwrap(const uint8_t *buf, uint32_t buf_size,
                  uint8_t *item_id_out,
                  const uint8_t **payload_out, uint32_t *payload_len_out);

/* ── FlyClient sync state machine ── */

typedef enum {
    LC_SYNC_IDLE = 0,
    LC_SYNC_WAIT_LAST_STATE,
    LC_SYNC_WAIT_LAST_STATE_PROOF,
    LC_SYNC_VERIFYING,
    LC_SYNC_SYNCED,
    LC_SYNC_ERROR,
} lc_sync_state_t;

typedef struct {
    lc_sync_state_t      state;
    uint8_t              tip_hash[32];
    uint64_t             tip_number;
    uint8_t              tip_total_difficulty[32];
    uint8_t              start_hash[32];
    uint64_t             start_number;
    lc_verifiable_header_t server_tip;
    uint8_t              server_tip_valid;
    uint8_t              sampled_difficulties[MAX_SAMPLED_BLOCKS][32];
    uint32_t             sampled_count;
    uint64_t             last_n_blocks;
    uint8_t              subscribe;
} lc_sync_ctx_t;

void lc_sync_init(lc_sync_ctx_t *ctx,
                  const uint8_t start_hash[32],
                  uint64_t start_number,
                  const uint8_t start_total_difficulty[32]);

int lc_sync_build_get_last_state(lc_sync_ctx_t *ctx, uint8_t *buf, uint32_t sz);
int lc_sync_process_last_state(lc_sync_ctx_t *ctx, const uint8_t *payload, uint32_t len);
int lc_sync_build_get_last_state_proof(lc_sync_ctx_t *ctx, uint8_t *buf, uint32_t sz);
int lc_sync_process_last_state_proof(lc_sync_ctx_t *ctx, const uint8_t *payload, uint32_t len);

int lc_flyclient_sample(lc_sync_ctx_t *ctx,
                         const uint8_t start_diff[32],
                         const uint8_t end_diff[32],
                         uint64_t chain_length,
                         uint32_t lambda);

#ifdef __cplusplus
}
#endif

#endif /* CKB_PROTOCOL_H */
