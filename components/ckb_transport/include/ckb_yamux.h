/*
 * ckb_yamux.h — Yamux stream multiplexer for CKB/Tentacle
 *
 * Yamux sits on top of the SecIO encrypted channel and provides
 * multiple logical streams over a single TCP connection.
 * Each CKB protocol (identify, ping, light-client) runs on its own stream.
 *
 * Frame format (12 bytes, all big-endian):
 *   [1] version   = 0
 *   [1] type      = Data(0), WindowUpdate(1), Ping(2), GoAway(3)
 *   [2] flags     = SYN(1), ACK(2), FIN(4), RST(8)
 *   [4] stream_id (0 = session-level)
 *   [4] length    (data length for Data frames; delta for WindowUpdate; ping_id for Ping)
 *
 * Initial window size: 256KB per stream.
 */

#ifndef CKB_YAMUX_H
#define CKB_YAMUX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define YAMUX_VERSION          0
#define YAMUX_HEADER_SIZE      12
#define YAMUX_INIT_WINDOW      (256 * 1024)
#define YAMUX_MAX_FRAME_SIZE   (16 * 1024 * 1024)

/* ── Frame types ── */
#define YAMUX_TYPE_DATA          0x00
#define YAMUX_TYPE_WINDOW_UPDATE 0x01
#define YAMUX_TYPE_PING          0x02
#define YAMUX_TYPE_GO_AWAY       0x03

/* ── Flags ── */
#define YAMUX_FLAG_SYN  0x0001
#define YAMUX_FLAG_ACK  0x0002
#define YAMUX_FLAG_FIN  0x0004
#define YAMUX_FLAG_RST  0x0008

/* ── GoAway codes ── */
#define YAMUX_GOAWAY_NORMAL    0x00000000
#define YAMUX_GOAWAY_PROTO_ERR 0x00000001
#define YAMUX_GOAWAY_INT_ERR   0x00000002

/* ── Frame struct ── */
typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint32_t stream_id;
    uint32_t length;
} yamux_frame_t;

/* ── Encode/decode frame header ── */

/**
 * Encode a yamux frame header into a 12-byte buffer (big-endian).
 */
void yamux_encode_header(const yamux_frame_t *f, uint8_t buf[YAMUX_HEADER_SIZE]);

/**
 * Decode 12 bytes into a yamux_frame_t.
 * Returns 0 on success, -1 if version mismatch or invalid type.
 */
int yamux_decode_header(const uint8_t buf[YAMUX_HEADER_SIZE], yamux_frame_t *out);

/* ── Frame builders ── */

/** Build a SYN frame to open a new stream */
void yamux_frame_syn(yamux_frame_t *f, uint32_t stream_id);

/** Build a SYN+ACK frame to accept a stream */
void yamux_frame_syn_ack(yamux_frame_t *f, uint32_t stream_id);

/** Build a data frame */
void yamux_frame_data(yamux_frame_t *f, uint32_t stream_id,
                      uint16_t flags, uint32_t data_len);

/** Build a window update frame */
void yamux_frame_window_update(yamux_frame_t *f, uint32_t stream_id,
                                uint16_t flags, uint32_t delta);

/** Build a ping frame (outbound) */
void yamux_frame_ping(yamux_frame_t *f, uint32_t ping_id);

/** Build a ping response frame */
void yamux_frame_ping_ack(yamux_frame_t *f, uint32_t ping_id);

/** Build a GoAway frame */
void yamux_frame_go_away(yamux_frame_t *f, uint32_t reason);

/* ── Stream state machine ── */

#define YAMUX_MAX_STREAMS  8  /* lightweight: only need a handful for CKB protocols */

typedef enum {
    YAMUX_STREAM_IDLE = 0,
    YAMUX_STREAM_SYN_SENT,
    YAMUX_STREAM_SYN_RECV,
    YAMUX_STREAM_OPEN,
    YAMUX_STREAM_FIN_SENT,
    YAMUX_STREAM_CLOSED,
} yamux_stream_state_t;

typedef struct {
    uint32_t             id;
    yamux_stream_state_t state;
    uint32_t             send_window;
    uint32_t             recv_window;
    uint8_t              protocol_id; /* CKB protocol this stream carries */
} yamux_stream_t;

typedef struct {
    yamux_stream_t streams[YAMUX_MAX_STREAMS];
    uint32_t       next_stream_id; /* odd=client, even=server; we're client so start at 1 */
    uint8_t        going_away;
} yamux_session_t;

/**
 * Initialise a yamux session as the client side.
 */
void yamux_session_init(yamux_session_t *s);

/**
 * Find a stream by ID. Returns NULL if not found.
 */
yamux_stream_t *yamux_find_stream(yamux_session_t *s, uint32_t stream_id);

/**
 * Allocate and return a new stream slot, or NULL if full.
 * Assigns next odd stream_id and moves to SYN_SENT state.
 */
yamux_stream_t *yamux_open_stream(yamux_session_t *s, uint8_t protocol_id);

/**
 * Process an incoming frame and update session state.
 * @return 0 OK, -1 protocol error (send GoAway), 1 stream has data ready
 */
int yamux_process_frame(yamux_session_t *s, const yamux_frame_t *f);

/* ── Tentacle framing ──
 *
 * Above Yamux, Tentacle adds per-protocol framing:
 *   [4-byte LE length][protocol_id u8][flags u8][payload...]
 * The length includes the protocol_id and flags bytes.
 * With optional LZ4 compression (flag bit 0x01).
 */
#define TENTACLE_FRAME_HEADER_SIZE  6  /* 4-byte len + 1-byte proto_id + 1-byte flags */
#define TENTACLE_FLAG_COMPRESSED    0x01

typedef struct {
    uint8_t  protocol_id;
    uint8_t  flags;
    uint32_t payload_len;
    /* payload follows immediately after header */
} tentacle_frame_t;

/**
 * Encode a Tentacle protocol frame header (6 bytes).
 * payload_len = length of payload (not including header).
 */
void tentacle_encode_header(const tentacle_frame_t *f, uint8_t buf[TENTACLE_FRAME_HEADER_SIZE]);

/**
 * Decode a Tentacle frame header.
 * Returns 0 OK, -1 error.
 */
int tentacle_decode_header(const uint8_t buf[TENTACLE_FRAME_HEADER_SIZE], tentacle_frame_t *out);

/* CKB protocol IDs (as used in tentacle) */
#define CKB_PROTO_IDENTIFY      0
#define CKB_PROTO_PING          1
#define CKB_PROTO_DISCOVERY     2
#define CKB_PROTO_SYNC          3  /* full node only */
#define CKB_PROTO_RELAY         4  /* full node only */
#define CKB_PROTO_LIGHT_CLIENT  100 /* RFC 0044 */

#ifdef __cplusplus
}
#endif

#endif /* CKB_YAMUX_H */
