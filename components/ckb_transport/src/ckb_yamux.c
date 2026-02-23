/*
 * ckb_yamux.c — Yamux + Tentacle framing implementation
 */

#include "ckb_yamux.h"
#include <string.h>

/* Big-endian helpers */
static inline uint16_t read_u16_be(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static inline uint32_t read_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}
static inline void write_u16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v);
}
static inline void write_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)(v);
}

/* Little-endian helpers (Tentacle frame header uses LE length) */
static inline uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void write_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* ── Yamux header encode/decode ── */

void yamux_encode_header(const yamux_frame_t *f, uint8_t buf[YAMUX_HEADER_SIZE]) {
    buf[0] = f->version;
    buf[1] = f->type;
    write_u16_be(buf + 2, f->flags);
    write_u32_be(buf + 4, f->stream_id);
    write_u32_be(buf + 8, f->length);
}

int yamux_decode_header(const uint8_t buf[YAMUX_HEADER_SIZE], yamux_frame_t *out) {
    if (buf[0] != YAMUX_VERSION) return -1;
    uint8_t type = buf[1];
    if (type > YAMUX_TYPE_GO_AWAY) return -1;

    out->version   = buf[0];
    out->type      = type;
    out->flags     = read_u16_be(buf + 2);
    out->stream_id = read_u32_be(buf + 4);
    out->length    = read_u32_be(buf + 8);
    return 0;
}

/* ── Frame builders ── */

void yamux_frame_syn(yamux_frame_t *f, uint32_t stream_id) {
    f->version   = YAMUX_VERSION;
    f->type      = YAMUX_TYPE_WINDOW_UPDATE;
    f->flags     = YAMUX_FLAG_SYN;
    f->stream_id = stream_id;
    f->length    = YAMUX_INIT_WINDOW;
}

void yamux_frame_syn_ack(yamux_frame_t *f, uint32_t stream_id) {
    f->version   = YAMUX_VERSION;
    f->type      = YAMUX_TYPE_WINDOW_UPDATE;
    f->flags     = YAMUX_FLAG_SYN | YAMUX_FLAG_ACK;
    f->stream_id = stream_id;
    f->length    = YAMUX_INIT_WINDOW;
}

void yamux_frame_data(yamux_frame_t *f, uint32_t stream_id,
                      uint16_t flags, uint32_t data_len) {
    f->version   = YAMUX_VERSION;
    f->type      = YAMUX_TYPE_DATA;
    f->flags     = flags;
    f->stream_id = stream_id;
    f->length    = data_len;
}

void yamux_frame_window_update(yamux_frame_t *f, uint32_t stream_id,
                                uint16_t flags, uint32_t delta) {
    f->version   = YAMUX_VERSION;
    f->type      = YAMUX_TYPE_WINDOW_UPDATE;
    f->flags     = flags;
    f->stream_id = stream_id;
    f->length    = delta;
}

void yamux_frame_ping(yamux_frame_t *f, uint32_t ping_id) {
    f->version   = YAMUX_VERSION;
    f->type      = YAMUX_TYPE_PING;
    f->flags     = YAMUX_FLAG_SYN;
    f->stream_id = 0;
    f->length    = ping_id;
}

void yamux_frame_ping_ack(yamux_frame_t *f, uint32_t ping_id) {
    f->version   = YAMUX_VERSION;
    f->type      = YAMUX_TYPE_PING;
    f->flags     = YAMUX_FLAG_ACK;
    f->stream_id = 0;
    f->length    = ping_id;
}

void yamux_frame_go_away(yamux_frame_t *f, uint32_t reason) {
    f->version   = YAMUX_VERSION;
    f->type      = YAMUX_TYPE_GO_AWAY;
    f->flags     = 0;
    f->stream_id = 0;
    f->length    = reason;
}

/* ── Session state machine ── */

void yamux_session_init(yamux_session_t *s) {
    if (!s) return;
    memset(s, 0, sizeof(*s));
    s->next_stream_id = 1; /* client uses odd IDs */
}

yamux_stream_t *yamux_find_stream(yamux_session_t *s, uint32_t stream_id) {
    if (!s) return NULL;
    int i;
    for (i = 0; i < YAMUX_MAX_STREAMS; i++) {
        if (s->streams[i].state != YAMUX_STREAM_IDLE &&
            s->streams[i].id == stream_id)
            return &s->streams[i];
    }
    return NULL;
}

yamux_stream_t *yamux_open_stream(yamux_session_t *s, uint8_t protocol_id) {
    if (!s || s->going_away) return NULL;
    int i;
    for (i = 0; i < YAMUX_MAX_STREAMS; i++) {
        if (s->streams[i].state == YAMUX_STREAM_IDLE) {
            s->streams[i].id           = s->next_stream_id;
            s->streams[i].state        = YAMUX_STREAM_SYN_SENT;
            s->streams[i].send_window  = YAMUX_INIT_WINDOW;
            s->streams[i].recv_window  = YAMUX_INIT_WINDOW;
            s->streams[i].protocol_id  = protocol_id;
            s->next_stream_id += 2; /* stay odd */
            return &s->streams[i];
        }
    }
    return NULL; /* no free slots */
}

int yamux_process_frame(yamux_session_t *s, const yamux_frame_t *f) {
    if (!s || !f) return -1;

    switch (f->type) {
    case YAMUX_TYPE_DATA: {
        yamux_stream_t *st = yamux_find_stream(s, f->stream_id);
        if (!st) return -1;
        if (st->state != YAMUX_STREAM_OPEN &&
            st->state != YAMUX_STREAM_SYN_RECV) return -1;
        if (f->flags & YAMUX_FLAG_FIN)
            st->state = YAMUX_STREAM_CLOSED;
        return 1; /* caller should read f->length bytes from transport */
    }
    case YAMUX_TYPE_WINDOW_UPDATE: {
        if (f->flags & YAMUX_FLAG_SYN) {
            /* Remote is opening a stream */
            yamux_stream_t *st = yamux_find_stream(s, f->stream_id);
            if (!st) {
                /* Find free slot for incoming stream */
                int i;
                for (i = 0; i < YAMUX_MAX_STREAMS; i++) {
                    if (s->streams[i].state == YAMUX_STREAM_IDLE) {
                        st = &s->streams[i];
                        st->id          = f->stream_id;
                        st->state       = YAMUX_STREAM_SYN_RECV;
                        st->send_window = YAMUX_INIT_WINDOW;
                        st->recv_window = f->length;
                        break;
                    }
                }
            } else {
                /* SYN+ACK: our stream was accepted */
                if (f->flags & YAMUX_FLAG_ACK)
                    st->state = YAMUX_STREAM_OPEN;
                st->send_window += f->length;
            }
        } else if (f->flags & YAMUX_FLAG_ACK) {
            yamux_stream_t *st = yamux_find_stream(s, f->stream_id);
            if (st && st->state == YAMUX_STREAM_SYN_SENT)
                st->state = YAMUX_STREAM_OPEN;
            if (st) st->send_window += f->length;
        } else {
            /* Pure window update */
            yamux_stream_t *st = yamux_find_stream(s, f->stream_id);
            if (st) st->send_window += f->length;
        }
        return 0;
    }
    case YAMUX_TYPE_PING:
        /* Caller must send a ping-ack with same length (ping_id) */
        return 0;
    case YAMUX_TYPE_GO_AWAY:
        s->going_away = 1;
        return -1;
    default:
        return -1;
    }
}

/* ── Tentacle framing ── */

void tentacle_encode_header(const tentacle_frame_t *f, uint8_t buf[TENTACLE_FRAME_HEADER_SIZE]) {
    /* length field = payload_len + 2 (for proto_id + flags bytes) */
    uint32_t wire_len = f->payload_len + 2;
    write_u32_le(buf, wire_len);
    buf[4] = f->protocol_id;
    buf[5] = f->flags;
}

int tentacle_decode_header(const uint8_t buf[TENTACLE_FRAME_HEADER_SIZE], tentacle_frame_t *out) {
    if (!buf || !out) return -1;
    uint32_t wire_len = read_u32_le(buf);
    if (wire_len < 2) return -1;
    out->payload_len  = wire_len - 2;
    out->protocol_id  = buf[4];
    out->flags        = buf[5];
    return 0;
}
