// bitchat_packet.cpp — BitChat binary protocol codec implementation
// toastmanAu/ckb-light-esp
//
// Wire format reference: BinaryProtocol.swift + BitchatMessage.swift
// All multi-byte values are big-endian (network byte order).
//
// HOST_TEST: compiled with g++ -DHOST_TEST (no Arduino SDK)

#include "bitchat_packet.h"

#ifdef HOST_TEST
  #include <stdio.h>
  #include <stdlib.h>
  #include <stdint.h>
  #include <string.h>
#else
  #include <Arduino.h>
#endif

// ─── Internal write helpers (big-endian) ─────────────────────────────────────

static inline bool _write8(uint8_t* buf, size_t* off, size_t cap, uint8_t v) {
    if (*off + 1 > cap) return false;
    buf[(*off)++] = v;
    return true;
}

static inline bool _write16(uint8_t* buf, size_t* off, size_t cap, uint16_t v) {
    if (*off + 2 > cap) return false;
    buf[(*off)++] = (v >> 8) & 0xFF;
    buf[(*off)++] = v & 0xFF;
    return true;
}

static inline bool _write32(uint8_t* buf, size_t* off, size_t cap, uint32_t v) {
    if (*off + 4 > cap) return false;
    buf[(*off)++] = (v >> 24) & 0xFF;
    buf[(*off)++] = (v >> 16) & 0xFF;
    buf[(*off)++] = (v >>  8) & 0xFF;
    buf[(*off)++] = v & 0xFF;
    return true;
}

static inline bool _write64(uint8_t* buf, size_t* off, size_t cap, uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) {
        if (!_write8(buf, off, cap, (uint8_t)((v >> s) & 0xFF))) return false;
    }
    return true;
}

static inline bool _writeBytes(uint8_t* buf, size_t* off, size_t cap,
                                const uint8_t* src, size_t n) {
    if (*off + n > cap) return false;
    memcpy(buf + *off, src, n);
    *off += n;
    return true;
}

// ─── Internal read helpers ────────────────────────────────────────────────────

static inline bool _read8(const uint8_t* buf, size_t* off, size_t len, uint8_t* v) {
    if (*off + 1 > len) return false;
    *v = buf[(*off)++];
    return true;
}

static inline bool _read16(const uint8_t* buf, size_t* off, size_t len, uint16_t* v) {
    if (*off + 2 > len) return false;
    *v = ((uint16_t)buf[*off] << 8) | buf[*off + 1];
    *off += 2;
    return true;
}

static inline bool _read64(const uint8_t* buf, size_t* off, size_t len, uint64_t* v) {
    if (*off + 8 > len) return false;
    *v = 0;
    for (int i = 0; i < 8; i++)
        *v = (*v << 8) | buf[(*off)++];
    return true;
}

static inline bool _readBytes(const uint8_t* buf, size_t* off, size_t len,
                               uint8_t* dst, size_t n) {
    if (*off + n > len) return false;
    memcpy(dst, buf + *off, n);
    *off += n;
    return true;
}

// Read length-prefixed string: 1-byte len + UTF-8 bytes → null-terminated dst
static bool _readStr8(const uint8_t* buf, size_t* off, size_t len,
                      char* dst, size_t dst_size) {
    if (*off >= len) return false;
    uint8_t slen = buf[(*off)++];
    if (*off + slen > len) return false;
    size_t copy = (slen < dst_size - 1) ? slen : dst_size - 1;
    memcpy(dst, buf + *off, copy);
    dst[copy] = '\0';
    *off += slen;
    return true;
}

// Write length-prefixed string: 1-byte len + UTF-8 bytes
static bool _writeStr8(uint8_t* buf, size_t* off, size_t cap, const char* src) {
    size_t slen = strlen(src);
    if (slen > 255) slen = 255;
    if (!_write8(buf, off, cap, (uint8_t)slen)) return false;
    return _writeBytes(buf, off, cap, (const uint8_t*)src, slen);
}

// ─── bc_packet_encode ─────────────────────────────────────────────────────────

size_t bc_packet_encode(const BitchatPacket* pkt, uint8_t* buf, size_t buf_size, bool padding) {
    if (!pkt || !buf || buf_size < 32) return 0;
    if (pkt->version != BC_VERSION_V1 && pkt->version != BC_VERSION_V2) return 0;

    size_t off = 0;

    // Flags
    uint8_t flags = 0;
    if (pkt->has_recipient)  flags |= BC_FLAG_HAS_RECIPIENT;
    if (pkt->has_signature)  flags |= BC_FLAG_HAS_SIGNATURE;
    // We don't implement compression on ESP32 (no zlib) — flag stays 0
    if (pkt->is_rsr)         flags |= BC_FLAG_IS_RSR;
    // HAS_ROUTE not yet implemented

    uint16_t payload_len = pkt->payload ? pkt->payload_len : 0;

    // Header
    if (!_write8(buf, &off, buf_size, pkt->version))       return 0;
    if (!_write8(buf, &off, buf_size, pkt->type))          return 0;
    if (!_write8(buf, &off, buf_size, pkt->ttl))           return 0;
    if (!_write64(buf, &off, buf_size, pkt->timestamp_ms)) return 0;
    if (!_write8(buf, &off, buf_size, flags))              return 0;

    if (pkt->version == BC_VERSION_V2) {
        if (!_write32(buf, &off, buf_size, (uint32_t)payload_len)) return 0;
    } else {
        if (!_write16(buf, &off, buf_size, payload_len))           return 0;
    }

    // Sender ID (always 8 bytes)
    if (!_writeBytes(buf, &off, buf_size, pkt->sender_id, BC_SENDER_ID_SIZE)) return 0;

    // Recipient ID (8 bytes, optional)
    if (pkt->has_recipient) {
        if (!_writeBytes(buf, &off, buf_size, pkt->recipient_id, BC_RECIPIENT_ID_SIZE)) return 0;
    }

    // Payload
    if (payload_len > 0 && pkt->payload) {
        if (!_writeBytes(buf, &off, buf_size, pkt->payload, payload_len)) return 0;
    }

    // Signature (64 bytes, optional)
    if (pkt->has_signature) {
        if (!_writeBytes(buf, &off, buf_size, pkt->signature, BC_SIGNATURE_SIZE)) return 0;
    }

    // Padding
    if (padding) {
        size_t padded = bc_pad(buf, off, buf_size);
        if (padded == 0) return 0;  // buf too small
        return padded;
    }

    return off;
}

// ─── bc_packet_decode ─────────────────────────────────────────────────────────

bool bc_packet_decode(const uint8_t* buf, size_t len, BitchatPacket* pkt) {
    if (!buf || !pkt || len < (size_t)(BC_HEADER_SIZE_V1 + BC_SENDER_ID_SIZE)) return false;

    // Try to remove padding first (check if last byte looks like a pad byte)
    size_t raw_len = bc_unpad(buf, len);

    const uint8_t* data = buf;
    size_t data_len = raw_len;

    size_t off = 0;

    if (!_read8(data, &off, data_len, &pkt->version)) return false;
    if (pkt->version != BC_VERSION_V1 && pkt->version != BC_VERSION_V2) return false;

    size_t header_size = (pkt->version == BC_VERSION_V2) ? BC_HEADER_SIZE_V2 : BC_HEADER_SIZE_V1;
    if (data_len < header_size + BC_SENDER_ID_SIZE) return false;

    if (!_read8(data, &off, data_len, &pkt->type))         return false;
    if (!_read8(data, &off, data_len, &pkt->ttl))          return false;
    if (!_read64(data, &off, data_len, &pkt->timestamp_ms)) return false;
    if (!_read8(data, &off, data_len, &pkt->flags))        return false;

    pkt->has_recipient = (pkt->flags & BC_FLAG_HAS_RECIPIENT) != 0;
    pkt->has_signature = (pkt->flags & BC_FLAG_HAS_SIGNATURE) != 0;
    pkt->is_rsr        = (pkt->flags & BC_FLAG_IS_RSR) != 0;

    uint16_t payload_len = 0;
    if (pkt->version == BC_VERSION_V2) {
        uint8_t b0, b1, b2, b3;
        if (!_read8(data, &off, data_len, &b0)) return false;
        if (!_read8(data, &off, data_len, &b1)) return false;
        if (!_read8(data, &off, data_len, &b2)) return false;
        if (!_read8(data, &off, data_len, &b3)) return false;
        uint32_t pl32 = ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) |
                        ((uint32_t)b2 << 8) | b3;
        if (pl32 > BC_MAX_PAYLOAD) return false;
        payload_len = (uint16_t)pl32;
    } else {
        if (!_read16(data, &off, data_len, &payload_len)) return false;
    }

    // Sender ID
    if (!_readBytes(data, &off, data_len, pkt->sender_id, BC_SENDER_ID_SIZE)) return false;

    // Recipient ID
    if (pkt->has_recipient) {
        if (!_readBytes(data, &off, data_len, pkt->recipient_id, BC_RECIPIENT_ID_SIZE)) return false;
        pkt->is_broadcast = bc_is_broadcast(pkt->recipient_id);
    } else {
        memset(pkt->recipient_id, 0, BC_RECIPIENT_ID_SIZE);
        pkt->is_broadcast = false;
    }

    // Payload (zero-copy: points into buf)
    if (payload_len > 0) {
        if (off + payload_len > data_len) return false;
        pkt->payload = (uint8_t*)(data + off);
        pkt->payload_len = payload_len;
        off += payload_len;
    } else {
        pkt->payload = NULL;
        pkt->payload_len = 0;
    }

    // Signature
    if (pkt->has_signature) {
        if (!_readBytes(data, &off, data_len, pkt->signature, BC_SIGNATURE_SIZE)) return false;
    } else {
        memset(pkt->signature, 0, BC_SIGNATURE_SIZE);
    }

    return true;
}

// ─── bc_message_encode ────────────────────────────────────────────────────────

size_t bc_message_encode(const BitchatMessage* msg, uint8_t* buf, size_t buf_size) {
    if (!msg || !buf || buf_size < 16) return 0;
    size_t off = 0;

    // Flags
    uint8_t flags = 0;
    if (msg->is_relay)         flags |= 0x01;
    if (msg->is_private)       flags |= 0x02;
    if (msg->has_orig_sender)  flags |= 0x04;
    if (msg->has_recip_nick)   flags |= 0x08;
    // bit 4: hasSenderPeerID — not in our struct, skip
    // bit 5: hasMentions — not in our struct, skip

    if (!_write8(buf, &off, buf_size, flags)) return 0;

    // Timestamp (8 bytes BE)
    if (!_write64(buf, &off, buf_size, msg->timestamp_ms)) return 0;

    // ID (1-byte len + data)
    if (!_writeStr8(buf, &off, buf_size, msg->id)) return 0;

    // Sender (1-byte len + data)
    if (!_writeStr8(buf, &off, buf_size, msg->sender)) return 0;

    // Content (2-byte len + data)
    {
        size_t clen = strlen(msg->content);
        if (clen > 65535) clen = 65535;
        if (!_write16(buf, &off, buf_size, (uint16_t)clen)) return 0;
        if (!_writeBytes(buf, &off, buf_size, (const uint8_t*)msg->content, clen)) return 0;
    }

    // Optional: orig_sender
    if (msg->has_orig_sender) {
        if (!_writeStr8(buf, &off, buf_size, msg->orig_sender)) return 0;
    }

    // Optional: recip_nick
    if (msg->has_recip_nick) {
        if (!_writeStr8(buf, &off, buf_size, msg->recip_nick)) return 0;
    }

    return off;
}

// ─── bc_message_decode ────────────────────────────────────────────────────────

bool bc_message_decode(const uint8_t* payload, size_t len, BitchatMessage* msg) {
    if (!payload || !msg || len < 13) return false;
    memset(msg, 0, sizeof(*msg));

    size_t off = 0;

    uint8_t flags;
    if (!_read8(payload, &off, len, &flags)) return false;
    msg->flags         = flags;
    msg->is_relay      = (flags & 0x01) != 0;
    msg->is_private    = (flags & 0x02) != 0;
    msg->has_orig_sender = (flags & 0x04) != 0;
    msg->has_recip_nick  = (flags & 0x08) != 0;

    if (!_read64(payload, &off, len, &msg->timestamp_ms)) return false;

    // ID
    if (!_readStr8(payload, &off, len, msg->id, sizeof(msg->id))) return false;

    // Sender
    if (!_readStr8(payload, &off, len, msg->sender, sizeof(msg->sender))) return false;

    // Content (2-byte len)
    if (off + 2 > len) return false;
    uint16_t clen;
    if (!_read16(payload, &off, len, &clen)) return false;
    if (off + clen > len) return false;
    size_t copy = (clen < sizeof(msg->content) - 1) ? clen : sizeof(msg->content) - 1;
    memcpy(msg->content, payload + off, copy);
    msg->content[copy] = '\0';
    off += clen;

    // Optional orig_sender
    if (msg->has_orig_sender && off < len) {
        _readStr8(payload, &off, len, msg->orig_sender, sizeof(msg->orig_sender));
    }

    // Optional recip_nick
    if (msg->has_recip_nick && off < len) {
        _readStr8(payload, &off, len, msg->recip_nick, sizeof(msg->recip_nick));
    }

    return true;
}

// ─── bc_announce_encode ───────────────────────────────────────────────────────

size_t bc_announce_encode(const BitchatAnnounce* ann, uint8_t* buf, size_t buf_size) {
    if (!ann || !buf || buf_size < 2) return 0;
    size_t off = 0;

    if (!_writeStr8(buf, &off, buf_size, ann->nickname)) return 0;

    if (ann->has_fingerprint) {
        if (!_writeBytes(buf, &off, buf_size, ann->pub_key_fingerprint, 32)) return 0;
    }

    return off;
}

// ─── bc_announce_decode ───────────────────────────────────────────────────────

bool bc_announce_decode(const uint8_t* payload, size_t len, BitchatAnnounce* ann) {
    if (!payload || !ann || len < 1) return false;
    memset(ann, 0, sizeof(*ann));

    size_t off = 0;
    if (!_readStr8(payload, &off, len, ann->nickname, sizeof(ann->nickname))) return false;

    if (off + 32 <= len) {
        memcpy(ann->pub_key_fingerprint, payload + off, 32);
        ann->has_fingerprint = true;
        off += 32;
    }

    return true;
}
