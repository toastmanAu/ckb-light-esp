// bitchat_packet.h — BitChat binary protocol codec for ESP32
// toastmanAu/ckb-light-esp
//
// Implements the BitChat wire format as specified in:
//   https://github.com/permissionlesstech/bitchat/blob/main/WHITEPAPER.md
//   https://github.com/permissionlesstech/bitchat/blob/main/bitchat/Protocols/BinaryProtocol.swift
//
// Protocol: Noise_XX_25519_ChaChaPoly_SHA256 over BLE mesh, transport-agnostic
// Wire format is identical for BLE and LoRa — only MTU/fragmentation differs
//
// Scope: packet encode/decode + BitchatMessage encode/decode.
// Noise crypto handshake: bitchat_noise.h (separate, future).
// BLE transport: bitchat_ble.h (separate, future).
// LoRa bridge: bitchat_lora.h (separate, future).
//
// Platform: Arduino/PlatformIO (ESP32, ESP32-S3, ESP32-C3)
//           HOST_TEST: g++ on Linux (no Arduino SDK)
//
// Released under the same Unlicense as BitChat itself.

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

// ─── Wire format constants ────────────────────────────────────────────────────

#define BC_VERSION_V1          0x01
#define BC_VERSION_V2          0x02  // V2 adds 4-byte payload length + source routing

#define BC_HEADER_SIZE_V1      14    // version(1)+type(1)+ttl(1)+timestamp(8)+flags(1)+payloadLen(2)
#define BC_HEADER_SIZE_V2      16
#define BC_SENDER_ID_SIZE      8     // 8-byte truncated peer ID
#define BC_RECIPIENT_ID_SIZE   8
#define BC_SIGNATURE_SIZE      64    // Ed25519 signature

// Max sizes
#define BC_MAX_PAYLOAD         65535
#define BC_MAX_NICKNAME        32
#define BC_MAX_CONTENT         1024
#define BC_MAX_MSG_ID          64    // UUID string (36) + margin
#define BC_MAX_PEERS           16

// TTL defaults
#define BC_TTL_DEFAULT         7
#define BC_TTL_ANNOUNCE        3
#define BC_TTL_DIRECT          1

// ─── Message types (from BitchatProtocol.swift MessageType enum) ─────────────

#define BC_TYPE_ANNOUNCE        0x01  // "I'm here" with nickname
#define BC_TYPE_MESSAGE         0x02  // Public broadcast chat message
#define BC_TYPE_LEAVE           0x03  // "I'm leaving"
#define BC_TYPE_NOISE_HANDSHAKE 0x10  // Noise XX handshake (init or response)
#define BC_TYPE_NOISE_ENCRYPTED 0x11  // Encrypted payload (private msg/receipts)
#define BC_TYPE_FRAGMENT        0x20  // Fragment (large message chunked)
#define BC_TYPE_REQUEST_SYNC    0x21  // GCS filter-based sync (local only)
#define BC_TYPE_FILE_TRANSFER   0x22  // Binary file/audio/image

// ─── Noise payload types (first byte after decryption) ───────────────────────

#define BC_NOISE_PRIVATE_MSG    0x01
#define BC_NOISE_READ_RECEIPT   0x02
#define BC_NOISE_DELIVERED      0x03
#define BC_NOISE_VERIFY_CHAL    0x10
#define BC_NOISE_VERIFY_RESP    0x11

// ─── Flags byte bitmask ──────────────────────────────────────────────────────

#define BC_FLAG_HAS_RECIPIENT   0x01
#define BC_FLAG_HAS_SIGNATURE   0x02
#define BC_FLAG_IS_COMPRESSED   0x04
#define BC_FLAG_HAS_ROUTE       0x08  // V2 only
#define BC_FLAG_IS_RSR          0x10

// ─── BitchatPacket (decoded representation) ───────────────────────────────────

typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint8_t  ttl;
    uint64_t timestamp_ms;
    uint8_t  flags;
    uint8_t  sender_id[BC_SENDER_ID_SIZE];
    bool     has_recipient;
    uint8_t  recipient_id[BC_RECIPIENT_ID_SIZE];
    bool     is_broadcast;
    uint8_t* payload;           // points into caller's buffer (zero-copy)
    uint16_t payload_len;
    bool     has_signature;
    uint8_t  signature[BC_SIGNATURE_SIZE];
    bool     is_rsr;
} BitchatPacket;

// ─── BitchatMessage (application layer, BC_TYPE_MESSAGE payload) ──────────────

typedef struct {
    uint8_t  flags;
    uint64_t timestamp_ms;
    char     id[BC_MAX_MSG_ID];
    char     sender[BC_MAX_NICKNAME+1];
    char     content[BC_MAX_CONTENT+1];
    bool     has_orig_sender;
    char     orig_sender[BC_MAX_NICKNAME+1];
    bool     has_recip_nick;
    char     recip_nick[BC_MAX_NICKNAME+1];
    bool     is_relay;
    bool     is_private;
} BitchatMessage;

// ─── Announce payload (BC_TYPE_ANNOUNCE) ──────────────────────────────────────

typedef struct {
    char     nickname[BC_MAX_NICKNAME+1];
    uint8_t  pub_key_fingerprint[32];   // SHA-256 of Noise static pub key
    bool     has_fingerprint;
} BitchatAnnounce;

// ─── Fragment packet (BC_TYPE_FRAGMENT) ───────────────────────────────────────

typedef struct {
    char     msg_id[BC_MAX_MSG_ID];
    uint8_t  fragment_index;
    uint8_t  total_fragments;
    uint8_t* data;              // points into caller's buffer
    uint16_t data_len;
} BitchatFragment;

// ─── Encode/Decode API ───────────────────────────────────────────────────────

// Encode a BitchatPacket into buf. Returns bytes written, or 0 on error.
// padding=true pads to BitChat block sizes (256/512/1024/2048).
// Set padding=false for LoRa (MTU-constrained).
size_t bc_packet_encode(const BitchatPacket* pkt, uint8_t* buf, size_t buf_size, bool padding);

// Decode buf into pkt. pkt->payload points into buf (zero-copy).
// buf must remain valid for the lifetime of pkt.
// Returns true on success.
bool bc_packet_decode(const uint8_t* buf, size_t len, BitchatPacket* pkt);

// Encode/decode application-layer messages
size_t bc_message_encode(const BitchatMessage* msg, uint8_t* buf, size_t buf_size);
bool   bc_message_decode(const uint8_t* payload, size_t len, BitchatMessage* msg);

size_t bc_announce_encode(const BitchatAnnounce* ann, uint8_t* buf, size_t buf_size);
bool   bc_announce_decode(const uint8_t* payload, size_t len, BitchatAnnounce* ann);

// ─── Helper utilities ────────────────────────────────────────────────────────

static inline void bc_set_broadcast(uint8_t* id) {
    memset(id, 0xFF, BC_RECIPIENT_ID_SIZE);
}

static inline bool bc_is_broadcast(const uint8_t* id) {
    for (int i = 0; i < BC_RECIPIENT_ID_SIZE; i++)
        if (id[i] != 0xFF) return false;
    return true;
}

// BitChat PKCS#7-style padding block sizes
static const uint16_t BC_PAD_SIZES[] = { 256, 512, 1024, 2048 };

static inline uint16_t bc_optimal_pad_size(size_t n) {
    for (int i = 0; i < 4; i++)
        if ((size_t)BC_PAD_SIZES[i] > n) return BC_PAD_SIZES[i];
    return (uint16_t)((n + 255) & ~(size_t)255);
}

static inline size_t bc_pad(uint8_t* buf, size_t data_len, size_t buf_size) {
    uint16_t target = bc_optimal_pad_size(data_len);
    if (buf_size < target) return 0;
    // pad_count can be up to 256 (e.g. 256 bytes data → 512 block)
    // Use uint16_t to avoid uint8_t overflow
    uint16_t pad_count = (uint16_t)(target - data_len);
    // PKCS#7: pad_byte is the number of pad bytes, clamped to uint8_t
    // If pad_count > 255 (only when exactly 256 bytes needed), use 0x01 sentinel
    uint8_t pad_byte = (pad_count > 255) ? 0x01 : (uint8_t)pad_count;
    if (pad_byte == 0) { pad_byte = 1; pad_count = 1; target++; }  // safety
    memset(buf + data_len, pad_byte, pad_count);
    return target;
}

static inline size_t bc_unpad(const uint8_t* buf, size_t len) {
    if (len == 0) return 0;
    // Only attempt unpadding on recognised BitChat block sizes
    bool is_block = (len == 256 || len == 512 || len == 1024 || len == 2048);
    if (!is_block) return len;
    uint8_t pad_byte = buf[len - 1];
    // pad_byte must be 1..255 and less than len
    if (pad_byte == 0 || (size_t)pad_byte >= len) return len;
    for (size_t i = len - pad_byte; i < len; i++)
        if (buf[i] != pad_byte) return len;
    return len - pad_byte;
}
