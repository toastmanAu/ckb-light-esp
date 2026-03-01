// bitchat_mesh.h — BitChat mesh relay engine for ESP32
// toastmanAu/ckb-light-esp
//
// Implements the gossip/flood routing layer from the BitChat whitepaper §7:
//   - Bloom filter deduplication (seen packet IDs)
//   - TTL-based relay (decrement, forward to all peers except source)
//   - Directed vs broadcast packet handling
//   - Store-and-forward queue for offline peers
//
// Transport-agnostic: plugs into BLE, LoRa, or WiFi transports.
// The BLE relay case is packet-transparent (relay without decrypting Noise).
//
// Usage (Arduino loop):
//   BitchatMesh mesh;
//   mesh.begin("Kernel");
//   mesh.onMessage([](const BitchatMessage* msg) { ... });
//   mesh.onRawRelay([](const uint8_t* buf, size_t len, uint8_t src_port) { ... });
//   // On receive from any transport:
//   mesh.receive(raw_bytes, len, source_peer_index);
//   // Periodic:
//   mesh.tick();

#pragma once

#include "bitchat_packet.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ─── Bloom filter for deduplication ──────────────────────────────────────────
// Simple fixed-size Bloom filter using 3 independent hash functions.
// Tracks recently seen packet timestamps (not full IDs — saves memory).
// False positive rate ~0.1% with 512 bits + 1024 entries.

#define BC_BLOOM_BITS   512      // 64 bytes
#define BC_BLOOM_HASHES 3

typedef struct {
    uint8_t  bits[BC_BLOOM_BITS / 8];
    uint16_t count;
    uint32_t last_clear_ms;
    uint32_t clear_interval_ms;  // reset filter after this many ms (default 5min)
} BitchatBloom;

void     bc_bloom_init(BitchatBloom* bf, uint32_t clear_interval_ms);
void     bc_bloom_add(BitchatBloom* bf, uint64_t ts_ms, const uint8_t* sender, uint8_t type);
bool     bc_bloom_check(BitchatBloom* bf, uint64_t ts_ms, const uint8_t* sender, uint8_t type);
void     bc_bloom_tick(BitchatBloom* bf, uint32_t now_ms);

// ─── Peer table ───────────────────────────────────────────────────────────────

#define BC_PEER_NONE    0xFF

typedef struct {
    uint8_t  id[BC_SENDER_ID_SIZE];
    char     nickname[BC_MAX_NICKNAME+1];
    uint8_t  fingerprint[32];
    bool     has_fingerprint;
    uint32_t last_seen_ms;
    bool     active;
} BitchatPeer;

// ─── Callbacks (set before begin()) ──────────────────────────────────────────

// Called when a public BC_TYPE_MESSAGE is decoded and delivered to this node
typedef void (*bc_msg_cb)(const BitchatMessage* msg, const uint8_t* sender_id, void* ctx);

// Called when a peer announces or leaves
typedef void (*bc_peer_cb)(const BitchatPeer* peer, bool joined, void* ctx);

// Called when a raw packet needs forwarding to a transport
// src_peer: index into peer table of who sent it to us (-1 = local origin)
// buf: fully encoded BitchatPacket ready to transmit
typedef void (*bc_relay_cb)(const uint8_t* buf, size_t len, int src_peer, void* ctx);

// Called for encrypted (Noise) packets destined for us — caller handles decrypt
typedef void (*bc_noise_cb)(uint8_t noise_type, const uint8_t* payload, uint16_t len,
                             const uint8_t* sender_id, void* ctx);

// ─── BitchatMesh ─────────────────────────────────────────────────────────────

typedef struct {
    // Identity
    uint8_t  local_id[BC_SENDER_ID_SIZE];
    char     nickname[BC_MAX_NICKNAME+1];

    // Peer table
    BitchatPeer peers[BC_MAX_PEERS];
    uint8_t     peer_count;

    // Deduplication
    BitchatBloom bloom;

    // Callbacks
    bc_msg_cb   on_message;
    bc_peer_cb  on_peer;
    bc_relay_cb on_relay;
    bc_noise_cb on_noise;
    void*       cb_ctx;

    // Stats
    uint32_t rx_count;
    uint32_t relay_count;
    uint32_t drop_count;
    uint32_t own_count;
} BitchatMesh;

// ─── API ─────────────────────────────────────────────────────────────────────

// Initialise mesh. nickname up to BC_MAX_NICKNAME chars.
// local_id: 8-byte node ID (pass NULL to auto-generate from chip ID).
void bc_mesh_init(BitchatMesh* mesh, const char* nickname, const uint8_t* local_id);

// Set callbacks before processing any packets.
void bc_mesh_set_callbacks(BitchatMesh* mesh,
                           bc_msg_cb msg_cb, bc_peer_cb peer_cb,
                           bc_relay_cb relay_cb, bc_noise_cb noise_cb,
                           void* ctx);

// Process a received raw packet (from any transport).
// src_peer: index into peer table (or -1 if unknown).
// now_ms: current millis().
void bc_mesh_receive(BitchatMesh* mesh, const uint8_t* buf, size_t len,
                     int src_peer, uint32_t now_ms);

// Send a broadcast public message. Fills sender_id, timestamp, TTL, encodes.
// Calls on_relay with the encoded packet.
// Returns true if packet was built and queued.
bool bc_mesh_send_message(BitchatMesh* mesh, const char* content, uint32_t now_ms);

// Send an announce packet (call once after begin, and after nickname changes).
bool bc_mesh_send_announce(BitchatMesh* mesh, const uint8_t* noise_pub_key,
                           uint32_t now_ms);

// Send a leave packet (call before shutdown).
bool bc_mesh_send_leave(BitchatMesh* mesh, uint32_t now_ms);

// Periodic maintenance: age out peers, reset bloom filter.
void bc_mesh_tick(BitchatMesh* mesh, uint32_t now_ms);

// Find a peer by ID. Returns NULL if not found.
BitchatPeer* bc_mesh_find_peer(BitchatMesh* mesh, const uint8_t* id);

// ─── Encode helpers for common outbound packets ───────────────────────────────

// Build a complete encoded BC_TYPE_MESSAGE packet into buf.
// Returns encoded size, or 0 on error. padding=false for LoRa.
size_t bc_build_message_packet(
    const uint8_t* sender_id,
    const char* sender_nick,
    const char* content,
    uint64_t    timestamp_ms,
    uint8_t     ttl,
    uint8_t*    buf,
    size_t      buf_size,
    bool        padding
);

// Build a BC_TYPE_ANNOUNCE packet.
size_t bc_build_announce_packet(
    const uint8_t* sender_id,
    const char*    nickname,
    const uint8_t* noise_pub_key,  // NULL if no fingerprint
    uint64_t       timestamp_ms,
    uint8_t*       buf,
    size_t         buf_size
);

// Build a BC_TYPE_LEAVE packet.
size_t bc_build_leave_packet(
    const uint8_t* sender_id,
    uint64_t       timestamp_ms,
    uint8_t*       buf,
    size_t         buf_size
);
