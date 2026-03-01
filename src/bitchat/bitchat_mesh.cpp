// bitchat_mesh.cpp — BitChat mesh relay engine implementation
// toastmanAu/ckb-light-esp

#include "bitchat_mesh.h"

#ifdef HOST_TEST
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <stdint.h>
  #include <time.h>
  #ifndef millis
    // Monotonic ms for host tests
    static uint32_t _host_ms() {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    }
    #define millis() _host_ms()
  #endif
#else
  #include <Arduino.h>
  #include <esp_system.h>   // esp_efuse_mac_get_default
#endif

// ─── Bloom filter implementation ─────────────────────────────────────────────
// Key = murmurhash3-inspired mix of (ts_ms XOR sender_bytes XOR type)
// Three independent hash functions via different seeds.

static uint32_t _bhash(uint64_t ts, const uint8_t* sender, uint8_t type, uint32_t seed) {
    uint32_t h = seed ^ (uint32_t)(ts & 0xFFFFFFFF) ^ (uint32_t)(ts >> 32) ^ type;
    for (int i = 0; i < BC_SENDER_ID_SIZE; i++) {
        h ^= (uint32_t)sender[i] << ((i & 3) * 8);
        h = (h << 13) | (h >> 19);
        h *= 0xC2B2AE35U;
    }
    h ^= h >> 16;
    h *= 0x85EBCA77U;
    h ^= h >> 13;
    return h % BC_BLOOM_BITS;
}

void bc_bloom_init(BitchatBloom* bf, uint32_t clear_interval_ms) {
    memset(bf, 0, sizeof(*bf));
    bf->clear_interval_ms = clear_interval_ms ? clear_interval_ms : 300000; // 5min default
}

static void _bloom_set(BitchatBloom* bf, uint32_t bit) {
    bf->bits[bit / 8] |= (1 << (bit % 8));
}

static bool _bloom_get(const BitchatBloom* bf, uint32_t bit) {
    return (bf->bits[bit / 8] & (1 << (bit % 8))) != 0;
}

void bc_bloom_add(BitchatBloom* bf, uint64_t ts_ms, const uint8_t* sender, uint8_t type) {
    _bloom_set(bf, _bhash(ts_ms, sender, type, 0xDEADBEEF));
    _bloom_set(bf, _bhash(ts_ms, sender, type, 0xCAFEBABE));
    _bloom_set(bf, _bhash(ts_ms, sender, type, 0xABCD1234));
    bf->count++;
}

bool bc_bloom_check(BitchatBloom* bf, uint64_t ts_ms, const uint8_t* sender, uint8_t type) {
    return _bloom_get(bf, _bhash(ts_ms, sender, type, 0xDEADBEEF)) &&
           _bloom_get(bf, _bhash(ts_ms, sender, type, 0xCAFEBABE)) &&
           _bloom_get(bf, _bhash(ts_ms, sender, type, 0xABCD1234));
}

void bc_bloom_tick(BitchatBloom* bf, uint32_t now_ms) {
    if (now_ms - bf->last_clear_ms >= bf->clear_interval_ms) {
        memset(bf->bits, 0, sizeof(bf->bits));
        bf->count = 0;
        bf->last_clear_ms = now_ms;
    }
}

// ─── Local ID generation ──────────────────────────────────────────────────────

static void _gen_local_id(uint8_t* id) {
#ifdef HOST_TEST
    // Deterministic test ID from pid + timestamp
    uint32_t seed = (uint32_t)(time(NULL) ^ (uint32_t)(size_t)id);
    for (int i = 0; i < BC_SENDER_ID_SIZE; i++) {
        seed = seed * 1664525 + 1013904223;
        id[i] = (uint8_t)(seed >> 24);
    }
#else
    // Use bottom 8 bytes of ESP32 MAC + efuse
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    memcpy(id, mac, 6);
    id[6] = (uint8_t)(ESP.getEfuseMac() >> 8);
    id[7] = (uint8_t)(ESP.getEfuseMac());
#endif
}

// ─── bc_mesh_init ─────────────────────────────────────────────────────────────

void bc_mesh_init(BitchatMesh* mesh, const char* nickname, const uint8_t* local_id) {
    memset(mesh, 0, sizeof(*mesh));

    if (local_id) {
        memcpy(mesh->local_id, local_id, BC_SENDER_ID_SIZE);
    } else {
        _gen_local_id(mesh->local_id);
    }

    strncpy(mesh->nickname, nickname, BC_MAX_NICKNAME);
    mesh->nickname[BC_MAX_NICKNAME] = '\0';

    bc_bloom_init(&mesh->bloom, 300000); // 5 minute window
}

void bc_mesh_set_callbacks(BitchatMesh* mesh,
                           bc_msg_cb msg_cb, bc_peer_cb peer_cb,
                           bc_relay_cb relay_cb, bc_noise_cb noise_cb,
                           void* ctx) {
    mesh->on_message = msg_cb;
    mesh->on_peer    = peer_cb;
    mesh->on_relay   = relay_cb;
    mesh->on_noise   = noise_cb;
    mesh->cb_ctx     = ctx;
}

// ─── Peer management ──────────────────────────────────────────────────────────

BitchatPeer* bc_mesh_find_peer(BitchatMesh* mesh, const uint8_t* id) {
    for (int i = 0; i < BC_MAX_PEERS; i++) {
        if (mesh->peers[i].active &&
            memcmp(mesh->peers[i].id, id, BC_SENDER_ID_SIZE) == 0) {
            return &mesh->peers[i];
        }
    }
    return NULL;
}

static BitchatPeer* _find_or_add_peer(BitchatMesh* mesh, const uint8_t* id) {
    // Check existing
    BitchatPeer* existing = bc_mesh_find_peer(mesh, id);
    if (existing) return existing;

    // Find empty slot
    for (int i = 0; i < BC_MAX_PEERS; i++) {
        if (!mesh->peers[i].active) {
            memset(&mesh->peers[i], 0, sizeof(BitchatPeer));
            memcpy(mesh->peers[i].id, id, BC_SENDER_ID_SIZE);
            mesh->peers[i].active = true;
            mesh->peer_count++;
            return &mesh->peers[i];
        }
    }

    // Table full — evict oldest
    uint32_t oldest_ms = 0xFFFFFFFF;
    int oldest_idx = 0;
    for (int i = 0; i < BC_MAX_PEERS; i++) {
        if (mesh->peers[i].last_seen_ms < oldest_ms) {
            oldest_ms = mesh->peers[i].last_seen_ms;
            oldest_idx = i;
        }
    }
    memset(&mesh->peers[oldest_idx], 0, sizeof(BitchatPeer));
    memcpy(mesh->peers[oldest_idx].id, id, BC_SENDER_ID_SIZE);
    mesh->peers[oldest_idx].active = true;
    return &mesh->peers[oldest_idx];
}

// ─── bc_mesh_receive ──────────────────────────────────────────────────────────
//
// Core relay logic (BitChat whitepaper §7.2):
//   1. Decode packet
//   2. Check bloom filter — discard if seen
//   3. Add to bloom filter
//   4. If from us: discard (our own echo)
//   5. If for us OR broadcast: process (dispatch to callback)
//   6. Decrement TTL. If TTL > 0: relay to all transports except source

void bc_mesh_receive(BitchatMesh* mesh, const uint8_t* buf, size_t len,
                     int src_peer, uint32_t now_ms) {
    if (!buf || len < 2) return;
    mesh->rx_count++;

    BitchatPacket pkt;
    if (!bc_packet_decode(buf, len, &pkt)) {
        mesh->drop_count++;
        return;
    }

    // Dedup check
    if (bc_bloom_check(&mesh->bloom, pkt.timestamp_ms, pkt.sender_id, pkt.type)) {
        mesh->drop_count++;
        return;
    }
    bc_bloom_add(&mesh->bloom, pkt.timestamp_ms, pkt.sender_id, pkt.type);

    // Update peer table
    BitchatPeer* peer = _find_or_add_peer(mesh, pkt.sender_id);
    peer->last_seen_ms = now_ms;

    // Is this packet from us? Discard (echo suppression)
    if (memcmp(pkt.sender_id, mesh->local_id, BC_SENDER_ID_SIZE) == 0) {
        mesh->drop_count++;
        return;
    }

    // Is this packet addressed to us or broadcast?
    bool for_us = false;
    if (!pkt.has_recipient) {
        // No recipient field — broadcast
        for_us = true;
    } else if (pkt.is_broadcast) {
        for_us = true;
    } else if (memcmp(pkt.recipient_id, mesh->local_id, BC_SENDER_ID_SIZE) == 0) {
        for_us = true;
    }

    // Dispatch application packets destined for us
    if (for_us) {
        switch (pkt.type) {

            case BC_TYPE_MESSAGE: {
                if (mesh->on_message && pkt.payload && pkt.payload_len > 0) {
                    BitchatMessage msg;
                    if (bc_message_decode(pkt.payload, pkt.payload_len, &msg)) {
                        mesh->own_count++;
                        mesh->on_message(&msg, pkt.sender_id, mesh->cb_ctx);
                    }
                }
                break;
            }

            case BC_TYPE_ANNOUNCE: {
                if (pkt.payload && pkt.payload_len > 0) {
                    BitchatAnnounce ann;
                    if (bc_announce_decode(pkt.payload, pkt.payload_len, &ann)) {
                        // Update peer name + fingerprint
                        strncpy(peer->nickname, ann.nickname, BC_MAX_NICKNAME);
                        peer->nickname[BC_MAX_NICKNAME] = '\0';
                        if (ann.has_fingerprint) {
                            memcpy(peer->fingerprint, ann.pub_key_fingerprint, 32);
                            peer->has_fingerprint = true;
                        }
                        if (mesh->on_peer) mesh->on_peer(peer, true, mesh->cb_ctx);
                    }
                }
                break;
            }

            case BC_TYPE_LEAVE: {
                peer->active = false;
                mesh->peer_count = (mesh->peer_count > 0) ? mesh->peer_count - 1 : 0;
                if (mesh->on_peer) mesh->on_peer(peer, false, mesh->cb_ctx);
                break;
            }

            case BC_TYPE_NOISE_HANDSHAKE:
            case BC_TYPE_NOISE_ENCRYPTED: {
                // Pass raw payload to Noise handler — we never decrypt relay nodes' sessions
                if (mesh->on_noise && pkt.payload && pkt.payload_len > 0) {
                    mesh->on_noise(pkt.type, pkt.payload, pkt.payload_len,
                                   pkt.sender_id, mesh->cb_ctx);
                }
                break;
            }

            default:
                break;
        }
    }

    // Relay: decrement TTL and forward (whitepaper §7.3)
    // We relay even packets addressed to us — mesh needs coverage.
    // Private directed packets (not broadcast, not for us): relay opaquely.
    if (pkt.ttl > 0 && mesh->on_relay) {
        // Rebuild with decremented TTL
        uint8_t relay_buf[2048];
        BitchatPacket relay_pkt = pkt;
        relay_pkt.ttl = pkt.ttl - 1;

        size_t relay_len = bc_packet_encode(&relay_pkt, relay_buf, sizeof(relay_buf),
                                            true /* padding */);
        if (relay_len > 0) {
            mesh->relay_count++;
            mesh->on_relay(relay_buf, relay_len, src_peer, mesh->cb_ctx);
        }
    }
}

// ─── Outbound packet builders ─────────────────────────────────────────────────

size_t bc_build_message_packet(
    const uint8_t* sender_id,
    const char* sender_nick,
    const char* content,
    uint64_t    timestamp_ms,
    uint8_t     ttl,
    uint8_t*    buf,
    size_t      buf_size,
    bool        padding)
{
    // Encode the BitchatMessage payload
    uint8_t payload[BC_MAX_CONTENT + 128];
    BitchatMessage msg;
    memset(&msg, 0, sizeof(msg));
    // Generate a simple UUID-style ID: ts_ms hex + sender_id[0]
    snprintf(msg.id, sizeof(msg.id), "%016llx-%02x%02x%02x%02x",
             (unsigned long long)timestamp_ms,
             sender_id[0], sender_id[1], sender_id[2], sender_id[3]);
    strncpy(msg.sender, sender_nick, BC_MAX_NICKNAME);
    strncpy(msg.content, content, BC_MAX_CONTENT);
    msg.timestamp_ms = timestamp_ms;

    size_t payload_len = bc_message_encode(&msg, payload, sizeof(payload));
    if (payload_len == 0) return 0;

    BitchatPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.version      = BC_VERSION_V1;
    pkt.type         = BC_TYPE_MESSAGE;
    pkt.ttl          = ttl;
    pkt.timestamp_ms = timestamp_ms;
    memcpy(pkt.sender_id, sender_id, BC_SENDER_ID_SIZE);
    pkt.has_recipient = true;
    bc_set_broadcast(pkt.recipient_id);
    pkt.is_broadcast = true;
    pkt.payload      = payload;
    pkt.payload_len  = (uint16_t)payload_len;

    return bc_packet_encode(&pkt, buf, buf_size, padding);
}

size_t bc_build_announce_packet(
    const uint8_t* sender_id,
    const char*    nickname,
    const uint8_t* noise_pub_key,
    uint64_t       timestamp_ms,
    uint8_t*       buf,
    size_t         buf_size)
{
    uint8_t payload[64];
    BitchatAnnounce ann;
    memset(&ann, 0, sizeof(ann));
    strncpy(ann.nickname, nickname, BC_MAX_NICKNAME);
    if (noise_pub_key) {
        // Fingerprint = SHA-256(noise_pub_key) — caller must pass pre-hashed fingerprint
        memcpy(ann.pub_key_fingerprint, noise_pub_key, 32);
        ann.has_fingerprint = true;
    }

    size_t payload_len = bc_announce_encode(&ann, payload, sizeof(payload));
    if (payload_len == 0) return 0;

    BitchatPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.version      = BC_VERSION_V1;
    pkt.type         = BC_TYPE_ANNOUNCE;
    pkt.ttl          = BC_TTL_ANNOUNCE;
    pkt.timestamp_ms = timestamp_ms;
    memcpy(pkt.sender_id, sender_id, BC_SENDER_ID_SIZE);
    pkt.has_recipient = false;
    pkt.payload      = payload;
    pkt.payload_len  = (uint16_t)payload_len;

    return bc_packet_encode(&pkt, buf, buf_size, false /* no padding on announce */);
}

size_t bc_build_leave_packet(
    const uint8_t* sender_id,
    uint64_t       timestamp_ms,
    uint8_t*       buf,
    size_t         buf_size)
{
    BitchatPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.version      = BC_VERSION_V1;
    pkt.type         = BC_TYPE_LEAVE;
    pkt.ttl          = BC_TTL_ANNOUNCE;
    pkt.timestamp_ms = timestamp_ms;
    memcpy(pkt.sender_id, sender_id, BC_SENDER_ID_SIZE);
    pkt.has_recipient = false;
    pkt.payload      = NULL;
    pkt.payload_len  = 0;

    return bc_packet_encode(&pkt, buf, buf_size, false);
}

// ─── bc_mesh_send_* ───────────────────────────────────────────────────────────

bool bc_mesh_send_message(BitchatMesh* mesh, const char* content, uint32_t now_ms) {
    if (!mesh->on_relay || !content) return false;

    uint8_t buf[2048];
    size_t len = bc_build_message_packet(
        mesh->local_id, mesh->nickname, content,
        (uint64_t)now_ms, BC_TTL_DEFAULT,
        buf, sizeof(buf), true /* padding */
    );
    if (len == 0) return false;

    // Add to own bloom filter so we don't relay our own packets
    // We need a temp decode to get the bloom key
    BitchatPacket tmp;
    if (bc_packet_decode(buf, len, &tmp)) {
        bc_bloom_add(&mesh->bloom, tmp.timestamp_ms, tmp.sender_id, tmp.type);
    }

    mesh->on_relay(buf, len, -1 /* local origin */, mesh->cb_ctx);
    return true;
}

bool bc_mesh_send_announce(BitchatMesh* mesh, const uint8_t* noise_pub_key_fingerprint,
                           uint32_t now_ms) {
    if (!mesh->on_relay) return false;

    uint8_t buf[256];
    size_t len = bc_build_announce_packet(
        mesh->local_id, mesh->nickname,
        noise_pub_key_fingerprint,
        (uint64_t)now_ms, buf, sizeof(buf)
    );
    if (len == 0) return false;

    mesh->on_relay(buf, len, -1, mesh->cb_ctx);
    return true;
}

bool bc_mesh_send_leave(BitchatMesh* mesh, uint32_t now_ms) {
    if (!mesh->on_relay) return false;

    uint8_t buf[64];
    size_t len = bc_build_leave_packet(
        mesh->local_id, (uint64_t)now_ms, buf, sizeof(buf)
    );
    if (len == 0) return false;

    mesh->on_relay(buf, len, -1, mesh->cb_ctx);
    return true;
}

// ─── bc_mesh_tick ─────────────────────────────────────────────────────────────

#define BC_PEER_TIMEOUT_MS  120000  // 2 minutes

void bc_mesh_tick(BitchatMesh* mesh, uint32_t now_ms) {
    // Age out bloom filter
    bc_bloom_tick(&mesh->bloom, now_ms);

    // Age out stale peers
    for (int i = 0; i < BC_MAX_PEERS; i++) {
        if (mesh->peers[i].active &&
            (now_ms - mesh->peers[i].last_seen_ms) > BC_PEER_TIMEOUT_MS) {
            if (mesh->on_peer) mesh->on_peer(&mesh->peers[i], false, mesh->cb_ctx);
            mesh->peers[i].active = false;
            mesh->peer_count = (mesh->peer_count > 0) ? mesh->peer_count - 1 : 0;
        }
    }
}
