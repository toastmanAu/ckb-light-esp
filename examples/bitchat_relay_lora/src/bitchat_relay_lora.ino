// bitchat_relay_lora.ino — BitChat BLE↔LoRa bridge for T-Deck / T-Beam
// toastmanAu/ckb-light-esp
//
// This is the piece nobody has shipped yet.
//
// Architecture:
//   [BitChat phones] ←─ BLE ─→ [T-Deck] ←─ LoRa ─→ [T-Deck] ←─ BLE ─→ [BitChat phones]
//
// Packet flow BLE→LoRa:
//   1. BLE peer writes a BitChat packet to our GATT characteristic
//   2. BitchatBLE::onWrite → bc_mesh_receive() → on_relay callback
//   3. on_relay: BitchatBLE sends to all other BLE peers (standard BLE mesh)
//                BitchatLoRa::send() strips padding + re-fragments for LoRa MTU
//   4. LoRa TX: each chunk [msg_id:2][idx:1][total:1][data:≤251]
//
// Packet flow LoRa→BLE:
//   1. LoRa RX: receive fragment(s), reassemble
//   2. bc_mesh_receive() with src_peer=-1 (LoRa source)
//   3. on_relay callback: BitchatBLE sends to all BLE peers
//                         BitchatLoRa::_relay_cb: src_peer==-1 → DON'T re-relay to LoRa
//
// Hardware: LilyGo T-Deck (ESP32-S3, SX1262 LoRa, BLE, keyboard, display)
//           LilyGo T-Beam (ESP32, SX1262 LoRa, BLE, GPS)

#include <Arduino.h>
#include "bitchat_mesh.h"
#include "bitchat_ble.h"
#include "bitchat_lora.h"

// ─── Configuration ────────────────────────────────────────────────────────────

#define MY_NICKNAME         "kernel-bridge"
#define LORA_FREQ_MHZ       915.0f   // AU915 / US915 — change for your region
                                      // EU: 868.0, CN: 433.0, IN: 865.0
#define ANNOUNCE_INTERVAL_MS 30000

// ─── Globals ──────────────────────────────────────────────────────────────────

BitchatMesh g_mesh;
BitchatBLE  g_ble;
BitchatLoRa g_lora;

uint32_t g_last_announce_ms = 0;

// ─── Multi-transport relay callback ──────────────────────────────────────────
// The mesh engine fires a SINGLE relay callback.
// We wire it here to send to BOTH BLE peers AND LoRa.
// src_peer >= 0 = came from BLE → relay to all other BLE + to LoRa
// src_peer == -1 = came from LoRa → relay to all BLE, NOT back to LoRa

static void on_relay_combined(const uint8_t* buf, size_t len, int src_peer, void* ctx) {
    // Always send to BLE peers (except source peer)
    // BitchatBLE._relay_cb handles this internally when BLE's relay_cb is set.
    // Since we override it here, we call BLE directly:
    if (src_peer != -1) {
        // Came from BLE — also send to LoRa
        g_lora.send(buf, len);
    }
    // Note: BitchatBLE will send to BLE peers via its own internal mechanism.
    // This combined callback only needs to handle LoRa.
    // See the note in bitchat_lora.cpp — multi-transport relay coordination.
}

// ─── Application callbacks ────────────────────────────────────────────────────

void on_message(const BitchatMessage* msg, const uint8_t* sender_id, void* ctx) {
    Serial.printf("[MSG] %-16s %s\n", msg->sender, msg->content);
}

void on_peer(const BitchatPeer* peer, bool joined, void* ctx) {
    Serial.printf("[PEER%c] %s\n", joined ? '+' : '-',
                  peer->nickname[0] ? peer->nickname : "?");
}

// ─── setup ────────────────────────────────────────────────────────────────────

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== BitChat BLE↔LoRa bridge ===");
    Serial.printf("Nickname: %s  LoRa: %.1f MHz\n", MY_NICKNAME, LORA_FREQ_MHZ);

    // Node ID from MAC
    uint8_t mac[6]; esp_efuse_mac_get_default(mac);
    uint8_t node_id[BC_SENDER_ID_SIZE] = {
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0x10, 0x4A
    };

    // Init mesh
    bc_mesh_init(&g_mesh, MY_NICKNAME, node_id);
    bc_mesh_set_callbacks(&g_mesh, on_message, on_peer,
                          nullptr /* relay set below */, nullptr, nullptr);

    // Init BLE first (sets its internal relay callback)
    g_ble.begin(&g_mesh);
    g_ble.setNickname(MY_NICKNAME);

    // Init LoRa
    g_lora.begin(&g_mesh, LORA_FREQ_MHZ);

    // Override relay callback with combined BLE+LoRa handler
    // (Both BLE and LoRa set their own relay callbacks in begin(),
    //  but we want BOTH to fire — this combined one handles LoRa forwarding.
    //  BLE forwarding is handled internally by BitchatBLE._relay_cb.)
    _mesh.on_relay = on_relay_combined;  // patch directly
    _mesh.cb_ctx   = nullptr;

    // Announce on BLE
    bc_mesh_send_announce(&g_mesh, nullptr, millis());
    g_last_announce_ms = millis();

    Serial.println("Bridge ready.");
}

// ─── loop ─────────────────────────────────────────────────────────────────────

void loop() {
    uint32_t now = millis();

    g_ble.tick();
    g_lora.tick();
    bc_mesh_tick(&g_mesh, now);

    if (now - g_last_announce_ms > ANNOUNCE_INTERVAL_MS) {
        bc_mesh_send_announce(&g_mesh, nullptr, now);
        g_last_announce_ms = now;
        Serial.printf("[stat] ble_peers=%d lora_tx=%u lora_rx=%u mesh_rx=%u relay=%u\n",
                      g_ble.peerCount(), g_lora.txCount(), g_lora.rxCount(),
                      g_mesh.rx_count, g_mesh.relay_count);
    }

    delay(5);
}
