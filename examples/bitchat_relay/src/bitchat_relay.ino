// bitchat_relay.ino — BitChat BLE mesh relay node for ESP32
// toastmanAu/ckb-light-esp
//
// Minimal BitChat relay node. No display, no keyboard — just a fixed
// BLE mesh node that relays packets, optionally bridging to LoRa.
//
// What this does:
//   - Advertises as a BitChat peer
//   - Scans for nearby BitChat peers and connects
//   - Relays all packets between connected peers (gossip flood, TTL--)
//   - Sends an announce on boot and leave on shutdown
//   - Logs received public messages to Serial
//
// Hardware: any ESP32 with BLE (esp32dev, CYD, T-Deck, T-Beam, etc.)
// Library:  NimBLE-Arduino (h2zero/NimBLE-Arduino)
//           ckb-light-esp (this library)
//
// Future extensions (not in this sketch):
//   - LoRa bridge: receive from BLE, re-fragment for LoRa 255-byte MTU
//   - CKB light client: watch an address, alert on payment via BitChat
//   - Noise session: send/receive private messages

#include <Arduino.h>
#include "bitchat_mesh.h"
#include "bitchat_ble.h"

// ─── Configuration ────────────────────────────────────────────────────────────

#define MY_NICKNAME    "kernel-relay"
#define ANNOUNCE_INTERVAL_MS  30000  // re-announce every 30s

// ─── Globals ─────────────────────────────────────────────────────────────────

BitchatMesh g_mesh;
BitchatBLE  g_ble;

uint32_t g_last_announce_ms = 0;

// ─── Callbacks ────────────────────────────────────────────────────────────────

void on_message(const BitchatMessage* msg, const uint8_t* sender_id, void* ctx) {
    Serial.printf("[MSG] %s: %s\n", msg->sender, msg->content);
    if (msg->is_relay && msg->has_orig_sender) {
        Serial.printf("      (relayed from %s)\n", msg->orig_sender);
    }
}

void on_peer(const BitchatPeer* peer, bool joined, void* ctx) {
    if (joined) {
        Serial.printf("[PEER+] %s\n", peer->nickname[0] ? peer->nickname : "(unknown)");
    } else {
        Serial.printf("[PEER-] %s\n", peer->nickname[0] ? peer->nickname : "(unknown)");
    }
}

// relay_cb is handled internally by BitchatBLE — it calls _relay_cb
// which sends to all connected BLE peers. Nothing to do here.

void on_noise(uint8_t noise_type, const uint8_t* payload, uint16_t len,
              const uint8_t* sender_id, void* ctx) {
    // Noise packets (private messages) — we're not a session endpoint.
    // bc_mesh_receive() already relayed these. Just log for debug.
    Serial.printf("[NOISE] type=0x%02x len=%d (relayed)\n", noise_type, len);
}

// ─── setup ────────────────────────────────────────────────────────────────────

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== BitChat relay node ===");
    Serial.printf("Nickname: %s\n", MY_NICKNAME);

    // Derive node ID from chip MAC
    uint8_t mac[6]; esp_efuse_mac_get_default(mac);
    uint8_t node_id[BC_SENDER_ID_SIZE] = {
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0x00, 0x01
    };
    char id_hex[17];
    snprintf(id_hex, sizeof(id_hex),
             "%02x%02x%02x%02x%02x%02x%02x%02x",
             node_id[0],node_id[1],node_id[2],node_id[3],
             node_id[4],node_id[5],node_id[6],node_id[7]);
    Serial.printf("Node ID: %s\n", id_hex);

    // Init mesh engine
    bc_mesh_init(&g_mesh, MY_NICKNAME, node_id);
    bc_mesh_set_callbacks(&g_mesh, on_message, on_peer, nullptr, on_noise, nullptr);

    // Init BLE transport (sets relay callback internally)
    g_ble.begin(&g_mesh);
    g_ble.setNickname(MY_NICKNAME);

    // Announce presence
    bc_mesh_send_announce(&g_mesh, nullptr /* no Noise key yet */, millis());
    g_last_announce_ms = millis();

    Serial.println("Ready. Listening for BitChat peers...");
}

// ─── loop ─────────────────────────────────────────────────────────────────────

void loop() {
    uint32_t now = millis();

    // Drive BLE scan/connect loop
    g_ble.tick();

    // Drive mesh maintenance (peer aging, bloom rotation)
    bc_mesh_tick(&g_mesh, now);

    // Periodic re-announce
    if (now - g_last_announce_ms > ANNOUNCE_INTERVAL_MS) {
        bc_mesh_send_announce(&g_mesh, nullptr, now);
        g_last_announce_ms = now;
        Serial.printf("[stat] peers=%d ble=%d rx=%u relay=%u drop=%u\n",
                      g_mesh.peer_count, g_ble.peerCount(),
                      g_mesh.rx_count, g_mesh.relay_count, g_mesh.drop_count);
    }

    delay(10);  // yield to BLE stack
}
