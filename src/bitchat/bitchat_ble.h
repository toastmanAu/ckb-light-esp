// bitchat_ble.h — BitChat BLE GATT transport for ESP32 (NimBLE-Arduino)
// toastmanAu/ckb-light-esp
//
// Implements the BitChat BLE transport layer using the NimBLE-Arduino library.
// Connects to the bitchat_mesh relay engine via the bc_relay_cb callback.
//
// BitChat BLE protocol:
//   - GATT service UUID: F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C
//   - Characteristic:    A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D
//   - Write to char = send packet to peer
//   - Notify on char = receive packet from peer
//   - CCCD descriptor:   00002902-0000-1000-8000-00805f9b34fb (standard)
//
// Mode: Simultaneous peripheral (advertise) + central (scan + connect).
// ESP32 supports this natively. Max simultaneous connections: ~3-7 (chip-dependent).
//
// Usage (Arduino setup()):
//   BitchatBLE ble;
//   ble.begin(&mesh);          // pass your BitchatMesh
//   ble.setNickname("Kernel"); // shown in scan response
//
// Usage (Arduino loop()):
//   ble.tick();                // drives BLE event loop
//
// Dependencies:
//   - NimBLE-Arduino library (h2zero/NimBLE-Arduino)
//   - bitchat_mesh.h (relay engine)
//
// Host test: BLE is Arduino-only. Compile guard: #ifndef HOST_TEST

#pragma once

#include "bitchat_mesh.h"

#ifndef HOST_TEST

#include <NimBLEDevice.h>
#include <NimBLEServer.h>
#include <NimBLEScan.h>
#include <NimBLEClient.h>
#include <Arduino.h>

// ─── BitChat GATT UUIDs ───────────────────────────────────────────────────────
// Confirmed from permissionlesstech/bitchat-android AppConstants.kt + iOS source.

#define BC_BLE_SERVICE_UUID    "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
#define BC_BLE_CHAR_UUID       "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"
#define BC_BLE_CCCD_UUID       "00002902-0000-1000-8000-00805f9b34fb"

// ─── Configuration ────────────────────────────────────────────────────────────

#define BC_BLE_MAX_CONNECTIONS  4     // max simultaneous BLE peers
#define BC_BLE_MTU             512    // negotiated MTU (BLE 4.2+, actual ATT ~509)
#define BC_BLE_SCAN_DURATION    5     // seconds per scan window
#define BC_BLE_SCAN_INTERVAL   30     // seconds between scan windows
#define BC_BLE_TX_POWER         3     // dBm (ESP32 max = 9)
#define BC_BLE_DEVICE_NAME_PFX  "bitchat" // advertised name prefix

// ─── Connected peer state ─────────────────────────────────────────────────────

struct BLEPeer {
    NimBLEClient*       client;
    NimBLERemoteCharacteristic* charac;
    uint8_t             peer_id[BC_SENDER_ID_SIZE]; // learned from first packet
    bool                peer_id_known;
    bool                subscribed;    // CCCD notifications enabled
    uint32_t            last_rx_ms;
    bool                active;
};

// ─── BitchatBLE class ─────────────────────────────────────────────────────────

class BitchatBLE : public NimBLEServerCallbacks,
                   public NimBLECharacteristicCallbacks,
                   public NimBLEScanCallbacks {
public:
    BitchatBLE();

    // Initialise BLE, attach to mesh engine.
    // Call once in setup() after bc_mesh_init().
    void begin(BitchatMesh* mesh);

    // Set device nickname (used in BLE advertisement).
    void setNickname(const char* nick);

    // Periodic maintenance — call in loop(). Drives scan/connect logic.
    void tick();

    // Force an immediate scan pass (e.g. after wake from sleep).
    void scan();

    // Disconnect all peers and stop advertising.
    void stop();

    // Stats
    uint32_t txCount()  const { return _tx_count; }
    uint32_t rxCount()  const { return _rx_count; }
    uint8_t  peerCount() const;

private:
    BitchatMesh*  _mesh;
    char          _nickname[BC_MAX_NICKNAME + 1];

    // GATT server side (peripheral role)
    NimBLEServer*         _server;
    NimBLEService*        _service;
    NimBLECharacteristic* _characteristic;

    // Connected peers
    BLEPeer  _peers[BC_BLE_MAX_CONNECTIONS];

    // Scan state
    uint32_t _last_scan_ms;
    bool     _scanning;

    // Stats
    uint32_t _tx_count;
    uint32_t _rx_count;

    // ── Relay callback registered with mesh ──────────────────────────────────
    // Called by bc_mesh_receive() when a packet needs forwarding.
    // Sends to all connected BLE peers except src_peer.
    static void _relay_cb(const uint8_t* buf, size_t len, int src_peer, void* ctx);

    // ── Internal helpers ─────────────────────────────────────────────────────
    void _init_server();
    void _start_advertising();
    void _connect_to(NimBLEAdvertisedDevice* device);
    BLEPeer* _find_peer_slot();
    BLEPeer* _find_peer_by_client(NimBLEClient* client);
    void     _on_packet_received(const uint8_t* data, size_t len, int peer_slot);
    void     _send_to_peer(BLEPeer* peer, const uint8_t* buf, size_t len);

    // ── NimBLEServerCallbacks ────────────────────────────────────────────────
    void onConnect(NimBLEServer* server, ble_gap_conn_desc* desc) override;
    void onDisconnect(NimBLEServer* server) override;

    // ── NimBLECharacteristicCallbacks ────────────────────────────────────────
    // Fired when a remote central writes to our characteristic (sends us a packet)
    void onWrite(NimBLECharacteristic* pCharacteristic,
                 ble_gap_conn_desc* desc) override;

    // ── NimBLEScanCallbacks ──────────────────────────────────────────────────
    // Fired when scanner finds a device advertising the BitChat service UUID
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) override;
    void onScanEnd(NimBLEScanResults results) override;
};

// ─── Singleton helper (one BLE stack per device) ─────────────────────────────
// BitchatBLE is not copyable. Use a single global instance.
// extern BitchatBLE g_ble;   // declare in your .ino

#endif // HOST_TEST
