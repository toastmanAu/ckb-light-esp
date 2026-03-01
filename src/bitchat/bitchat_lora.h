// bitchat_lora.h — BitChat LoRa transport bridge for ESP32
// toastmanAu/ckb-light-esp
//
// Bridges BitChat BLE mesh ↔ LoRa radio on T-Deck / T-Beam.
// This is the piece the community has been asking for (BitChat issue #508).
//
// PROBLEM: MTU mismatch
//   BLE ATT payload:  up to 509 bytes (MTU 512 - 3)
//   LoRa SF7/125kHz:  max 255 bytes physical (RadioLib SX1262/SX1276 limit)
//   BitChat padding:  256/512/1024/2048 blocks
//
// SOLUTION: fragment relay
//   BLE→LoRa:  receive full BitChat packet (up to 2048 bytes)
//               strip padding (bc_unpad) → raw packet
//               re-fragment into LoRa-sized chunks (≤ LORA_FRAG_MAX bytes)
//               transmit each chunk with LoRa-layer fragment header
//
//   LoRa→BLE:  receive LoRa fragment chunks
//               reassemble into complete packet
//               feed into bc_mesh_receive() — same as BLE side
//               bc_mesh relay callback sends to all BLE peers
//
// LORA FRAGMENT FORMAT (different from BitChat's BLE fragment type):
//   This is a LoRa-layer framing header prepended to raw BitChat packet data.
//   BitChat nodes treat the LoRa bridge as just another peer — they never see
//   the LoRa framing. Only LoRa-capable nodes (T-Deck/T-Beam) speak this.
//
//   [msg_id: 2 bytes][frag_idx: 1 byte][frag_total: 1 byte][data: ...]
//    └─ hash of packet timestamp+sender  ──────────────────┘
//       (enough to match fragments without 36-byte UUID)
//
// Compile guard: #ifdef LIGHT_PROFILE_LORA or LIGHT_PROFILE_LORAWAN
// Requires: RadioLib (jgromes/RadioLib)

#pragma once

#include "bitchat_mesh.h"

#if defined(LIGHT_PROFILE_LORA) || defined(LIGHT_PROFILE_LORAWAN)
#ifndef HOST_TEST

#include <RadioLib.h>
#include <Arduino.h>

// ─── LoRa fragment header ─────────────────────────────────────────────────────

#define BC_LORA_FRAG_HDR_SIZE   4    // msg_id(2) + idx(1) + total(1)
#define BC_LORA_MAX_PAYLOAD     251  // 255 - 4 byte frag header
#define BC_LORA_REASSEMBLY_SLOTS 4   // max parallel in-flight reassemblies
#define BC_LORA_FRAG_TIMEOUT_MS 5000 // drop incomplete reassembly after 5s

typedef struct {
    uint16_t msg_id;
    uint8_t  frag_idx;
    uint8_t  frag_total;
    uint8_t  data[BC_LORA_MAX_PAYLOAD];
    uint8_t  data_len;
} LoRaFragment;

typedef struct {
    uint16_t msg_id;
    uint8_t  total_frags;
    uint8_t  received;           // bitmask (up to 8 frags, usually 1-4)
    uint8_t  buf[2048];          // reassembly buffer
    uint16_t buf_fill;
    uint32_t started_ms;
    bool     active;
} LoRaReassembly;

// ─── BitchatLoRa class ────────────────────────────────────────────────────────

class BitchatLoRa {
public:
    BitchatLoRa();

    // Attach to mesh engine + configure LoRa radio.
    // radio: RadioLib module (SX1262, SX1276, etc.)
    // freq: MHz (e.g. 915.0 for AU, 868.0 for EU, 433.0 for CN)
    void begin(BitchatMesh* mesh, float freq_mhz = 915.0);

    // Call in loop() — polls for received LoRa packets.
    void tick();

    // Send a raw packet over LoRa (called from relay callback).
    // Strips BLE padding, re-fragments for LoRa MTU.
    void send(const uint8_t* buf, size_t len);

    uint32_t txCount() const { return _tx_count; }
    uint32_t rxCount() const { return _rx_count; }

private:
    BitchatMesh*     _mesh;
    float            _freq;
    uint32_t         _tx_count;
    uint32_t         _rx_count;

    LoRaReassembly   _reassembly[BC_LORA_REASSEMBLY_SLOTS];

    // Relay callback: mesh→LoRa
    static void _relay_cb(const uint8_t* buf, size_t len, int src_peer, void* ctx);

    // Fragment a raw (unpadded) packet into LoRa chunks and transmit
    void _send_fragmented(const uint8_t* raw, size_t raw_len, uint16_t msg_id);

    // Receive a LoRa fragment, reassemble, feed to mesh if complete
    void _on_lora_fragment(const uint8_t* frag_buf, size_t frag_len);

    // Find or allocate a reassembly slot for msg_id
    LoRaReassembly* _find_reassembly(uint16_t msg_id);

    // Age out stale reassembly slots
    void _age_reassembly(uint32_t now_ms);

    // Compute 2-byte msg_id from packet (hash of timestamp + sender[0:2])
    static uint16_t _packet_msg_id(const uint8_t* raw, size_t len);
};

#endif // HOST_TEST
#endif // LIGHT_PROFILE_LORA || LIGHT_PROFILE_LORAWAN
