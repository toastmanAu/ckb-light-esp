// bitchat_lora.cpp — BitChat LoRa transport bridge implementation
// toastmanAu/ckb-light-esp

#include "bitchat_lora.h"

#if defined(LIGHT_PROFILE_LORA) || defined(LIGHT_PROFILE_LORAWAN)
#ifndef HOST_TEST

// Board-specific LoRa pin definitions from wyltek-embedded-builder
#if defined(WY_BOARD_TDECK)
  // T-Deck: SX1262 on SPI (from boards.h WY_LORA_* defines)
  #define LORA_CS_PIN    WY_LORA_CS
  #define LORA_IRQ_PIN   WY_LORA_DIO1
  #define LORA_RST_PIN   WY_LORA_RST
  #define LORA_BUSY_PIN  WY_LORA_BUSY
  static SX1262 _radio = new Module(LORA_CS_PIN, LORA_IRQ_PIN, LORA_RST_PIN, LORA_BUSY_PIN);

#elif defined(WY_BOARD_TBEAM)
  #define LORA_CS_PIN    WY_LORA_CS
  #define LORA_IRQ_PIN   WY_LORA_DIO1
  #define LORA_RST_PIN   WY_LORA_RST
  #define LORA_BUSY_PIN  WY_LORA_BUSY
  static SX1262 _radio = new Module(LORA_CS_PIN, LORA_IRQ_PIN, LORA_RST_PIN, LORA_BUSY_PIN);

#else
  // Generic SX1276 fallback (most LoRa shield modules)
  #define LORA_CS_PIN    18
  #define LORA_IRQ_PIN   26
  #define LORA_RST_PIN   14
  static SX1276 _radio = new Module(LORA_CS_PIN, LORA_IRQ_PIN, LORA_RST_PIN);
#endif

// LoRa RF settings — matched to what community members use for BitChat LoRa experiments
// AU915: 915 MHz, SF7 (fast, 5.5kbps, ~900m urban range)
// EU868: 868 MHz
// Bandwidth 125 kHz, CR 4/5, preamble 8
#define LORA_BW_KHZ     125.0
#define LORA_SF         7
#define LORA_CR         5    // 4/5
#define LORA_PREAMBLE   8
#define LORA_TX_POWER   17   // dBm

// ─── BitchatLoRa ─────────────────────────────────────────────────────────────

BitchatLoRa::BitchatLoRa()
    : _mesh(nullptr), _freq(915.0f), _tx_count(0), _rx_count(0) {
    memset(_reassembly, 0, sizeof(_reassembly));
}

void BitchatLoRa::begin(BitchatMesh* mesh, float freq_mhz) {
    _mesh = mesh;
    _freq = freq_mhz;

    // Init radio
    int state = _radio.begin(_freq, LORA_BW_KHZ, LORA_SF, LORA_CR,
                              RADIOLIB_SX127X_SYNC_WORD, LORA_TX_POWER,
                              LORA_PREAMBLE);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[LoRa] init failed: %d\n", state);
        return;
    }
    _radio.setCRC(true);

    // Set max packet length to 255 (SX127x limit)
    _radio.setMaxPayloadLength(255);

    // Register relay callback — mesh sends here when relaying
    // We save existing callbacks and chain them
    bc_relay_cb existing_relay = _mesh->on_relay;
    void*        existing_ctx  = _mesh->cb_ctx;

    // Use a simple approach: LoRa relay fires for ALL relay packets.
    // BLE relay is set separately (BitchatBLE::begin sets its own cb).
    // To avoid double-setting, the LoRa bridge is designed to be added
    // AFTER BitchatBLE::begin() by chaining ctx pointers.
    // For simplicity here: LoRa is an additional relay target.
    // The mesh engine fires one relay_cb — for multi-transport, the sketch
    // should wire both in its own relay_cb and call both.
    // (See examples/bitchat_relay_lora for the combined sketch.)

    bc_mesh_set_callbacks(_mesh,
        _mesh->on_message, _mesh->on_peer,
        _relay_cb, _mesh->on_noise,
        this
    );

    // Start in receive mode
    _radio.startReceive();

    Serial.printf("[LoRa] ready %.1fMHz SF%d BW%.0fkHz\n",
                  _freq, LORA_SF, LORA_BW_KHZ);
}

// ─── tick ─────────────────────────────────────────────────────────────────────

void BitchatLoRa::tick() {
    uint32_t now = millis();

    // Age out stale reassembly slots
    _age_reassembly(now);

    // Poll for received packet
    if (_radio.available()) {
        uint8_t frag_buf[255];
        size_t  frag_len = 0;

        int state = _radio.readData(frag_buf, sizeof(frag_buf));
        if (state == RADIOLIB_ERR_NONE) {
            frag_len = _radio.getPacketLength(false);
            if (frag_len >= BC_LORA_FRAG_HDR_SIZE) {
                _on_lora_fragment(frag_buf, frag_len);
            }
        }

        // Return to receive mode
        _radio.startReceive();
    }
}

// ─── send ─────────────────────────────────────────────────────────────────────

void BitchatLoRa::send(const uint8_t* buf, size_t len) {
    if (!buf || len < 14) return;

    // Strip BLE padding to get raw packet
    size_t raw_len = bc_unpad(buf, len);
    if (raw_len == 0 || raw_len > 2048) return;

    // Generate 2-byte msg_id for this packet's fragments
    uint16_t msg_id = _packet_msg_id(buf, raw_len);

    // Fragment and transmit
    _send_fragmented(buf, raw_len, msg_id);
}

// ─── _send_fragmented ─────────────────────────────────────────────────────────

void BitchatLoRa::_send_fragmented(const uint8_t* raw, size_t raw_len, uint16_t msg_id) {
    uint8_t total = (uint8_t)((raw_len + BC_LORA_MAX_PAYLOAD - 1) / BC_LORA_MAX_PAYLOAD);
    if (total == 0) total = 1;

    for (uint8_t i = 0; i < total; i++) {
        uint8_t tx_buf[255];
        size_t data_off = (size_t)i * BC_LORA_MAX_PAYLOAD;
        size_t data_len = raw_len - data_off;
        if (data_len > BC_LORA_MAX_PAYLOAD) data_len = BC_LORA_MAX_PAYLOAD;

        // Build fragment header: [msg_id_hi][msg_id_lo][idx][total]
        tx_buf[0] = (msg_id >> 8) & 0xFF;
        tx_buf[1] = msg_id & 0xFF;
        tx_buf[2] = i;
        tx_buf[3] = total;
        memcpy(tx_buf + BC_LORA_FRAG_HDR_SIZE, raw + data_off, data_len);
        size_t tx_len = BC_LORA_FRAG_HDR_SIZE + data_len;

        // Transmit (blocking — LoRa TX takes ~50-200ms at SF7)
        int state = _radio.transmit(tx_buf, tx_len);
        if (state == RADIOLIB_ERR_NONE) {
            _tx_count++;
        } else {
            Serial.printf("[LoRa] TX error: %d\n", state);
        }

        // Inter-fragment gap (allow other stations to start listening)
        if (i < total - 1) delay(20);

        // Return to receive mode between fragments
        _radio.startReceive();
    }
}

// ─── _on_lora_fragment ────────────────────────────────────────────────────────

void BitchatLoRa::_on_lora_fragment(const uint8_t* frag_buf, size_t frag_len) {
    if (frag_len < BC_LORA_FRAG_HDR_SIZE) return;

    uint16_t msg_id    = ((uint16_t)frag_buf[0] << 8) | frag_buf[1];
    uint8_t  frag_idx  = frag_buf[2];
    uint8_t  frag_total = frag_buf[3];
    const uint8_t* data = frag_buf + BC_LORA_FRAG_HDR_SIZE;
    size_t   data_len  = frag_len - BC_LORA_FRAG_HDR_SIZE;

    if (frag_total == 0 || frag_idx >= frag_total) return;

    _rx_count++;

    // Single-fragment packet (common case) — fast path
    if (frag_total == 1) {
        bc_mesh_receive(_mesh, data, data_len, -1 /* LoRa source */, millis());
        return;
    }

    // Multi-fragment: find or allocate reassembly slot
    LoRaReassembly* slot = _find_reassembly(msg_id);
    if (!slot) return;  // all slots busy

    // Copy fragment data into reassembly buffer
    size_t write_off = (size_t)frag_idx * BC_LORA_MAX_PAYLOAD;
    if (write_off + data_len > sizeof(slot->buf)) return;  // too big
    memcpy(slot->buf + write_off, data, data_len);
    slot->buf_fill = write_off + data_len;

    // Mark fragment as received (bit in received bitmask, up to 8 frags)
    if (frag_idx < 8) slot->received |= (1 << frag_idx);
    slot->total_frags = frag_total;

    // Check if we have all fragments
    uint8_t expected_mask = (frag_total < 8) ? ((1 << frag_total) - 1) : 0xFF;
    if ((slot->received & expected_mask) == expected_mask) {
        // Reassembly complete — feed into mesh
        bc_mesh_receive(_mesh, slot->buf, slot->buf_fill, -1, millis());
        // Free slot
        memset(slot, 0, sizeof(LoRaReassembly));
    }
}

// ─── _find_reassembly ─────────────────────────────────────────────────────────

LoRaReassembly* BitchatLoRa::_find_reassembly(uint16_t msg_id) {
    // Check existing slot for this msg_id
    for (int i = 0; i < BC_LORA_REASSEMBLY_SLOTS; i++) {
        if (_reassembly[i].active && _reassembly[i].msg_id == msg_id)
            return &_reassembly[i];
    }
    // Allocate new slot
    for (int i = 0; i < BC_LORA_REASSEMBLY_SLOTS; i++) {
        if (!_reassembly[i].active) {
            memset(&_reassembly[i], 0, sizeof(LoRaReassembly));
            _reassembly[i].msg_id     = msg_id;
            _reassembly[i].active     = true;
            _reassembly[i].started_ms = millis();
            return &_reassembly[i];
        }
    }
    return nullptr;
}

void BitchatLoRa::_age_reassembly(uint32_t now_ms) {
    for (int i = 0; i < BC_LORA_REASSEMBLY_SLOTS; i++) {
        if (_reassembly[i].active &&
            (now_ms - _reassembly[i].started_ms) > BC_LORA_FRAG_TIMEOUT_MS) {
            Serial.printf("[LoRa] reassembly timeout msg_id=%04x\n",
                          _reassembly[i].msg_id);
            _reassembly[i].active = false;
        }
    }
}

// ─── _packet_msg_id ──────────────────────────────────────────────────────────

uint16_t BitchatLoRa::_packet_msg_id(const uint8_t* raw, size_t len) {
    if (len < 11) return 0;
    // Use bytes 3-10 (timestamp) XOR bytes 11-12 (start of sender_id)
    // → 2 bytes of "good enough" uniqueness for fragment matching
    uint32_t h = 0;
    for (int i = 3; i < 11 && i < (int)len; i++)
        h = (h << 5) ^ raw[i];
    if (len > 14) h ^= ((uint32_t)raw[14] << 8) | raw[15];
    return (uint16_t)(h ^ (h >> 16));
}

// ─── _relay_cb ───────────────────────────────────────────────────────────────

void BitchatLoRa::_relay_cb(const uint8_t* buf, size_t len, int src_peer, void* ctx) {
    BitchatLoRa* self = static_cast<BitchatLoRa*>(ctx);
    if (!self) return;
    // src_peer == -1 means local origin or LoRa-received — don't echo to LoRa
    // src_peer >= 0 means came from BLE — relay to LoRa
    if (src_peer >= 0) {
        self->send(buf, len);
    }
}

#endif // HOST_TEST
#endif // LIGHT_PROFILE_LORA || LIGHT_PROFILE_LORAWAN
