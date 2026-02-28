#pragma once
#include <stdint.h>
#include <stdbool.h>

// =============================================================================
// lorawan_transport.h — LoRaWAN transport for ckb-light-esp
//
// Bridges CKB light client protocol over a LoRaWAN network.
// Supports TTN (The Things Network), Chirpstack, and any compliant NS.
//
// vs raw LoRa (lora_transport.h):
//   Raw LoRa  → point-to-point, private gateway, you control everything
//   LoRaWAN   → public/private network, OTAA join, MAC-managed duty cycle,
//               multi-hop: device → gateway → network server → backend → node
//
// Use LoRaWAN when:
//   - Shipping a product (user just points at TTN, no gateway setup)
//   - Coverage from existing LoRaWAN infrastructure
//   - Need roaming across multiple gateways
//
// Use raw LoRa when:
//   - Private off-grid setup (shed ASIC ↔ Pi gateway)
//   - Lower latency (no NS round-trip)
//   - Full control over protocol and duty cycle
//
// Architecture:
//   Device (this) ──LoRaWAN──► Gateway ──► Network Server (TTN/Chirpstack)
//                                                    │
//                                          ckb-lora-bridge (companion)
//                                                    │
//                                          CKB full/light node RPC
//
// Requires: MCCI LoRaWAN LMIC library (arduino-lmic)
//           Hardware: TTGO T-Beam, Heltec LoRa 32, or any SX1276/SX1262 + ESP32
//
// Activation: OTAA only (ABP supported but not recommended)
// Payload: custom compact binary format (not raw JSON — LoRaWAN MTU is 51–242 bytes)
// Port assignments:
//   Port 1 — RPC request (uplink)
//   Port 2 — RPC response (downlink)
//   Port 3 — keepalive / ping
// =============================================================================

// LoRaWAN payload limits (SF-dependent, conservative defaults)
#define LORAWAN_MAX_UPLINK_BYTES    51    // safe for all SF (SF12 = 51 bytes)
#define LORAWAN_MAX_DOWNLINK_BYTES  242   // max downlink payload
#define LORAWAN_MAX_FRAGMENTS       8     // max fragments per logical message

// Port assignments
#define LORAWAN_PORT_RPC_REQUEST    1
#define LORAWAN_PORT_RPC_RESPONSE   2
#define LORAWAN_PORT_KEEPALIVE      3

// Fragmentation header (1 byte): [frag_idx:4][total_frags:4]
// Allows up to 16 fragments = ~800 bytes max message over LoRaWAN
#define LORAWAN_FRAG_HEADER_SIZE    1

// Join modes
typedef enum {
    LORAWAN_JOIN_OTAA,   // Over-the-air activation (recommended)
    LORAWAN_JOIN_ABP,    // Activation by personalisation (static keys)
} LoRaWANJoinMode;

// Spreading factor (controls range vs data rate trade-off)
typedef enum {
    LORAWAN_SF7  = 7,   // fastest, shortest range, most duty cycle headroom
    LORAWAN_SF8  = 8,
    LORAWAN_SF9  = 9,
    LORAWAN_SF10 = 10,
    LORAWAN_SF11 = 11,
    LORAWAN_SF12 = 12,  // slowest, longest range, tight duty cycle
} LoRaWANSF;

// OTAA credentials (from TTN/Chirpstack console)
typedef struct {
    uint8_t devEUI[8];    // device EUI (LSB first)
    uint8_t appEUI[8];    // application EUI / join EUI (LSB first)
    uint8_t appKey[16];   // application key
} LoRaWANOTAA;

// ABP credentials (static, no join required)
typedef struct {
    uint32_t devAddr;
    uint8_t  nwkSKey[16];
    uint8_t  appSKey[16];
} LoRaWANABP;

class LoRaWANTransport {
public:
    // OTAA constructor (recommended)
    LoRaWANTransport(
        const LoRaWANOTAA& creds,
        LoRaWANSF sf     = LORAWAN_SF9,   // SF9 = good balance for CKB sync
        long freq        = 915E6           // 915MHz (AU/US). 868MHz for EU.
    );

    // ABP constructor (for testing / fixed deployments)
    LoRaWANTransport(
        const LoRaWANABP& creds,
        LoRaWANSF sf     = LORAWAN_SF9,
        long freq        = 915E6
    );

    // Initialise radio + LMIC stack
    // Call from setup(). Blocks until joined (OTAA) or immediately (ABP).
    // Returns false if join fails within timeoutMs.
    bool begin(uint32_t timeoutMs = 30000);

    // Drive the LMIC event loop — call from your loop() frequently
    // (LoRaWAN is event-driven, needs regular calls to os_runloop_once)
    void poll();

    // Send a JSON-RPC request, wait for downlink response
    // Large requests/responses are fragmented automatically.
    // timeoutMs should be generous — LoRaWAN downlink can take 1–2 rx windows
    // Returns bytes written to responseBuf, or -1 on error/timeout
    int request(
        const char* method,
        const char* params,
        char*       responseBuf,
        size_t      responseBufSize,
        uint32_t    timeoutMs = 30000     // LoRaWAN needs longer than WiFi/raw LoRa
    );

    // True if joined and ready
    bool isConnected();

    // True if currently in a duty cycle wait (can't transmit)
    bool isDutyCycleLimited();

    // Estimated wait time before next uplink allowed (ms)
    uint32_t dutyCycleRemainingMs();

    // Current RSSI + SNR of last received downlink
    int8_t  lastRSSI() const { return _lastRSSI; }
    int8_t  lastSNR()  const { return _lastSNR; }

    const char* lastError() const { return _lastError; }

private:
    LoRaWANJoinMode _joinMode;
    LoRaWANOTAA     _otaa;
    LoRaWANABP      _abp;
    LoRaWANSF       _sf;
    long            _freq;

    bool    _joined;
    uint8_t _seq;
    int8_t  _lastRSSI;
    int8_t  _lastSNR;
    char    _lastError[64];

    // Fragmentation reassembly buffer
    uint8_t  _rxBuf[LORAWAN_MAX_FRAGMENTS * LORAWAN_MAX_DOWNLINK_BYTES];
    uint16_t _rxLen;
    uint8_t  _rxFragsReceived;
    uint8_t  _rxFragsExpected;

    // Transmit with automatic fragmentation if payload > MTU
    bool _sendFragmented(uint8_t port, const uint8_t* data, size_t len);

    // Wait for downlink with timeout, reassemble fragments
    int  _recvFragmented(uint8_t* out, size_t maxLen, uint32_t timeoutMs);

    // LMIC event callback (static, routes to instance)
    static void _onEvent(void* ctx, uint32_t ev);
};
