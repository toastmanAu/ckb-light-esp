#pragma once
#include <stdint.h>
#include <stdbool.h>

// =============================================================================
// lora_transport.h — LoRa packet transport for off-grid light client sync
//
// Bridges CKB light client protocol over LoRa radio.
// Requires a paired LoRa gateway running ckb-lora-bridge (companion software).
//
// Protocol overview:
//   - Custom lightweight packet format (not raw TCP)
//   - Sequence numbers + ACK for share/tx submissions (no loss tolerance)
//   - Job delivery is best-effort (pool will resend on new block anyway)
//   - Default: SX1276 via RadioLib
//
// Hardware: any ESP32 + SX1276/SX1278/SX1262 LoRa module
// Tested: TTGO T-Beam, Heltec WiFi LoRa 32
//
// Pin config via LightConfig.h or constructor args.
// =============================================================================

// LoRa packet types
#define LORA_PKT_PING           0x01
#define LORA_PKT_PONG           0x02
#define LORA_PKT_RPC_REQUEST    0x10
#define LORA_PKT_RPC_RESPONSE   0x11
#define LORA_PKT_ACK            0x20
#define LORA_PKT_NACK           0x21

// Max LoRa payload (SX1276 max = 255 bytes)
#define LORA_MAX_PAYLOAD        240

typedef struct {
  uint8_t  type;
  uint8_t  seq;
  uint16_t len;
  uint8_t  payload[LORA_MAX_PAYLOAD];
} LoRaPacket;

class LoRaTransport {
public:
  // pin assignments — adjust for your board
  LoRaTransport(
    int pinNSS  = 18,
    int pinRST  = 14,
    int pinDIO0 = 26,
    long freq   = 915E6    // 915MHz (AU/US). 868MHz for EU.
  );

  // Initialise radio
  bool begin();

  // Send a JSON-RPC request via LoRa, block for ACK + response
  // Large responses are fragmented and reassembled automatically
  // Returns bytes written to responseBuf, or -1 on timeout/error
  int request(
    const char* method,
    const char* params,
    char*       responseBuf,
    size_t      responseBufSize,
    uint32_t    timeoutMs = 10000   // LoRa needs more time than WiFi
  );

  bool isConnected();

  // Ping the gateway — returns round-trip time in ms, or -1
  int ping();

  const char* lastError() const { return _lastError; }

private:
  int   _pinNSS, _pinRST, _pinDIO0;
  long  _freq;
  uint8_t _seq;
  char  _lastError[64];

  bool _sendPacket(const LoRaPacket& pkt);
  bool _recvPacket(LoRaPacket& out, uint32_t timeoutMs);
  bool _waitAck(uint8_t seq, uint32_t timeoutMs);
};
