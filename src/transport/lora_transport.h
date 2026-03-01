#pragma once
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// =============================================================================
// lora_transport.h — LoRa packet transport for off-grid CKB light client sync
//
// Protocol: custom lightweight binary framing
//   Wire format: [type:1][seq:1][len:2 LE][payload:len]
//   Fragmentation: [frag_total:1][frag_idx:1][data...] inside payload
//   ACK/NACK per fragment for reliable multi-hop delivery
//
// Hardware: any ESP32 + SX1276/SX1278/SX1262 (RadioLib)
// Tested boards: TTGO T-Beam, Heltec WiFi LoRa 32, T-Deck
//
// HOST_TEST: loopback stub — no RadioLib dependency
// =============================================================================

// Packet types
#define LORA_PKT_PING           0x01
#define LORA_PKT_PONG           0x02
#define LORA_PKT_RPC_REQUEST    0x10
#define LORA_PKT_RPC_RESPONSE   0x11
#define LORA_PKT_ACK            0x20
#define LORA_PKT_NACK           0x21

// SX1276 max payload = 255; leave 15 bytes for wire header overhead
#define LORA_MAX_PAYLOAD        240

typedef struct {
    uint8_t  type;
    uint8_t  seq;
    uint16_t len;
    uint8_t  payload[LORA_MAX_PAYLOAD];
} LoRaPacket;

class LoRaTransport {
public:
    LoRaTransport(
        int  pinNSS  = 18,
        int  pinRST  = 14,
        int  pinDIO0 = 26,
        long freq    = 915000000L   // 915 MHz AU/US; 868 MHz EU
    );

    bool begin();
    bool isConnected();

    // Ping the gateway; returns RTT ms or -1
    int ping();

    // JSON-RPC request over LoRa (fragmented, ACK'd)
    // Returns bytes written to responseBuf, or -1 on error
    int request(
        const char* method,
        const char* params,
        char*       responseBuf,
        size_t      responseBufSize,
        uint32_t    timeoutMs = 10000
    );

    const char* lastError() const { return _lastError; }

#ifdef HOST_TEST
    // Test hooks: inject a pre-built response into the receive buffer
    void injectResponse(const uint8_t* data, size_t len) {
        if (len <= sizeof(_injectBuf)) {
            memcpy(_injectBuf, data, len);
            _injectLen = len;
        }
    }
    void injectPacket(const LoRaPacket& pkt) {
        uint8_t buf[LORA_MAX_PAYLOAD + 4];
        size_t wireLen = 4 + pkt.len;
        buf[0] = pkt.type; buf[1] = pkt.seq;
        buf[2] = pkt.len & 0xFF; buf[3] = pkt.len >> 8;
        if (pkt.len) memcpy(buf + 4, pkt.payload, pkt.len);
        if (_injectLen + wireLen <= sizeof(_injectBuf)) {
            memcpy(_injectBuf + _injectLen, buf, wireLen);
            _injectLen += wireLen;
        }
    }
    void clearBuffers() { _loopbackLen = 0; _injectLen = 0; }
    uint8_t lastSeq() const { return _seq; }
#endif

private:
    int   _pinNSS, _pinRST, _pinDIO0;
    long  _freq;
    uint8_t _seq;
    bool  _connected;
    char  _lastError[64];

    bool _sendPacket(const LoRaPacket& pkt);
    bool _recvPacket(LoRaPacket& out, uint32_t timeoutMs);
    bool _waitAck(uint8_t seq, uint32_t timeoutMs);

#ifdef HOST_TEST
    uint8_t _loopbackBuf[2048];
    size_t  _loopbackLen;
    uint8_t _injectBuf[2048];
    size_t  _injectLen;
#endif
};
