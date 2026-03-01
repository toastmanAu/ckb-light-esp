// lora_transport.cpp — LoRa packet transport for CKB light client
//
// Protocol: custom lightweight binary framing with ACK + fragmentation
// RadioLib handles radio layer on device; loopback stub for HOST_TEST.
//
// Host test build:
//   g++ -DHOST_TEST -std=c++11 -I. -Isrc -Isrc/transport -Isrc/core \
//       -I/home/phill/workspace/CKB-ESP32/src \
//       test/test_lora_transport.cpp src/transport/lora_transport.cpp \
//       -o test/test_lora && test/test_lora

#include "lora_transport.h"
#include <string.h>
#include <stdio.h>

#ifndef HOST_TEST
#include <RadioLib.h>
static SX1276* _radioInst = nullptr;
static volatile bool _rxFlag = false;
static void IRAM_ATTR _onRxDone() { _rxFlag = true; }
#endif

// ── millis_compat() ───────────────────────────────────────────────────────────
#ifdef HOST_TEST
#include <time.h>
static uint32_t millis_compat() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#else
static uint32_t millis_compat() { return (uint32_t)millis(); }
#endif

// ── Constructor ───────────────────────────────────────────────────────────────
LoRaTransport::LoRaTransport(int pinNSS, int pinRST, int pinDIO0, long freq)
    : _pinNSS(pinNSS), _pinRST(pinRST), _pinDIO0(pinDIO0),
      _freq(freq), _seq(0), _connected(false) {
    _lastError[0] = '\0';
#ifdef HOST_TEST
    _loopbackLen = 0;
    _injectLen   = 0;
#endif
}

// ── begin() ───────────────────────────────────────────────────────────────────
bool LoRaTransport::begin() {
#ifdef HOST_TEST
    _connected = true;
    return true;
#else
    Module* mod = new Module(_pinNSS, _pinDIO0, _pinRST);
    _radioInst = new SX1276(mod);
    int state = _radioInst->begin(
        (float)(_freq / 1e6), 125.0, 9, 7, 0x12, 17, 8, 0);
    if (state != RADIOLIB_ERR_NONE) {
        snprintf(_lastError, sizeof(_lastError), "LoRa init: %d", state);
        return false;
    }
    _radioInst->setDio0Action(_onRxDone, RISING);
    _radioInst->startReceive();
    _connected = true;
    return true;
#endif
}

bool LoRaTransport::isConnected() { return _connected; }

// ── Wire encode/decode ────────────────────────────────────────────────────────
// Wire format: [type:1][seq:1][len:2 LE][payload:len]
static uint16_t encodePacket(const LoRaPacket& pkt, uint8_t* buf, size_t bufSize) {
    uint16_t wireLen = 4 + pkt.len;
    if (wireLen > bufSize || pkt.len > LORA_MAX_PAYLOAD) return 0;
    buf[0] = pkt.type;
    buf[1] = pkt.seq;
    buf[2] = (uint8_t)(pkt.len & 0xFF);
    buf[3] = (uint8_t)(pkt.len >> 8);
    if (pkt.len > 0) memcpy(buf + 4, pkt.payload, pkt.len);
    return wireLen;
}

static bool decodePacket(const uint8_t* buf, uint16_t bufLen, LoRaPacket& out) {
    if (bufLen < 4) return false;
    out.type = buf[0];
    out.seq  = buf[1];
    out.len  = (uint16_t)buf[2] | ((uint16_t)buf[3] << 8);
    if (out.len > LORA_MAX_PAYLOAD || (uint16_t)(4 + out.len) > bufLen) return false;
    if (out.len > 0) memcpy(out.payload, buf + 4, out.len);
    return true;
}

// ── _sendPacket() ─────────────────────────────────────────────────────────────
bool LoRaTransport::_sendPacket(const LoRaPacket& pkt) {
    uint8_t buf[LORA_MAX_PAYLOAD + 4];
    uint16_t wireLen = encodePacket(pkt, buf, sizeof(buf));
    if (!wireLen) { snprintf(_lastError, sizeof(_lastError), "encode failed"); return false; }

#ifdef HOST_TEST
    // Loopback: sent packets go to _loopbackBuf (simulates remote echo)
    if (_loopbackLen + wireLen <= sizeof(_loopbackBuf)) {
        memcpy(_loopbackBuf + _loopbackLen, buf, wireLen);
        _loopbackLen += wireLen;
    }
    return true;
#else
    _radioInst->standby();
    int state = _radioInst->transmit(buf, wireLen);
    _radioInst->startReceive();
    if (state != RADIOLIB_ERR_NONE) {
        snprintf(_lastError, sizeof(_lastError), "TX: %d", state);
        return false;
    }
    return true;
#endif
}

// ── _recvPacket() ─────────────────────────────────────────────────────────────
bool LoRaTransport::_recvPacket(LoRaPacket& out, uint32_t timeoutMs) {
#ifdef HOST_TEST
    // First drain _injectBuf (test-injected responses), then _loopbackBuf
    uint8_t* src = nullptr;
    size_t*  len = nullptr;
    if (_injectLen >= 4) { src = _injectBuf; len = &_injectLen; }
    else if (_loopbackLen >= 4) { src = _loopbackBuf; len = &_loopbackLen; }
    if (!src) return false;

    if (!decodePacket(src, (uint16_t)*len, out)) return false;
    size_t consumed = 4 + out.len;
    memmove(src, src + consumed, *len - consumed);
    *len -= consumed;
    return true;
#else
    uint32_t deadline = millis_compat() + timeoutMs;
    while (millis_compat() < deadline) {
        if (_rxFlag) {
            _rxFlag = false;
            uint8_t buf[LORA_MAX_PAYLOAD + 4];
            int n = _radioInst->readData(buf, sizeof(buf));
            _radioInst->startReceive();
            if (n < 4) continue;
            if (decodePacket(buf, (uint16_t)n, out)) return true;
        }
        delay(2);
    }
    snprintf(_lastError, sizeof(_lastError), "RX timeout %ums", timeoutMs);
    return false;
#endif
}

// ── _waitAck() ────────────────────────────────────────────────────────────────
bool LoRaTransport::_waitAck(uint8_t seq, uint32_t timeoutMs) {
    uint32_t deadline = millis_compat() + timeoutMs;
    while (millis_compat() < deadline) {
        LoRaPacket pkt;
        uint32_t rem = deadline - millis_compat();
        if (_recvPacket(pkt, rem < 200 ? rem : 200)) {
            if (pkt.type == LORA_PKT_ACK  && pkt.seq == seq) return true;
            if (pkt.type == LORA_PKT_NACK && pkt.seq == seq) {
                snprintf(_lastError, sizeof(_lastError), "NACK seq %u", seq);
                return false;
            }
        }
    }
    snprintf(_lastError, sizeof(_lastError), "ACK timeout seq %u", seq);
    return false;
}

// ── ping() ────────────────────────────────────────────────────────────────────
int LoRaTransport::ping() {
    LoRaPacket pkt = { LORA_PKT_PING, ++_seq, 0, {} };
    uint32_t t0 = millis_compat();
    if (!_sendPacket(pkt)) return -1;

    // In loopback test the sent packet comes straight back — intercept and
    // replace type with PONG before recvPacket sees it
#ifdef HOST_TEST
    // Patch loopback: PING → PONG
    if (_loopbackLen >= 1) _loopbackBuf[0] = LORA_PKT_PONG;
#endif
    LoRaPacket resp;
    if (!_recvPacket(resp, 5000)) return -1;
    if (resp.type != LORA_PKT_PONG) return -1;
    return (int)(millis_compat() - t0);
}

// ── request() — fragmented JSON-RPC ──────────────────────────────────────────
#define FRAG_HDR  2   // frag_total:1 + frag_idx:1
#define FRAG_MAX  (LORA_MAX_PAYLOAD - FRAG_HDR)

int LoRaTransport::request(
    const char* method, const char* params,
    char* responseBuf, size_t responseBufSize,
    uint32_t timeoutMs)
{
    if (!_connected) { snprintf(_lastError, sizeof(_lastError), "not connected"); return -1; }

    // Build JSON-RPC body
    char body[FRAG_MAX * 16]; // generous buffer
    int bodyLen = snprintf(body, sizeof(body),
        "{\"method\":\"%s\",\"params\":%s}", method, params ? params : "[]");
    if (bodyLen <= 0 || bodyLen >= (int)sizeof(body)) {
        snprintf(_lastError, sizeof(_lastError), "body overflow");
        return -1;
    }

    int nFrags = (bodyLen + FRAG_MAX - 1) / FRAG_MAX;
    if (nFrags > 255) { snprintf(_lastError, sizeof(_lastError), "request too large"); return -1; }
    uint8_t txSeq = ++_seq;

    // Send request fragments
    for (int i = 0; i < nFrags; i++) {
        LoRaPacket pkt;
        pkt.type = LORA_PKT_RPC_REQUEST;
        pkt.seq  = txSeq;
        int off   = i * FRAG_MAX;
        int chunk = bodyLen - off;
        if (chunk > FRAG_MAX) chunk = FRAG_MAX;
        pkt.len        = (uint16_t)(FRAG_HDR + chunk);
        pkt.payload[0] = (uint8_t)nFrags;
        pkt.payload[1] = (uint8_t)i;
        memcpy(pkt.payload + FRAG_HDR, body + off, chunk);
        if (!_sendPacket(pkt)) return -1;
        if (i < nFrags - 1 && !_waitAck(txSeq, 3000)) return -1;
    }

    // Receive response fragments
    memset(responseBuf, 0, responseBufSize);
    size_t responseLen = 0;
    int totalFrags = -1, rxCount = 0;

    uint32_t deadline = millis_compat() + timeoutMs;
    while (millis_compat() < deadline && (totalFrags < 0 || rxCount < totalFrags)) {
        LoRaPacket resp;
        uint32_t rem = deadline - millis_compat();
        if (!_recvPacket(resp, rem < 2000 ? rem : 2000)) break;

        if (resp.type == LORA_PKT_NACK && resp.seq == txSeq) {
            snprintf(_lastError, sizeof(_lastError), "RPC NACK"); return -1;
        }
        if (resp.type != LORA_PKT_RPC_RESPONSE || resp.seq != txSeq) continue;
        if (resp.len < FRAG_HDR) continue;

        int rTotal = resp.payload[0];
        int rIdx   = resp.payload[1];
        int dataLen = resp.len - FRAG_HDR;
        if (totalFrags < 0) totalFrags = rTotal;

        size_t writeOff = (size_t)rIdx * FRAG_MAX;
        if (writeOff + dataLen < responseBufSize) {
            memcpy(responseBuf + writeOff, resp.payload + FRAG_HDR, dataLen);
            if (writeOff + dataLen > responseLen) responseLen = writeOff + dataLen;
        }
        rxCount++;

        // ACK this fragment
        LoRaPacket ack = { LORA_PKT_ACK, txSeq, 0, {} };
        _sendPacket(ack);
    }

    if (totalFrags < 0 || rxCount < totalFrags) {
        snprintf(_lastError, sizeof(_lastError), "incomplete: %d/%d frags", rxCount, totalFrags);
        return -1;
    }
    return (int)responseLen;
}
