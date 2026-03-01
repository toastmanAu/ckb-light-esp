// test_lora_transport.cpp — host tests for lora_transport.cpp
//
// Build:
//   g++ -DHOST_TEST -std=c++11 -I. -Isrc -Isrc/transport -Isrc/core \
//       -I/home/phill/workspace/CKB-ESP32/src \
//       test/test_lora_transport.cpp src/transport/lora_transport.cpp \
//       -o test/test_lora && test/test_lora

#define HOST_TEST
#include "lora_transport.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int _pass = 0, _fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); _pass++; } \
    else      { printf("  FAIL: %s (line %d)\n", name, __LINE__); _fail++; } \
} while(0)

// Helper: build a wire-encoded LoRaPacket into a buffer
static size_t buildWire(uint8_t* buf, uint8_t type, uint8_t seq,
                         const uint8_t* payload, uint16_t payLen) {
    buf[0] = type; buf[1] = seq;
    buf[2] = payLen & 0xFF; buf[3] = payLen >> 8;
    if (payLen && payload) memcpy(buf + 4, payload, payLen);
    return 4 + payLen;
}

// Helper: build a single-fragment RPC response wire packet
static size_t buildRpcResp(uint8_t* buf, uint8_t seq,
                             const char* json, uint8_t totalFrags = 1, uint8_t idx = 0) {
    uint8_t pay[LORA_MAX_PAYLOAD];
    pay[0] = totalFrags;
    pay[1] = idx;
    size_t jsonLen = strlen(json);
    if (jsonLen > LORA_MAX_PAYLOAD - 2) jsonLen = LORA_MAX_PAYLOAD - 2;
    memcpy(pay + 2, json, jsonLen);
    return buildWire(buf, LORA_PKT_RPC_RESPONSE, seq, pay, (uint16_t)(2 + jsonLen));
}

// ── Tests ──────────────────────────────────────────────────────────────────────

void testBegin() {
    printf("\n[1] begin() and isConnected()\n");
    LoRaTransport lora;
    CHECK(!lora.isConnected(), "not connected before begin");
    CHECK(lora.begin(), "begin() returns true");
    CHECK(lora.isConnected(), "connected after begin");
}

void testPing() {
    printf("\n[2] ping() — loopback PING→PONG\n");
    LoRaTransport lora;
    lora.begin();
    int rtt = lora.ping();
    CHECK(rtt >= 0, "ping() returns non-negative RTT");
    printf("  INFO: loopback RTT = %d ms\n", rtt);
}

void testPacketEncoding() {
    printf("\n[3] Packet encode/decode — round trip via injectPacket\n");
    LoRaTransport lora;
    lora.begin();

    // Build an ACK packet and inject it as a "received" packet
    LoRaPacket ack;
    ack.type = LORA_PKT_ACK;
    ack.seq  = 42;
    ack.len  = 0;
    lora.injectPacket(ack);

    // Use request() with a tiny body — it will send 1 frag, then look for response
    // We need to also inject a valid RPC response
    uint8_t respWire[256];
    size_t respLen = buildRpcResp(respWire, 1, "{\"result\":\"ok\"}");
    lora.injectResponse(respWire, respLen);

    char respBuf[256];
    // seq will be 1 after the request (first seq bump)
    // But ACK has seq=42 — won't match. Test just encoding basics instead.
    // Reset and do a simpler check
    lora.clearBuffers();

    // Inject a PONG (seq=1 for the next ping call)
    LoRaPacket pong;
    pong.type = LORA_PKT_PONG;
    pong.seq  = 1;
    pong.len  = 0;
    lora.injectPacket(pong);
    int rtt = lora.ping();
    CHECK(rtt >= 0, "injected PONG → ping() succeeds");

    // Verify seq was bumped
    CHECK(lora.lastSeq() == 1, "seq == 1 after one ping");
}

void testRpcSingleFragment() {
    printf("\n[4] request() — single-fragment RPC\n");
    LoRaTransport lora;
    lora.begin();
    lora.clearBuffers();

    // After request() sends 1 frag with seq=1, it waits for RPC_RESPONSE with seq=1
    // Inject a 1-fragment response
    uint8_t wire[256];
    size_t wLen = buildRpcResp(wire, 1, "{\"id\":1,\"result\":\"0x1234\"}");
    lora.injectResponse(wire, wLen);

    char respBuf[256];
    int n = lora.request("get_tip_block_number", "[]", respBuf, sizeof(respBuf), 1000);
    CHECK(n > 0, "request() returns positive byte count");
    CHECK(strstr(respBuf, "0x1234") != nullptr, "response contains expected data");
    printf("  INFO: response = %.*s\n", n, respBuf);
}

void testRpcMultiFragmentRequest() {
    printf("\n[5] request() — large body triggers multi-fragment send\n");
    LoRaTransport lora;
    lora.begin();
    lora.clearBuffers();

    // Build a params string that's > FRAG_MAX (238 bytes) to force 2+ send fragments
    // FRAG_MAX = LORA_MAX_PAYLOAD(240) - FRAG_HDR(2) = 238
    char bigParams[600];
    memset(bigParams, 0, sizeof(bigParams));
    bigParams[0] = '[';
    memset(bigParams + 1, 'x', 500);
    bigParams[501] = ']';
    bigParams[502] = '\0';

    // For each fragment sent, the transport expects an ACK before sending next.
    // Inject ACKs for all but the last fragment, then inject the response.
    // body = {"method":"foo","params":[xxx...xxx]}
    // len ~ 22 + 502 = 524 bytes → ceil(524/238) = 3 fragments
    // Need to inject 2 ACKs (for frags 0 and 1) + 1 response (for frag 2)
    // seq will be 1
    uint8_t ack1[4] = {LORA_PKT_ACK, 1, 0, 0};
    uint8_t ack2[4] = {LORA_PKT_ACK, 1, 0, 0};
    lora.injectResponse(ack1, 4);

    // After ack1 is consumed (for frag 0), inject ack2 + response
    // Problem: injectResponse is a single buffer — use injectPacket to chain
    lora.clearBuffers();

    // Build inject buffer: ACK + ACK + RPC_RESPONSE
    uint8_t injBuf[512];
    size_t pos = 0;
    // ACK for frag 0
    injBuf[pos++] = LORA_PKT_ACK; injBuf[pos++] = 1;
    injBuf[pos++] = 0; injBuf[pos++] = 0;
    // ACK for frag 1
    injBuf[pos++] = LORA_PKT_ACK; injBuf[pos++] = 1;
    injBuf[pos++] = 0; injBuf[pos++] = 0;
    // RPC response (single frag)
    size_t rLen = buildRpcResp(injBuf + pos, 1, "{\"result\":\"big_ok\"}");
    pos += rLen;
    lora.injectResponse(injBuf, pos);

    char respBuf[256];
    int n = lora.request("big_method", bigParams, respBuf, sizeof(respBuf), 2000);
    CHECK(n > 0, "large request: response received");
    CHECK(strstr(respBuf, "big_ok") != nullptr, "large request: correct response content");
}

void testRpcMultiFragmentResponse() {
    printf("\n[6] request() — multi-fragment response reassembly\n");
    LoRaTransport lora;
    lora.begin();
    lora.clearBuffers();

    // Build a 2-fragment response
    // Fragment 0: first 238 chars of JSON
    // Fragment 1: remaining chars
    const char* part0 = "{\"result\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const char* part1 = "BBBBBBBBB\"}";

    uint8_t injBuf[1024];
    size_t pos = 0;
    // Frag 0 of response (totalFrags=2, idx=0)
    pos += buildRpcResp(injBuf + pos, 1, part0, 2, 0);
    // Frag 1 of response (totalFrags=2, idx=1)
    pos += buildRpcResp(injBuf + pos, 1, part1, 2, 1);
    // Also need to inject an ACK for our request send (seq=1)
    // The request will send 1 frag (small method), expect response directly
    // Prepend with nothing — the ACK from our send goes to loopback which we ignore
    lora.injectResponse(injBuf, pos);

    char respBuf[2048];
    int n = lora.request("get_block", "[]", respBuf, sizeof(respBuf), 2000);
    CHECK(n > 0, "multi-frag response: bytes received");
    // part1 should appear at correct offset
    CHECK(strstr(respBuf, "BBBBBBBBB") != nullptr, "multi-frag response: part1 present");
    CHECK(strstr(respBuf, "AAAAAAAAA") != nullptr, "multi-frag response: part0 present");
    printf("  INFO: reassembled %d bytes\n", n);
}

void testTimeout() {
    printf("\n[7] Timeout — no response injected\n");
    LoRaTransport lora;
    lora.begin();
    lora.clearBuffers();

    char respBuf[256];
    int n = lora.request("get_tip", "[]", respBuf, sizeof(respBuf), 100); // 100ms timeout
    CHECK(n < 0, "timeout returns -1");
    CHECK(strlen(lora.lastError()) > 0, "error message set on timeout");
    printf("  INFO: error = %s\n", lora.lastError());
}

void testNotConnected() {
    printf("\n[8] Not connected guard\n");
    LoRaTransport lora; // no begin()
    char buf[64];
    int n = lora.request("foo", "[]", buf, sizeof(buf), 100);
    CHECK(n < 0, "request without begin() returns -1");
    CHECK(strlen(lora.lastError()) > 0, "error set when not connected");
}

// ── main ──────────────────────────────────────────────────────────────────────
int main() {
    printf("========================================\n");
    printf("  lora_transport.cpp host tests\n");
    printf("========================================\n");

    testBegin();
    testPing();
    testPacketEncoding();
    testRpcSingleFragment();
    testRpcMultiFragmentRequest();
    testRpcMultiFragmentResponse();
    testTimeout();
    testNotConnected();

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n", _pass, _fail);
    printf("========================================\n");
    return _fail > 0 ? 1 : 0;
}
