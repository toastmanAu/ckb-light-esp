#pragma once
// ckb_rpc_fixtures.h — shared canned RPC response strings for host tests
// All responses are real-format JSON matching CKB node RPC output.
// Used across test_light_client.cpp, test_wifi_transport.cpp, etc.
//
// Note: block number 0x64 = 100, used as a predictable test anchor.

// ── Helpers ───────────────────────────────────────────────────────────────────

// Wrap a JSON body in a Content-Length HTTP/1.1 response
#include <stdio.h>
#include <string.h>

static inline std::string ckbMakeHttpResp(const char* body) {
    char buf[4096];
    snprintf(buf, sizeof(buf),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s",
        strlen(body), body);
    return std::string(buf);
}

// ── Fixture bodies ────────────────────────────────────────────────────────────

// get_tip_header — block 100 (0x64), synthetic hash
static inline std::string ckbRespTipHeader() {
    return ckbMakeHttpResp(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
        "\"number\":\"0x64\","
        "\"hash\":\"0xaabbcc0000000000000000000000000000000000000000000000000000001234\","
        "\"parent_hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\","
        "\"compact_target\":\"0x20010000\","
        "\"timestamp\":\"0x19ca68c34a7\","
        "\"transactions_root\":\"0x0000000000000000000000000000000000000000000000000000000000000000\","
        "\"proposals_hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\","
        "\"nonce\":\"0x00000000000000000000000000000000\","
        "\"epoch\":\"0x708200000000\","
        "\"dao\":\"0x\","
        "\"version\":\"0x0\""
        "}}");
}

// set_scripts — null result (success)
static inline std::string ckbRespSetScripts() {
    return ckbMakeHttpResp(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}");
}

// get_peers — 1 peer
static inline std::string ckbRespPeers1() {
    return ckbMakeHttpResp(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":["
        "{\"node_id\":\"0xdeadbeef\",\"addresses\":[],\"protocols\":[]}"
        "]}");
}

// get_peers — 0 peers (not synced / dev chain)
static inline std::string ckbRespPeers0() {
    return ckbMakeHttpResp(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[]}");
}

// get_block_filter — empty filter (0 elements), block 100
static inline std::string ckbRespEmptyFilter() {
    return ckbMakeHttpResp(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
        "\"data\":\"0x0000000000000000\""
        "}}");
}

// get_block_filter — filter containing script hash 0x55*32
// (pre-computed reference: 0x0100000000000000899bf8)
static inline std::string ckbRespMatchFilter() {
    return ckbMakeHttpResp(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
        "\"data\":\"0x0100000000000000899bf8\""
        "}}");
}

// get_header_by_number — returns synthetic block hash for block 100
static inline std::string ckbRespHeaderByNumber() {
    return ckbMakeHttpResp(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
        "\"number\":\"0x64\","
        "\"hash\":\"0xaabbcc0000000000000000000000000000000000000000000000000000001234\""
        "}}");
}

// fetch_transaction — status: fetching (FETCH_PENDING)
static inline std::string ckbRespFetchPending() {
    return ckbMakeHttpResp(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
        "\"status\":\"fetching\","
        "\"first_sent\":\"0x1a2b3c\""
        "}}");
}

// fetch_transaction — status: fetched (FETCH_DONE)
static inline std::string ckbRespFetchDone(const char* txHash) {
    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
        "\"status\":\"fetched\","
        "\"transaction\":{\"hash\":\"%s\",\"version\":\"0x0\","
        "\"cell_deps\":[],\"header_deps\":[],\"inputs\":[],\"outputs\":[],\"witnesses\":[]}"
        "}}",
        txHash);
    return ckbMakeHttpResp(buf);
}

// fetch_transaction — status: not_found
static inline std::string ckbRespFetchNotFound() {
    return ckbMakeHttpResp(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
        "\"status\":\"not_found\""
        "}}");
}

// error response (method not found, etc.)
static inline std::string ckbRespError(int code, const char* msg) {
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":%d,\"message\":\"%s\"}}",
        code, msg);
    return ckbMakeHttpResp(buf);
}
