#pragma once
#include <stdint.h>
#include <stdbool.h>
#ifndef HOST_TEST
#  include <WiFi.h>
#  include <WiFiClient.h>
#endif

// =============================================================================
// wifi_transport.h — WiFi TCP transport to CKB light client node RPC
//
// ⚠️  BACKEND REQUIREMENT
// This transport talks to the CKB *light client node* RPC (default port 9000),
// NOT a full node (port 8114). Full nodes do not serve block filters or the
// light client protocol methods.
//
// Run the Rust light client as your backend:
//   https://github.com/nervosnetwork/ckb-light-client
//
// The light client node handles P2P filter sync with the CKB network.
// This ESP implementation talks to the light client's HTTP/JSON-RPC interface.
//
// Architecture:
//   CKB network (P2P) ←→ [ckb-light-client Rust node] ←→ WiFi ←→ [ESP32]
//
// ── RPC methods we use ────────────────────────────────────────────────────
//
// set_scripts      — register scripts to watch (takes full Script objects, not hashes)
// get_scripts      — query current watch list + filtered block number per script
// get_tip_header   — latest known header (HeaderView JSON)
// get_header       — header by block hash
// get_transaction  — tx by hash (committed only, returns TransactionWithStatus)
// fetch_transaction — async tx fetch: "fetched"/"fetching"/"added"/"not_found"
// send_transaction — broadcast a signed tx → returns tx_hash
// get_peers        — connected peer info (use for health / sync checks)
//
// ── set_scripts params format ─────────────────────────────────────────────
//
// Takes FULL Script objects (code_hash + hash_type + args), NOT hashes:
//   [[{ "script": { "code_hash": "0x...", "hash_type": "type", "args": "0x..." },
//      "script_type": "lock",
//      "block_number": "0x0" }],
//    "partial"]   ← optional: "all" (default, replaces all) | "partial" | "delete"
//
// "partial" adds/updates without removing existing scripts.
//
// ── fetch_transaction vs get_transaction ──────────────────────────────────
//
// get_transaction  — returns committed tx immediately (or null if unknown)
// fetch_transaction — async: asks P2P network, returns:
//   { "status": "fetched",   "data": TransactionWithStatus }  ← done
//   { "status": "fetching",  "first_sent": Uint64 }           ← in progress, retry
//   { "status": "added",     "timestamp": Uint64 }            ← queued, retry
//   { "status": "not_found" }                                  ← not on network
//
// Uses HTTP/1.1 keep-alive to reduce TCP handshake overhead.
// Non-blocking reconnect with configurable retry interval.
// =============================================================================

class WiFiTransport {
public:

  // Async fetch status (fetch_transaction return value)
  enum FetchStatus {
    FETCH_DONE,       // "fetched" — data is in responseBuf
    FETCH_PENDING,    // "fetching" or "added" — retry later
    FETCH_NOT_FOUND,  // "not_found" — tx unknown to network
    FETCH_ERROR       // connection or parse error
  };

  WiFiTransport();

  // Connect to CKB light client node RPC endpoint (default port 9000)
  bool connect(const char* host, uint16_t port = 9000);

  // Check if TCP connection is alive
  bool isConnected();

  // Raw JSON-RPC call. Sends method + params, receives JSON body into responseBuf.
  // params:          JSON array string, e.g. "[]" or "[\"0x1\"]"
  // Returns bytes written to responseBuf, or -1 on error.
  int request(
    const char* method,
    const char* params,
    char*       responseBuf,
    size_t      responseBufSize,
    uint32_t    timeoutMs = 5000
  );

  // set_scripts: register a lock script with the light client.
  // codeHashHex:  "0x" + 64 hex chars (e.g. secp256k1: 0x9bd7e06f...)
  // hashType:     "type" or "data"
  // argsHex:      "0x" + hex-encoded lock args (e.g. 20-byte pubkey hash)
  // blockNumber:  filter start — light client won't report TXs before this
  // Uses "partial" command — adds without replacing existing scripts.
  bool setScripts(const char* codeHashHex, const char* hashType,
                  const char* argsHex, uint64_t blockNumber = 0);

  // get_tip_header: fills *blockNumber with current chain tip.
  bool getTipHeader(uint64_t* blockNumber);

  // fetch_transaction: async fetch via P2P network.
  // On FETCH_DONE, responseBuf contains the TransactionWithStatus JSON.
  // On FETCH_PENDING, retry after a short delay.
  FetchStatus fetchTransaction(const char* txHashHex,
                               char* responseBuf, size_t responseBufSize);

  // get_peers: returns number of connected peers, or -1 on error.
  // peer count == 0 means not syncing — useful for health checks.
  int getPeerCount();

  // Disconnect and free TCP resources
  void disconnect();

  // Last error string (for debugging)
  const char* lastError() const { return _lastError; }

private:
  WiFiClient  _client;
  char        _host[64];
  uint16_t    _port;
  char        _lastError[64];
  uint32_t    _reqId;

  bool _reconnect();
  int  _buildRequest(const char* method, const char* params,
                     char* out, size_t outSize);

#ifdef HOST_TEST
public:
  // Test hook: preload a canned HTTP response into _client
  void _testLoad(const char* s) { _client.load(s); }
  // Test hook: expose _buildRequest for inspection
  int  _testBuildRequest(const char* m, const char* p, char* o, size_t n) {
    return _buildRequest(m, p, o, n);
  }
#endif
};
