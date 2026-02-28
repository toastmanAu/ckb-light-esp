#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <WiFi.h>
#include <WiFiClient.h>

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
// Light client RPC methods we use:
//   set_scripts      — register script hashes to watch
//   get_scripts      — query current watch list
//   get_tip_header   — latest known header
//   get_transaction  — fetch tx by hash (with proof)
//   send_transaction — broadcast a signed tx
//
// Uses HTTP/1.1 keep-alive to reduce TCP handshake overhead.
// Non-blocking reconnect with configurable retry interval.
// =============================================================================

class WiFiTransport {
public:
  WiFiTransport();

  // Connect to CKB light client node RPC endpoint (default port 9000)
  bool connect(const char* host, uint16_t port = 9000);

  // Check if TCP connection is alive
  bool isConnected();

  // Send a JSON-RPC request, receive response into caller-supplied buffer.
  // method:          e.g. "get_tip_header"
  // params:          JSON array string, e.g. "[]" or "[\"0x1\"]"
  // responseBuf:     caller-allocated output buffer
  // responseBufSize: size of responseBuf (must fit full HTTP response body)
  // timeoutMs:       read timeout (default 5s)
  // Returns: number of bytes written to responseBuf, or -1 on error.
  // On error, lastError() has a short description.
  int request(
    const char* method,
    const char* params,
    char*       responseBuf,
    size_t      responseBufSize,
    uint32_t    timeoutMs = 5000
  );

  // Convenience: set_scripts — register script hashes with the light client node.
  // scriptHashesHex: array of "0x..." hex strings (32-byte hashes)
  // count:           number of hashes
  // blockNumber:     filter start block (light client won't report TXs before this)
  // Returns true on RPC success.
  bool setScripts(const char** scriptHashesHex, uint8_t count, uint64_t blockNumber = 0);

  // Convenience: get_tip_header — fills blockNumber with current tip.
  bool getTipHeader(uint64_t* blockNumber);

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
};
