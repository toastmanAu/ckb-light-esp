#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <WiFi.h>
#include <WiFiClient.h>

// =============================================================================
// wifi_transport.h — WiFi TCP transport to CKB light/full node RPC
//
// Handles connection, reconnection, and JSON-RPC request/response.
// Uses HTTP/1.1 keep-alive where possible to reduce handshake overhead.
// =============================================================================

class WiFiTransport {
public:
  WiFiTransport();

  // Connect to node RPC endpoint
  bool connect(const char* host, uint16_t port);

  // Check if connected
  bool isConnected();

  // Send a JSON-RPC request, receive response into buffer
  // Returns number of bytes written to responseBuf, or -1 on error
  int request(
    const char* method,
    const char* params,       // JSON array string, e.g. "[]" or "[\"0x1\"]"
    char*       responseBuf,
    size_t      responseBufSize,
    uint32_t    timeoutMs = 5000
  );

  // Disconnect
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
