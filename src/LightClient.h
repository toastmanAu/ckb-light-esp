#pragma once

// =============================================================================
// LightClient.h — Main entry point for ckb-light-esp
//
// Usage:
//   #define LIGHT_PROFILE_STANDARD
//   #include "LightClient.h"
//
//   LightClient client;
//
//   void setup() {
//     client.begin("node-host", 8116);
//     client.watchScript("0x...", "0x...", SCRIPT_TYPE_LOCK);
//   }
//
//   void loop() {
//     client.sync();   // call regularly — non-blocking state machine
//   }
// =============================================================================

#include "LightConfig.h"
#include "core/header_chain.h"
#include "core/merkle.h"
#include "core/block_filter.h"

#ifndef LIGHT_NO_UTXO_STORE
  #include "core/utxo_store.h"
#endif

#ifdef LIGHT_TRANSPORT_WIFI
  #include "transport/wifi_transport.h"
#endif

#ifdef LIGHT_TRANSPORT_LORA
  #include "transport/lora_transport.h"
#endif

#ifdef LIGHT_TRANSPORT_LORAWAN
  #include "transport/lorawan_transport.h"
#endif

#ifdef LIGHT_WITH_VM
  #include "vm/ckbvm_interp.h"
#endif

// Script type constants
#define SCRIPT_TYPE_LOCK  0
#define SCRIPT_TYPE_TYPE  1

// Sync state machine states
typedef enum {
  LIGHT_STATE_IDLE,
  LIGHT_STATE_CONNECTING,
  LIGHT_STATE_SYNCING_HEADERS,
  LIGHT_STATE_SYNCING_FILTERS,
  LIGHT_STATE_READY,
  LIGHT_STATE_ERROR
} LightSyncState;

class LightClient {
public:
  LightClient();

  // Initialise with node endpoint
  bool begin(const char* host, uint16_t port = 8116);

  // Register a script to watch (code_hash + args + type)
  // Returns false if LIGHT_MAX_WATCHED_SCRIPTS exceeded
  bool watchScript(const char* codeHash, const char* args, uint8_t scriptType = SCRIPT_TYPE_LOCK);

  // Call from loop() — drives the sync state machine
  // Non-blocking: returns quickly, does one step per call
  void sync();

  // Current sync state
  LightSyncState state() const { return _state; }

  // Chain tip (latest verified header)
  uint64_t tipBlockNumber() const;
  const char* tipBlockHash() const;

  // Has a transaction been confirmed for any watched script?
  // Poll this after sync() returns LIGHT_STATE_READY
  bool hasPendingEvents() const;

  // Retrieve next pending event (tx hash + block number)
  // Returns false if no events queued
  bool nextEvent(char* txHashOut, uint64_t* blockNumOut);

  // Optional: verify tx inclusion via Merkle proof
  // (no-op if LIGHT_NO_MERKLE defined)
  bool verifyInclusion(const char* txHash, const char* blockHash);

private:
  LightSyncState _state;
  HeaderChain    _headers;
  BlockFilter    _filter;

#ifndef LIGHT_NO_UTXO_STORE
  UTXOStore      _utxos;
#endif

#ifdef LIGHT_TRANSPORT_WIFI
  WiFiTransport    _transport;
#endif

#ifdef LIGHT_TRANSPORT_LORA
  LoRaTransport    _transport;
#endif

#ifdef LIGHT_TRANSPORT_LORAWAN
  LoRaWANTransport _transport;
#endif

  char _watchedScripts[LIGHT_MAX_WATCHED_SCRIPTS][128];
  uint8_t _watchedTypes[LIGHT_MAX_WATCHED_SCRIPTS];
  uint8_t _watchedCount;

  void _stepConnect();
  void _stepSyncHeaders();
  void _stepSyncFilters();
};
