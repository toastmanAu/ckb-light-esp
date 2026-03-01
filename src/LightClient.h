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
// Order matches RFC 045 client operation requirements:
//   1. Connect + register scripts
//   2. SYNCING_CHECKPOINTS — fetch filter hash checkpoints (every 2000 blocks)
//   3. SYNCING_HASHES      — fetch per-block filter hashes between checkpoints
//   4. SYNCING_FILTERS     — fetch + test actual GCS filters against scripts
//   5. WATCHING            — tip in sync, polling for new blocks
typedef enum {
  LIGHT_STATE_IDLE,
  LIGHT_STATE_CONNECTING,
  LIGHT_STATE_SYNCING_CHECKPOINTS,
  LIGHT_STATE_SYNCING_HASHES,
  LIGHT_STATE_SYNCING_FILTERS,
  LIGHT_STATE_WATCHING,
  LIGHT_STATE_ERROR
} LightSyncState;

class LightClient {
public:
  LightClient();

  // Initialise with node endpoint
  bool begin(const char* host, uint16_t port = 8116);

  // Register a script to watch (code_hash + args + type)
  // Returns false if LIGHT_MAX_WATCHED_SCRIPTS exceeded
  bool watchScript(const char* codeHash, const char* args,
                   uint8_t scriptType = SCRIPT_TYPE_LOCK,
                   uint64_t startBlock = 0);

  // Call from loop() — drives the sync state machine
  // Non-blocking: returns quickly, does one step per call
  void sync();

  // Current sync state
  LightSyncState state() const { return _state; }
  const char* stateStr() const;

  // Chain tip (latest verified header from node)
  uint64_t tipBlockNumber() const { return _tipBlockNumber; }
  const char* tipBlockHash() const { return _tipBlockHash; }

  // Filter sync progress (0 when not yet syncing)
  uint64_t filterSyncBlock() const { return _filterSyncBlock; }

  // Has a transaction been confirmed for any watched script?
  bool hasPendingEvents() const;

  // Pop next pending event. Returns false if none queued.
  bool nextEvent(char* txHashOut, uint64_t* blockNumOut);

  // Peer count from node (0 = node not synced, -1 = error)
  int peerCount() const { return _peerCount; }

  // Get balance (shannons) for a watched lock script by code_hash + args.
  // Calls get_cells_capacity on the light node — instant, no filter sync needed.
  // Returns false on error; *outShannons set to 0 on failure.
  bool getBalance(const char* codeHash, const char* args,
                  uint64_t* outShannons,
                  const char* hashType = "type");

  // Get balance for a full CKB bech32 address string (ckb1q...).
  // Decodes address to lock script internally, then calls get_cells_capacity.
  bool getBalance(const char* ckbAddress, uint64_t* outShannons);

  // Format shannons as a CKB string with decimal (e.g. "142.5 CKB").
  // Writes to buf, returns buf. Safe for use in Serial.print / display.
  static char* formatCKB(uint64_t shannons, char* buf, size_t bufSize);

private:
  LightSyncState _state;
  HeaderChain    _headers;
  BlockFilter    _filter;

#ifndef LIGHT_NO_UTXO_STORE
  UTXOStore      _utxos;
#endif

#ifdef LIGHT_TRANSPORT_WIFI
  WiFiTransport  _transport;
#endif
#ifdef LIGHT_TRANSPORT_LORA
  LoRaTransport  _transport;
#endif
#ifdef LIGHT_TRANSPORT_LORAWAN
  LoRaWANTransport _transport;
#endif

  // Watched script registration (raw strings for set_scripts RPC)
  char    _watchCodeHash[LIGHT_MAX_WATCHED_SCRIPTS][67]; // "0x" + 64 + null
  char    _watchArgs[LIGHT_MAX_WATCHED_SCRIPTS][128];
  uint8_t _watchType[LIGHT_MAX_WATCHED_SCRIPTS];         // SCRIPT_TYPE_LOCK/TYPE
  uint64_t _watchStartBlock[LIGHT_MAX_WATCHED_SCRIPTS];
  uint8_t _watchedCount;

  // Node endpoint
  char     _host[64];
  uint16_t _port;

  // Tip state
  uint64_t _tipBlockNumber;
  char     _tipBlockHash[67];

  // Filter sync cursor
  uint64_t _filterSyncBlock;   // next block to fetch filter for
  uint64_t _lastAskMs;         // millis() of last filter request (anti-spam)

  // Peer count (cached from last check)
  int _peerCount;

  // Shared JSON response buffer
  char _jsonBuf[LIGHT_JSON_BUFFER_SIZE];

  // State steps
  void _stepConnect();
  void _stepSyncCheckpoints();
  void _stepSyncHashes();
  void _stepSyncFilters();
  void _stepWatching();

  // Helpers
  bool _registerScripts();
  bool _updateTip();
  bool _processMatchedBlock(uint64_t blockNumber);
  void _applyFilter(const char* filterHex, uint64_t blockNumber);

  // millis() shim (host-test safe)
  static uint32_t _ms();

#ifdef HOST_TEST
public:
  BlockFilter&   _filterRef()    { return _filter; }
  WiFiTransport& _transportRef() { return _transport; }
  void           _applyFilterPub(const char* h, uint64_t b) { _applyFilter(h, b); }
private:
#endif
};
