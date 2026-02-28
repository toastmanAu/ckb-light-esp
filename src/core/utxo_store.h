#pragma once
#include <stdint.h>
#include <stdbool.h>

// =============================================================================
// utxo_store.h — Persistent UTXO set for watched addresses
//
// Stores live cells (UTXOs) for watched scripts in NVS (ESP32 non-volatile
// storage) or LittleFS depending on available flash. Survives reboots.
//
// Disabled at compile time if LIGHT_NO_UTXO_STORE is defined.
// =============================================================================

#ifndef LIGHT_NO_UTXO_STORE

#define UTXO_MAX_PER_SCRIPT   32     // max UTXOs tracked per watched script
#define UTXO_OUT_POINT_LEN    36     // 32-byte tx hash + 4-byte index

typedef struct {
  uint8_t  outPoint[UTXO_OUT_POINT_LEN];   // tx_hash || index (big-endian)
  uint64_t capacity;                        // in shannons
  uint64_t blockNumber;                     // block where this UTXO appeared
  bool     spent;
} UTXO;

typedef struct {
  uint8_t  scriptHash[32];
  UTXO     utxos[UTXO_MAX_PER_SCRIPT];
  uint8_t  count;
  uint64_t balance;    // sum of unspent capacities (shannons)
} ScriptUTXOs;

class UTXOStore {
public:
  UTXOStore();

  // Initialise storage backend (NVS or LittleFS)
  bool begin(const char* namespace_ = "ckb_utxo");

  // Add a UTXO for a watched script
  bool addUTXO(const uint8_t* scriptHash32, const UTXO& utxo);

  // Mark a UTXO as spent
  bool markSpent(const uint8_t* txHash32, uint32_t index);

  // Get balance in shannons for a script hash
  uint64_t getBalance(const uint8_t* scriptHash32) const;

  // Get balance in CKB (shannons / 1e8)
  float getBalanceCKB(const uint8_t* scriptHash32) const;

  // Iterate UTXOs for a script
  bool getUTXOs(const uint8_t* scriptHash32, ScriptUTXOs& out) const;

  // Persist current state to flash
  bool save();

  // Load state from flash
  bool load();

  // Wipe stored state
  void reset();

private:
  ScriptUTXOs _store[LIGHT_MAX_WATCHED_SCRIPTS];
  uint8_t     _count;
  const char* _namespace;

  int _findScript(const uint8_t* scriptHash32) const;
};

#endif // LIGHT_NO_UTXO_STORE
