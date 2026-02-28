#pragma once

// =============================================================================
// LightConfig.h — Build profile selector for ckb-light-esp
//
// Select ONE profile before #include "LightClient.h":
//
//   #define LIGHT_PROFILE_MINIMAL    // ESP32-C6: header sync + address watch
//   #define LIGHT_PROFILE_STANDARD   // ESP32-S3: + Merkle proofs + UTXO store
//   #define LIGHT_PROFILE_FULL       // ESP32-P4: + CKB-VM interpreter
//   #define LIGHT_PROFILE_LORA       // Any: WiFi replaced by LoRa transport
//
// Fine-grained overrides (after profile selection):
//   #define LIGHT_NO_MERKLE          // disable Merkle proof verification
//   #define LIGHT_NO_UTXO_STORE      // disable persistent UTXO storage
//   #define LIGHT_WITH_VM            // force-enable CKB-VM (needs PSRAM)
//   #define LIGHT_WITH_LORA          // add LoRa transport alongside WiFi
//   #define LIGHT_WITH_CELLULAR      // add cellular transport
// =============================================================================

// --- Profile defaults --------------------------------------------------------

#if defined(LIGHT_PROFILE_MINIMAL)
  // ESP32-C6 / ESP32 classic: header chain only, watch one address
  #define LIGHT_MAX_WATCHED_SCRIPTS  2
  #define LIGHT_HEADER_CACHE_SIZE    10
  #define LIGHT_JSON_BUFFER_SIZE     4096
  // No Merkle, no UTXO store, no VM
  #define LIGHT_NO_MERKLE
  #define LIGHT_NO_UTXO_STORE
  #define LIGHT_TRANSPORT_WIFI

#elif defined(LIGHT_PROFILE_STANDARD)
  // ESP32-S3 (with PSRAM): full light client minus VM
  #define LIGHT_MAX_WATCHED_SCRIPTS  16
  #define LIGHT_HEADER_CACHE_SIZE    50
  #define LIGHT_JSON_BUFFER_SIZE     16384
  #define LIGHT_TRANSPORT_WIFI

#elif defined(LIGHT_PROFILE_FULL)
  // ESP32-P4: everything on
  #define LIGHT_MAX_WATCHED_SCRIPTS  32
  #define LIGHT_HEADER_CACHE_SIZE    100
  #define LIGHT_JSON_BUFFER_SIZE     32768
  #define LIGHT_WITH_VM
  #define LIGHT_TRANSPORT_WIFI

#elif defined(LIGHT_PROFILE_LORA)
  // LoRa transport — minimal footprint, no WiFi dependency
  #define LIGHT_MAX_WATCHED_SCRIPTS  2
  #define LIGHT_HEADER_CACHE_SIZE    10
  #define LIGHT_JSON_BUFFER_SIZE     4096
  #define LIGHT_NO_MERKLE
  #define LIGHT_NO_UTXO_STORE
  #define LIGHT_TRANSPORT_LORA

#else
  // Default: STANDARD
  #define LIGHT_PROFILE_STANDARD
  #define LIGHT_MAX_WATCHED_SCRIPTS  16
  #define LIGHT_HEADER_CACHE_SIZE    50
  #define LIGHT_JSON_BUFFER_SIZE     16384
  #define LIGHT_TRANSPORT_WIFI
#endif

// --- Sanity checks -----------------------------------------------------------

#if defined(LIGHT_WITH_VM) && !defined(BOARD_HAS_PSRAM)
  #warning "LIGHT_WITH_VM requires PSRAM. Make sure your board has it (ESP32-S3/P4)."
#endif

#if defined(LIGHT_TRANSPORT_LORA) && defined(LIGHT_TRANSPORT_WIFI)
  #error "Cannot enable both LIGHT_TRANSPORT_LORA and LIGHT_TRANSPORT_WIFI in the same build."
#endif
