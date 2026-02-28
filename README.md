# ckb-light-esp

> A self-sovereign CKB light client node for ESP32 hardware.

No cloud relay. No trusted third party. The chip verifies the chain itself.

---

## What it does

Runs a CKB light client entirely on-device:

1. **Sync headers** — downloads block headers, verifies Eaglesong PoW and parent linkage
2. **Filter blocks** — uses GCS compact block filters to find transactions touching watched scripts
3. **Verify inclusion** — Merkle proof verification confirms tx is in a real block
4. **Track UTXOs** — persistent UTXO set for watched addresses (survives reboots)
5. **Execute scripts** — optional CKB-VM interpreter for custom lock validation (P4/S3 only)

---

## Hardware targets

| Board | Profile | Features |
|---|---|---|
| ESP32-C6 / ESP32 classic | `LIGHT_PROFILE_MINIMAL` | Header sync + address watch |
| ESP32-S3 (with PSRAM) | `LIGHT_PROFILE_STANDARD` | + Merkle proofs + UTXO store |
| ESP32-P4 | `LIGHT_PROFILE_FULL` | + CKB-VM interpreter |
| Any ESP32 + LoRa module | `LIGHT_PROFILE_LORA` | Off-grid sync via LoRa radio |

---

## Quick start

```cpp
#define LIGHT_PROFILE_STANDARD
#include <LightClient.h>

LightClient client;

void setup() {
  WiFi.begin("ssid", "pass");
  client.begin("192.168.1.100", 8116);  // your CKB node
  client.watchScript(
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
    "0xYOUR_LOCK_ARGS"
  );
}

void loop() {
  client.sync();

  if (client.hasPendingEvents()) {
    char txHash[67]; uint64_t block;
    while (client.nextEvent(txHash, &block)) {
      Serial.printf("TX at block #%llu: %s\n", block, txHash);
    }
  }
}
```

---

## Architecture

```
LightClient.h              ← main API
  LightConfig.h            ← build profiles + feature flags

  core/
    header_chain.h/.cpp    ← header sync, Eaglesong PoW verify, chain tip
    block_filter.h/.cpp    ← GCS filter sync + script hash matching
    merkle.h/.cpp          ← tx inclusion proof verification (Blake2b tree)
    utxo_store.h/.cpp      ← persistent UTXO set (NVS/LittleFS)

  transport/
    wifi_transport.h/.cpp  ← TCP JSON-RPC to CKB node
    lora_transport.h/.cpp  ← LoRa packet bridge (off-grid)
    cellular_transport.h   ← SIM7080G/A7670 (future)

  vm/
    native_locks.h/.cpp    ← fast native secp256k1/multisig/ACP verification
    ckbvm_interp.h/.cpp    ← full RISC-V interpreter (PSRAM required)
```

---

## Dependency on CKB-ESP32

This library uses [CKB-ESP32](https://github.com/toastmanAu/CKB-ESP32) for:
- Blake2b-256 (with CKB personalisation)
- secp256k1 signing primitives (trezor-crypto)
- Molecule serialisation helpers

It does **not** duplicate those — `CKB-ESP32` is a required `lib_dep`.

---

## Build profiles

Select one before your `#include`:

```cpp
#define LIGHT_PROFILE_MINIMAL    // ESP32-C6: headers + watch only (~100KB RAM)
#define LIGHT_PROFILE_STANDARD   // ESP32-S3: + Merkle + UTXO store (~300KB RAM)
#define LIGHT_PROFILE_FULL       // ESP32-P4: + CKB-VM (PSRAM required)
#define LIGHT_PROFILE_LORA       // Any: LoRa transport instead of WiFi
```

Fine-grained overrides:

```cpp
#define LIGHT_NO_MERKLE          // remove Merkle proof support
#define LIGHT_NO_UTXO_STORE      // remove persistent UTXO storage
#define LIGHT_WITH_VM            // force-enable CKB-VM
#define LIGHT_WITH_LORA          // add LoRa alongside WiFi
```

---

## LoRa transport

The `LIGHT_PROFILE_LORA` build replaces WiFi with a LoRa radio bridge, enabling
light client sync from remote locations with no internet access — up to 15–40km
line-of-sight. Requires a paired gateway running `ckb-lora-bridge` (companion repo, planned).

Uses [RadioLib](https://github.com/jgromes/RadioLib) — supports SX1276, SX1278, SX1262.

---

## Status

**v0.1 — headers and scaffolding complete. Implementations in progress.**

- [x] Library structure + build profiles
- [x] Header chain (interface)
- [x] GCS block filter (interface)
- [x] Merkle proof verification (interface)
- [x] UTXO store (interface)
- [x] WiFi transport (interface)
- [x] LoRa transport (interface)
- [x] Native lock verifiers (interface)
- [x] CKB-VM interpreter (interface)
- [ ] Implementations (in progress)
- [ ] Integration tests
- [ ] First mainnet verified tx

---

Part of the [Wyltek embedded stack](https://wyltekindustries.com).
