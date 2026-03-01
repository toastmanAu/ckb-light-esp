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
    header_chain.h/.cpp    ← header sync, Eaglesong PoW verify, chain tip ✅
    block_filter.h/.cpp    ← GCS filter sync + script hash matching
    merkle.h/.cpp          ← tx inclusion proof verification (Blake2b tree)
    utxo_store.h/.cpp      ← persistent UTXO set (NVS/LittleFS)

  transport/
    wifi_transport.h/.cpp  ← TCP JSON-RPC to CKB node
    lora_transport.h/.cpp  ← raw LoRa packet bridge (point-to-point, private gateway)
    lorawan_transport.h    ← LoRaWAN (OTAA, TTN/Chirpstack, public network)
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

| Profile | Target MCU | Transport | Features |
|---|---|---|---|
| `LIGHT_MINIMAL` | ESP32-C6 / ESP32 | WiFi | Header sync + address watch |
| `LIGHT_STANDARD` | ESP32-S3 (PSRAM) | WiFi | + Merkle proofs + UTXO store |
| `LIGHT_FULL` | ESP32-P4 | WiFi | + CKB-VM interpreter |
| `LIGHT_LORA` | Any ESP32 | Raw LoRa | Off-grid, private gateway |
| `LIGHT_LORAWAN` | TTGO T-Beam | LoRaWAN | TTN/Chirpstack, no gateway setup |

Fine-grained overrides:

```cpp
#define LIGHT_NO_MERKLE          // remove Merkle proof support
#define LIGHT_NO_UTXO_STORE      // remove persistent UTXO storage
#define LIGHT_WITH_VM            // force-enable CKB-VM
#define LIGHT_WITH_LORA          // add LoRa alongside WiFi
```

---

## LoRa transports

Two LoRa transport options, same `ITransport` interface:

**Raw LoRa** (`LIGHT_PROFILE_LORA`) — point-to-point, private gateway
- You control the protocol entirely, no duty cycle enforcement
- Best for: off-grid mining rig, shed ASIC ↔ Pi gateway on your property
- Hardware: TTGO T-Beam, Heltec LoRa 32, any ESP32 + SX1276/SX1262
- Companion: `ckb-lora-bridge` (Pi/server side, planned)

**LoRaWAN** (`LIGHT_PROFILE_LORAWAN`) — public/private network, OTAA join
- Joins TTN, Chirpstack, or any compliant NS — user needs no gateway
- Duty cycle managed by LMIC MAC layer
- Best for: shipping a product, existing LoRaWAN infrastructure
- Hardware: TTGO T-Beam (GPS + LoRa + 18650 — ideal standalone watcher)
- Requires: `MCCI LoRaWAN LMIC library`

```cpp
// Raw LoRa
#define LIGHT_PROFILE_LORA
#include <LightClient.h>
client.begin("192.168.1.100", 8116);  // via ckb-lora-bridge gateway

// LoRaWAN
#define LIGHT_PROFILE_LORAWAN
#include <LightClient.h>
LoRaWANOTAA creds = { DEV_EUI, APP_EUI, APP_KEY };
client.begin(creds, LORAWAN_SF9);     // joins TTN/Chirpstack, syncs via backend
```

---

## LoRa transport

The `LIGHT_PROFILE_LORA` build replaces WiFi with a LoRa radio bridge, enabling
light client sync from remote locations with no internet access — up to 15–40km
line-of-sight. Requires a paired gateway running `ckb-lora-bridge` (companion repo, planned).

Uses [RadioLib](https://github.com/jgromes/RadioLib) — supports SX1276, SX1278, SX1262.

---

## Status

**v0.2 — fully implemented, 206/206 host tests passing.**

All modules implemented, host-tested, and verified against Nervos mainnet.

- [x] Library structure + build profiles
- [x] `header_chain` — Eaglesong PoW verify, parent linkage, 6/6 tests
- [x] `merkle` — CBMT verify + transactions_root merge, 11/11 tests
- [x] `block_filter` — GCS filter sync + script hash matching, 27/27 tests
- [x] `wifi_transport` — HTTP/1.1 keep-alive, chunked parsing, full RPC, 30/30 tests
- [x] `LightClient` — sync state machine (IDLE→CONNECTING→SYNCING→WATCHING), 25/25 tests
- [x] `native_locks` — secp256k1/multisig/ACP without VM, 37/37 tests
- [x] `ckbvm_interp` — RV64IMC interpreter, ELF64 loader, 7 syscalls, 24/24 tests
- [x] `lora_transport` — binary framing, fragmentation, ACK/NACK, 17/17 tests
- [x] Host test suite — `bash test/run_tests.sh` — 206 tests, ~9s on aarch64
- [ ] Hardware integration tests (needs LoRa radio + CKB node)
- [ ] First LoRa field test with `ckb-lora-bridge`

### Host test suite

```bash
cd ckb-light-esp
bash test/run_tests.sh
# → 206/206 passing
```

No Arduino SDK required — runs on bare Linux (aarch64/x86_64) via POSIX sockets.

---

Part of the [Wyltek embedded stack](https://wyltekindustries.com).
