# ROADMAP.md — ckb-light-esp

> First C/Arduino implementation of the CKB light client protocol.
> Watch any CKB address from ESP32 hardware. No cloud. No custodian.

---

## Vision

A complete, modular CKB light client stack for embedded hardware — from a $3 ESP32-C6 watching a single address, to a full ESP32-P4 node with RISC-V script execution and off-grid LoRa sync.

The end goal: `#include <LightClient.h>` and you're on the CKB network.

---

## The Stack

```
wyltek-embedded-builder   ← board targets + peripheral defines
CKB-ESP32                 ← crypto + tx library
ckb-light-esp             ← light client node  ← this repo
ckb-lora-bridge           ← Pi/server gateway for LoRa transport (planned)
```

---

## Status

### ✅ Phase 1 — Core verification (complete)

- [x] `header_chain.cpp` — Eaglesong PoW, Molecule serialisation, block hash
- [x] `merkle.cpp` — CBMT proof verification, transactions_root, witnesses_root
- [x] Build profiles: MINIMAL / STANDARD / FULL / LORA / LORAWAN
- [x] Transport stubs: WiFi, raw LoRa, LoRaWAN, cellular
- [x] Host test suite — all verified against mainnet

### 🔧 Phase 2 — Transport + sync loop (in progress)

- [ ] `wifi_transport.cpp` — TCP JSON-RPC to CKB light client node (port 9000)
- [ ] `LightClient.cpp` — sync state machine (connect → headers → filters → ready)
- [ ] `block_filter.cpp` — GCS filter sync, SipHash-2-4, checkpoint-based initial sync
- [ ] `utxo_store.cpp` — persistent UTXO set (NVS/LittleFS)

### 📋 Phase 3 — Script execution (planned)

- [ ] `native_locks.cpp` — secp256k1 / multisig / ACP without VM
- [ ] `ckbvm_interp.cpp` — minimal RISC-V interpreter (ESP32-P4 / S3 with PSRAM)

### 📡 Phase 4 — Off-grid transports (planned)

- [ ] `lora_transport.cpp` — raw LoRa bridge implementation
- [ ] `lorawan_transport.cpp` — LoRaWAN OTAA + LMIC (TTGO T-Beam)
- [ ] `ckb-lora-bridge` — companion repo: Pi/N100 gateway → CKB node RPC
- [ ] `cellular_transport.cpp` — SIM7080G / A7670 (NB-IoT / LTE-M)

### 🛍️ Phase 5 — Example products (planned)

- [ ] **CKB Payment Terminal** — ESP32 + display, generates QR invoices, confirms on-chain
- [ ] **Off-grid Balance Checker** — T-Beam, LoRaWAN, e-paper display, battery powered
- [ ] **LoRa ASIC Relay** — Stratum bridge for mining rigs with no direct internet
- [ ] **IoT Payment Trigger** — C6, one address, fires GPIO on receive (door unlock, vending, etc.)

---

## Architecture Notes

### Backend requirement

The WiFi transport talks to the **CKB light client node** RPC (port 9000), not a full node (port 8114). The light client node handles P2P filter sync; our ESP just talks to its HTTP API.

Run the Rust light client: `github.com/nervosnetwork/ckb-light-client`

### Key implementation facts

Discovered during development — things that will trip up anyone implementing from spec alone:

| Fact | Detail |
|---|---|
| Molecule encoding | `RawHeader` is a `struct` (not `table`) — 192 bytes flat, no header |
| Nonce byte order | RPC nonce = `u128` big-endian hex → reverse 16 bytes for Eaglesong |
| Eaglesong output | Big-endian bytes — compare `result[0]` first (not LE) |
| transactions_root | `merge(txs_CBMT_root, witnesses_root)` — NOT just tx hashes |
| RPC proof field | Called `lemmas` in CKB RPC (not `siblings` as in RFC 0006) |
| GCS hash function | SipHash-2-4 (not Blake2b) — constants M, P from `golomb_coded_set` |
| Filter checkpoint | Download checkpoints first, then filters from script's `block_number` onward |

### Transport comparison

| Transport | Use case | Latency | Range | Setup |
|---|---|---|---|---|
| WiFi | Home / office | ~10ms | LAN/internet | Direct to light client node |
| Raw LoRa | Off-grid, private | ~100–500ms | 5–40km LOS | Your own gateway required |
| LoRaWAN | Shipped product | ~2–5s | Existing network | TTN/Chirpstack account |
| Cellular | Remote, no LoRa | ~50–200ms | Global | SIM + data plan |

---

## Board Targets

| Board | Profile | RAM | Notes |
|---|---|---|---|
| ESP32-C6 | MINIMAL | 512KB | Address watch, GPIO trigger |
| ESP32 classic | MINIMAL | 520KB | WiFi only, tight on RAM |
| ESP32-S3 + PSRAM | STANDARD | 8MB+ | Full client, recommended |
| ESP32-P4 | FULL | 32MB PSRAM | + CKB-VM, ideal platform |
| TTGO T-Beam | LORAWAN | 4MB | GPS + LoRa + 18650, standalone |
| Heltec LoRa 32 | LORA | 4MB | Raw LoRa, compact |

---

## Contributing

This is part of the [Wyltek embedded stack](https://wyltekindustries.com).

If you're working with CKB and embedded hardware, contributions welcome — especially:
- GCS filter implementation (block_filter.cpp)
- Board-specific test reports
- Example product sketches
