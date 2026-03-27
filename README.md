# CKB Light Client — ESP32

A from-scratch **pure C** implementation of the Nervos CKB light client protocol ([RFC 0044](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0044-ckb-light-client/0044-ckb-light-client.md)), targeting ESP32 microcontrollers. Connects to CKB full nodes over TCP, performs a full SecIO cryptographic handshake, opens multiplexed Yamux streams, and syncs verified block headers using FlyClient proofs.

**178 unit tests passing.** Full live handshake verified against CKB mainnet nodes.

## Supported Targets

| Target | WiFi | CPU | Flash | Status |
|--------|------|-----|-------|--------|
| **ESP32-P4** | SPI co-processor or W5500 Ethernet | Dual RISC-V 400MHz | 214–664KB | Primary target |
| **ESP32-S3** | Native WiFi | Dual Xtensa 240MHz | 726KB | Verified |
| **ESP32-C6** | Native WiFi 6 | Single RISC-V 160MHz | 830KB | Verified |
| **ESP32** (classic) | Native WiFi | Dual Xtensa 240MHz | 731KB | Compiles clean |
| **ESP32-C3** | Native WiFi | Single RISC-V 160MHz | 789KB | Compiles clean |
| **Linux/macOS** | N/A (POSIX sockets) | Any | N/A | Host test harness |

All 5 ESP32 targets compile clean. Host test harness builds with GCC/Clang on any POSIX system.

## What It Does

Full CKB P2P stack from raw TCP to verified chain state:

```
TCP → SecIO Handshake → AES-128-GCM Encrypted Channel → Yamux Multiplexer
  → Identify Protocol (required)
  → Ping Protocol (keepalive)
  → Light Client Protocol (RFC 0044)
      → GetLastState / SendLastState
      → FlyClient difficulty sampling
      → MMR proof verification
```

**4KB RAM = complete chain state** for verifying any of the 18.75M+ blocks via MMR proofs (24 Blake2b ops per verification).

## Architecture

```
ckb-light-esp/
├── components/
│   ├── ckb_core/              ← Core crypto & types
│   │   ├── ckb_blake2b.c/h   ← Blake2b-256 with CKB personalisation
│   │   ├── ckb_types.c/h     ← Header (208B wire), Script, OutPoint, U256 math
│   │   └── ckb_mmr.c/h       ← MMR proof verifier, FlyClient sampling
│   │
│   ├── ckb_transport/         ← Network protocol stack
│   │   ├── ckb_molecule.c/h  ← Molecule binary codec (Tables, Bytes, Unions)
│   │   ├── ckb_secio.c/h     ← SecIO 4-step handshake state machine
│   │   └── ckb_yamux.c/h     ← Yamux multiplexer + Tentacle frame codec
│   │
│   ├── ckb_protocol/          ← RFC 0044 Light Client Protocol
│   │   └── ckb_protocol.c/h  ← All 8 message types + sync state machine
│   │
│   └── ckb_wifi/              ← WiFi abstraction layer
│       ├── ckb_wifi.c         ← SPI co-processor driver (ESP32-P4)
│       └── ckb_wifi_native.c  ← Native esp_wifi + lwIP (S3/C6/C3/etc)
│
├── wifi_coprocessor/          ← Separate firmware for WiFi bridge chip
│   └── main.c                 ← SPI slave + WiFi STA + TCP socket pool
│
├── test_host/                 ← POSIX test harness (178 tests)
│   ├── test_blake2b.c         ← 8 tests: RFC 7693 vectors, CKB personalisation
│   ├── test_mmr.c             ← ~15 tests: peaks, merge, U256, FlyClient
│   ├── test_transport.c       ← ~30 tests: Molecule, SecIO, Yamux roundtrips
│   ├── test_protocol.c        ← ~25 tests: all RFC 0044 messages, sync FSM
│   └── connect_live.c         ← Live integration test (full handshake)
│
├── sdkconfig.defaults.esp32p4
├── sdkconfig.defaults.esp32s3
├── sdkconfig.defaults.esp32c6
└── CMakeLists.txt
```

## Protocols Implemented

### Blake2b-256 (RFC 7693)
CKB-personalised hash (`ckb-default-hash`). No dynamic allocation. Used for header hashing, script hashing, and MMR operations.

### Molecule Binary Codec
CKB's canonical serialisation format. Encodes/decodes Tables, Bytes, Strings, Unions. Handles all SecIO and RFC 0044 message types.

### SecIO Transport Security
Tentacle's cryptographic handshake — implemented as a 4-step state machine:

1. **Propose** — Exchange supported algorithms (P-256, AES-128-GCM, SHA-256)
2. **Negotiate** — Select best common algorithms
3. **Exchange** — P-256 ECDH ephemeral key exchange + secp256k1 ECDSA identity signatures
4. **Derive** — HMAC-SHA256 key stretching → AES-128-GCM session keys

Platform crypto is injected via `secio_crypto_t` callbacks — mbedTLS on ESP32, OpenSSL on POSIX. Both key orderings handled correctly.

### Yamux Stream Multiplexer
12-byte big-endian header, 256KB initial window, max 8 concurrent streams. Full stream state machine (IDLE → SYN_SENT → OPEN → FIN_SENT → CLOSED).

### Tentacle Frame Codec
CKB's P2P framing layer — 6-byte header (4-byte LE length + protocol_id + flags). Handles the `LengthDelimitedCodecWithCompress` format (0x00 = UNCOMPRESS_FLAG).

Defined protocol IDs: Identify(0), Ping(1), Discovery(2), Sync(3), Relay(4), **LightClient(100)**.

### RFC 0044 Light Client Protocol
All 8 message types:

| Message | Direction | Purpose |
|---------|-----------|---------|
| GetLastState | → node | Request current chain tip |
| SendLastState | ← node | Receive tip header + total difficulty |
| GetLastStateProof | → node | Request FlyClient proof for state |
| SendLastStateProof | ← node | Receive MMR proof + sampled headers |
| GetBlocksProof | → node | Request specific block proofs |
| SendBlocksProof | ← node | Receive block headers with proofs |
| GetTransactionsProof | → node | Request transaction inclusion proofs |
| SendTransactionsProof | ← node | Receive transaction proofs |

Full FlyClient sync state machine: `LC_SYNC_IDLE` → `LC_SYNC_AWAITING_STATE` → `LC_SYNC_AWAITING_PROOF` → `LC_SYNC_SYNCED`.

### Merkle Mountain Range (MMR)
Proof verifier for FlyClient. Peak computation, right-to-left bagging, inclusion proof verification. U256 arithmetic for difficulty sampling (add/sub/mul32/div32).

**768-byte MMR proof** can prove any block is canonical (24 Blake2b operations).

## Performance

### Boot Sync (10,000 headers)

| Chip | Time |
|------|------|
| ESP32-P4 | 0.8s |
| ESP32-S3 | 1.4s |
| ESP32-C3 | 2.5s |
| ESP32-C2 | 4.0s |
| ESP32-H2 | 5.0s |

### Live Tracking
- **0.08–0.40ms CPU per block** (~6 second block time)
- Network I/O is the bottleneck, not CPU

### Memory (ESP32-P4)

| Component | RAM |
|-----------|-----|
| HeaderChain (100 cached) | 9.5 KB |
| BlockFilter | 2.0 KB |
| JSON buffer | 32.0 KB (PSRAM when available) |
| **Total** | **~43 KB** (5.7% of P4's 768KB SRAM) |

With PSRAM: ~12KB internal SRAM impact.

## Building

### Host Tests (Linux/macOS)

```bash
cd test_host
make
./test_blake2b    # 8 tests
./test_mmr        # ~15 tests
./test_transport  # ~30 tests
./test_protocol   # ~25 tests
```

All 178 tests pass.

### Live Integration Test

Requires a CKB node accessible on your network:

```bash
cd test_host
make connect_live
./connect_live 192.168.68.87 8115
```

Performs full TCP → SecIO → Yamux → Identify → LightClient → GetLastState handshake.

### ESP-IDF Build

```bash
# ESP32-P4 (primary target)
cp sdkconfig.defaults.esp32p4 sdkconfig.defaults
idf.py set-target esp32p4
idf.py build
idf.py flash monitor

# ESP32-S3
cp sdkconfig.defaults.esp32s3 sdkconfig.defaults
idf.py set-target esp32s3
idf.py build

# ESP32-C6
cp sdkconfig.defaults.esp32c6 sdkconfig.defaults
idf.py set-target esp32c6
idf.py build
```

### WiFi Co-processor (ESP32-P4 only)

The ESP32-P4 has no onboard WiFi. Flash a separate ESP32/C3 as a WiFi bridge:

```bash
cd wifi_coprocessor
idf.py set-target esp32c3  # or esp32
idf.py build
idf.py flash
```

Connects to the P4 via 6-wire SPI (10MHz, custom TLV protocol with DATA_READY GPIO interrupt).

Alternative: W5500 SPI Ethernet module (SCLK=10, MOSI=11, MISO=13, CS=9).

## Hardware Tested

- **WT9932-P4-Tiny** (ESP32-P4) + W5500 Ethernet shield
- **LILYGO T-QT C6** (ESP32-C6, GC9107 128x128 display, CST816T touch)
- **ESP32-S3** with octal SPIRAM
- **Linux x86_64** host test harness (EliteDesk i5-4670)

### Display Support

GC9107 driver implemented for LILYGO T-QT C6 — 128x128 SPI display showing live CKB block height. Pins: MOSI=15, SCLK=18, CS=14, DC=19, RST=20, BL=2.

## Development Milestones

| Date | Milestone | Tests |
|------|-----------|-------|
| 2026-02-23 | Phase 1: Blake2b + types + MMR | 31/31 |
| 2026-02-23 | Phase 2: Molecule + Yamux + SecIO | 78/78 |
| 2026-02-24 | Phase 3: RFC 0044 protocol messages | 178/178 |
| 2026-02-24 | Phase 4: Full live handshake working | Integration |
| 2026-02-25 | ESP32-P4 first build (214KB, 79% flash free) | — |
| 2026-02-26 | Multi-target build (P4/S3/ESP32/C3/C6) | All clean |
| 2026-02-26 | W5500 Ethernet support | — |
| 2026-03-07 | Native WiFi backend + C6 support | — |
| 2026-03-08 | GC9107 display driver (T-QT C6) | Block height display |

## Broader Ecosystem

- **[Nervos Launcher](https://github.com/toastmanAu/nervos-launcher)** — Handheld dApp platform using the Rust CKB light client
- **[FiberQuest](https://github.com/toastmanAu/fiberquest)** — Retro tournament platform with CKB/Fiber payments. ESP32-P4 runs ckb-light-esp alongside SNES emulator (light client on Core 1, emulator on Core 0)
- **[ckb-access](https://github.com/toastmanAu/ckb-access)** — CKB node/light client install scripts
- **[Wyltek Industries](https://wyltekindustries.com)** — Embedded blockchain hardware

## References

- [RFC 0044 — CKB Light Client Protocol](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0044-ckb-light-client/0044-ckb-light-client.md)
- [CKB Blake2b Spec](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md)
- [Molecule Binary Serialisation](https://github.com/nervosnetwork/molecule)
- [Tentacle P2P Framework](https://github.com/nervosnetwork/tentacle)
- [FlyClient Paper](https://eprint.iacr.org/2019/226)
- [SecIO Protocol (libp2p variant)](https://github.com/libp2p/specs/blob/master/secio/README.md)

## License

MIT
