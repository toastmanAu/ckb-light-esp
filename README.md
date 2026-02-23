# CKB Light Client — ESP32-P4

A from-scratch C implementation of the CKB light client protocol (RFC 0044),
targeting the ESP32-P4 with external PSRAM. Also builds as a POSIX library
for host-side testing on Linux/macOS.

## Architecture

```
ckb-light-esp/
├── components/
│   └── ckb_core/              ← Core library (ESP-IDF component, also POSIX)
│       ├── include/
│       │   ├── ckb_blake2b.h  ← Blake2b hash (RFC 7693)
│       │   ├── ckb_molecule.h ← Molecule serialisation codec
│       │   ├── ckb_mmr.h      ← Merkle Mountain Range + proof verifier
│       │   ├── ckb_types.h    ← CKB data structures
│       │   └── ckb_address.h  ← CKB address encode/decode
│       └── src/
│           ├── ckb_blake2b.c
│           ├── ckb_molecule.c
│           ├── ckb_mmr.c
│           └── ckb_address.c
├── test_host/                 ← POSIX test harness (runs on N100/Pi)
│   ├── Makefile
│   └── test_*.c
├── main/                      ← ESP-IDF app entry (future)
└── CMakeLists.txt
```

## Phase 1 — Core Crypto & Serialisation (this branch)
- [x] Blake2b (Blake2b-256 and Blake2b-512)
- [ ] Molecule codec (CKB header, script, transaction types)
- [ ] MMR proof verifier (FlyClient)
- [ ] CKB address derivation (secp256k1 lock)

## Phase 2 — Transport (planned)
- Noise protocol handshake (X25519 + ChaCha20-Poly1305)
- Yamux stream multiplexer
- Tentacle frame codec

## Phase 3 — Light Client Protocol (planned)
- RFC 0044 message types
- FlyClient block sampling
- Script/address watching

## Building (host)
```bash
cd test_host
make
./test_blake2b
./test_mmr
```

## Building (ESP-IDF)
```bash
idf.py set-target esp32p4
idf.py build
idf.py flash monitor
```

## References
- [RFC 0044 — CKB Light Client Protocol](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0044-ckb-light-client/0044-ckb-light-client.md)
- [CKB Blake2b spec](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md)
- [Molecule spec](https://github.com/nervosnetwork/molecule)
- [Tentacle P2P](https://github.com/nervosnetwork/tentacle)
