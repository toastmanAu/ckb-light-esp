# AGENTS.md — Development Policy for ckb-light-esp

This file defines how the AI agent (Kernel 🐧) operates on this repository.
It applies to all sessions working on `ckb-light-esp` and the broader Wyltek embedded stack.

---

## Core Principle

This repo is the **reference C implementation of the CKB light client protocol for embedded hardware**.
Every module built here must be correct first, then tested, then hardened — in that order.
The agent's job is to make the library better with each task, not just ship features.

---

## Library Hierarchy

When building anything, use the existing stack — don't reinvent:

```
wyltek-embedded-builder   ← board targets, peripheral defines
CKB-ESP32                 ← Blake2b, secp256k1, Molecule, transaction building
ckb-light-esp             ← light client sync, filter, transport  ← this repo
```

**Rule:** If a capability already exists in `CKB-ESP32` or `wyltek-embedded-builder`, use it.
Do not duplicate crypto primitives, board targets, or serialisation code.

---

## Fix Problems Upstream

If a bug or limitation is discovered in `CKB-ESP32` or `wyltek-embedded-builder` while
building something here:

1. Fix it in the **source library** — not with a workaround here
2. Push a commit to that repo with a clear message
3. Note the fix in the session memory and reference it in the `ckb-light-esp` commit

The test suite here is effectively an integration test for the whole stack.
Bugs found here are bugs in the stack — fix them at the root.

---

## Adding to CKB-ESP32

If a new CKB-related capability is needed that doesn't exist in `CKB-ESP32`:

- Add it to `CKB-ESP32` as a reusable component, not inline here
- Follow the existing header-only or minimal `.cpp` pattern
- Add a host test in `CKB-ESP32/test/` if possible
- Then use it from `ckb-light-esp` as a dependency

Examples of things that belong in `CKB-ESP32`:
- New lock script types (ACP, multisig, time-lock)
- Transaction building helpers
- New Molecule struct encoders
- Additional crypto primitives

Examples of things that belong here:
- Light client sync protocol (RFC 044/045)
- GCS filter matching
- Transport layers (WiFi, LoRa, LoRaWAN, cellular)
- State machine, UTXO store, event queue

---

## Test Policy

Every module must have a host test suite before it's considered done.

**Two build modes are required:**

| Mode | Flag | When to use |
|---|---|---|
| Stub | `-DHOST_TEST` | Unit tests, CI, fast iteration — no network needed |
| Live | `-DHOST_TEST -DLIVE_TEST` | Integration tests against devchain (192.168.68.93:8114) |

**Test suite must pass before any commit that touches logic.**
Helper infrastructure (`test/*.h`) is covered by `test/test_helpers.cpp`.

### Test infrastructure available

| File | Purpose |
|---|---|
| `test/wifi_client_stub.h` | Canned HTTP responses for stub mode |
| `test/posix_socket_client.h` | Real POSIX TCP for live mode |
| `test/ckb_rpc_fixtures.h` | Shared canned RPC JSON responses |
| `test/blake2b_real.h` | Real CKB Blake2b-256 (personalised) |
| `test/molecule_builder.h` | Molecule struct builder + script hash helpers |
| `src/core/ckb_hex.h` | Hex encode/decode, device-safe |
| `src/core/ckb_json.h` | Minimal JSON field extraction |

Use these. Do not copy-paste hex/JSON/Molecule logic into new test files.

---

## Hardening Signal

The test suite is the visible measure of library hardening.
As the library matures, the following should be observable:

- **Test count grows** — new modules add tests, edge cases get covered
- **Debug code shrinks** — temporary printf/dump helpers are removed after a module stabilises
- **Stub complexity shrinks** — fewer canned responses needed as real behaviour is verified live
- **Cross-module tests appear** — tests that exercise multiple modules together

If a new feature requires more than ~10 lines of one-off test scaffolding, that scaffolding
belongs in the shared helpers, not the test file.

---

## RFC Policy

Before implementing any CKB data structure or protocol behaviour:

1. Read the RFC
2. Follow reference implementation links in the RFC
3. Verify against a real mainnet block or the devchain before writing tests

Known relevant RFCs:
- [RFC 019](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0019-data-structures/) — Data structures (Molecule encoding)
- [RFC 044](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0044-ckb-light-client/) — Light client protocol (FlyClient/MMR)
- [RFC 045](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0045-ckb-light-client-block-filters/) — Block filter protocol (GCS/BIP157/158)

**Never guess at wire format.** The spec exists; use it.

---

## Commit Style

Commits must be self-contained and descriptive:

```
module: short summary

What changed and why. Include:
- Key implementation facts discovered (byte order, encoding quirks, etc.)
- Test results: N/N passing
- If fixing upstream: reference the source repo commit
```

---

## Devchain

OPi3B at `192.168.68.93:8114` — CKB full node, always-on dev target.
Start if down: `ssh opi3b-armbian 'bash ~/ckb-devchain/start.sh'`

Use for live integration tests. Not for production data.
Miner lock args: `0x72a4330a24e74209942062f24a2bbed8bd5f859a`

---

## Current Phase Status

| Phase | Status |
|---|---|
| 1 — Core verification (Eaglesong, Merkle, headers) | ✅ Complete |
| 2 — Transport + sync loop (WiFi, GCS, LightClient) | ✅ Complete |
| 3 — Script execution (native locks, CKB-VM interp) | 📋 Next |
| 4 — Off-grid transports (LoRa, LoRaWAN, cellular) | 📋 Planned |
| 5 — Example products (POS terminal, balance checker) | 📋 Planned |
