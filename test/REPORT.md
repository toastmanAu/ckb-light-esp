# ckb-light-esp — Test Report

| | |
|---|---|
| **Generated** | 2026-03-01 16:06:24 |
| **Platform** | `Linux 5.10.0-1012-rockchip aarch64` |
| **Compiler** | `g++ (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0` |
| **Commit** | `e983120` |
| **Total time** | 8920ms |

## Summary

✅ **All 206 tests passing**

| Suite | Passed | Failed | Time | Status |
|---|---:|---:|---:|---|
| `header_chain` | 6 | 0 | 561ms | 🟢 pass |
| `merkle` | 11 | 0 | 288ms | 🟢 pass |
| `block_filter` | 27 | 0 | 289ms | 🟢 pass |
| `wifi_transport` | 30 | 0 | 448ms | 🟢 pass |
| `light_client` | 25 | 0 | 518ms | 🟢 pass |
| `helpers` | 29 | 0 | 489ms | 🟢 pass |
| `native_locks` | 37 | 0 | 341ms | 🟢 pass |
| `ckbvm_interp` | 24 | 0 | 5608ms | 🟢 pass |
| `lora_transport` | 17 | 0 | 250ms | 🟢 pass |
| **TOTAL** | **206** | **0** | **8920ms** | ✅ **ALL PASS** |

## Per-Suite Details

### `header_chain`

**6 passed · 0 failed · 561ms**

**Sections:**
- block hash verification
- full PoW verification

<details>
<summary>Test cases (6)</summary>

- block_hash = Blake2b(struct || nonce_le)
- Eaglesong result <= compact_target
- Eaglesong self-test
- Molecule struct = 192 bytes
- nonce RPC → LE bytes
- pow_hash = Blake2b(Molecule struct)

</details>

### `merkle`

**11 passed · 0 failed · 288ms**

**Sections:**
- parseProof
- CBMT verify
- transactions_root
- full inclusion

<details>
<summary>Test cases (11)</summary>

- CBMT root correct
- CBMT verify succeeds
- parseProof depth = 2
- parseProof indices[0] = 5
- parseProof lemma[0] = T3
- parseProof lemma[1] = B1
- parseProof succeeds
- single-tx block inclusion
- transactions_root = merge(txsCBMTRoot, witnessesRoot)
- verifyInclusion (end-to-end)
- wrong txHash correctly rejected

</details>

### `block_filter`

**27 passed · 0 failed · 289ms**

**Sections:**
- [1] SipHash-2-4 (k0=0, k1=0)
- [2] GCS filter round-trip
- [3] BlockFilter API — addScriptHash + testFilter
- [4] Matched block queue
- [5] Event queue
- [6] minFilterBlockNumber
- [7] Devchain live filter test (requires 192.168.68.93:8114)

<details>
<summary>Test cases (27)</summary>

- addScriptHash returns true
- dequeue first = 42
- dequeue second = 100
- dequeue third = 999
- empty filter returns false for any query
- event 0 block = 500
- event 0 txHash prefix correct
- event 1 block = 501
- events empty after drain
- events empty on init
- events present after queue
- member 0x00*32 found
- member 0x11*32 found
- member 0x22*32 found
- member 0x33*32 found
- minFilterBlockNumber = 500 (earliest)
- no false positives in 10 non-member checks
- queue empty after drain
- queue empty on init
- queue has blocks after enqueue
- SipHash24([0,1,2], k=0) = 0x680fa79f0e7fdfe9
- SipHash24(0..31, 32 bytes) is deterministic
- SipHash24([0x00], k=0) = 0x8b5a0baa49fbc58d
- SipHash24("", k=0) = 0x1e924b9d737700d7
- testFilter matches at start block
- testFilter no match against empty filter
- testFilter skips blocks before script start

</details>

### `wifi_transport`

**30 passed · 0 failed · 448ms**

**Sections:**
- HTTP request building
- HTTP response parsing
- getTipHeader
- setScripts
- fetchTransaction status
- getPeerCount
- error handling

<details>
<summary>Test cases (30)</summary>

- added → FETCH_PENDING
- _buildRequest: Content-Type json
- _buildRequest: jsonrpc 2.0
- _buildRequest: keep-alive
- _buildRequest: method field
- _buildRequest: params field
- _buildRequest: positive length
- _buildRequest: POST / HTTP/1.1
- Chunked: has 0x5678
- Chunked: positive length
- Content-Length: has 0x1234
- Content-Length: has result
- Content-Length: positive length
- fetched → FETCH_DONE
- fetching → FETCH_PENDING
- getPeerCount: 0 peers
- getPeerCount: 3 peers
- getTipHeader: 0x11dd2e2 parsed
- getTipHeader: returns true
- not_found → FETCH_NOT_FOUND
- RPC error: lastError set
- RPC error response → returns -1
- setScripts: block num as 0x64
- setScripts: has args field
- setScripts: has block_number
- setScripts: has code_hash
- setScripts: has hash_type
- setScripts: has script_type
- setScripts: NOT raw hash field
- setScripts: uses partial command

</details>

### `light_client`

**25 passed · 0 failed · 518ms**

**Sections:**
- [1] begin() + state transitions
- [2] watchScript()
- [3] stateStr() all states
- [4] hasPendingEvents() / nextEvent()
- [5] _applyFilter() hex decode + GCS test
- [6] accessor sanity
- [7] sync() in IDLE is no-op
- [8] CONNECTING → SYNCING_CHECKPOINTS via mock transport
- [9] Devchain live smoke test (192.168.68.93:8114)

<details>
<summary>Test cases (25)</summary>

- after begin() state is CONNECTING
- CONNECTING string
- empty filter: no match queued
- filter match: block queued
- filterSyncBlock starts at 0
- filterSyncBlock starts at 0 before connect
- hasEvents after queueEvent
- IDLE string
- initial state is IDLE
- matched block number correct
- nextEvent() block number correct
- nextEvent() returns true
- nextEvent() txHash prefix correct
- no events after drain
- no events on init
- peerCount starts at -1
- state advanced past CONNECTING
- state is IDLE
- state still IDLE after sync()
- stateStr() == 'CONNECTING'
- stateStr() == 'IDLE'
- tip block = 100 (0x64 from mock)
- tip starts at 0
- watchScript() first script returns true
- watchScript() second script returns true

</details>

### `helpers`

**29 passed · 0 failed · 489ms**

**Sections:**
- [1] blake2b_real.h — real CKB Blake2b-256
- [2] molecule_builder.h — Molecule struct builder
- [3] ckb_rpc_fixtures.h — shared RPC response fixtures

<details>
<summary>Test cases (29)</summary>

- ckb_merge matches manual blake2b(a||b)
- empty input hash matches known vector
- error: code -32601
- error: message present
- fetchDone: status=fetched
- fetchDone: txHash present
- fetchNotFound: status=not_found
- fetchPending: status=fetching
- hash hex has 0x prefix
- hash hex is 66 chars (0x + 64)
- "hello" hash matches known vector
- incremental matches one-shot for 'hello'
- MolBuf reports ok
- MolBuf reset clears length
- OutPoint index=0 LE bytes correct
- OutPoint tx_hash last byte correct
- peers0: empty array
- peers1: node_id present
- Script hash is deterministic
- Script hash is non-zero
- Script molecule size = 73 bytes
- setScripts: null result
- tipHeader: block 0x64
- tipHeader: Content-Length present
- tipHeader: CRLF separator found
- tipHeader: hash field present
- tipHeader: HTTP 200
- tipHeader: parsed number=100 via ckb_json
- WitnessArgs placeholder size = 85 bytes

</details>

### `native_locks`

**37 passed · 0 failed · 341ms**

**Sections:**
- [1] identifyLock() — code hash recognition
- [2] blake160() — first 20 bytes of CKB Blake2b
- [3] extractWitnessLock() — WitnessArgs molecule parsing
- [4] verifySecp256k1() — full sign+verify round-trip
- [5] parseMultisigArgs() — lockArgs header parsing
- [6] verifyMultisig() — 2-of-3 signature verification
- [7] verifyACP() — anyone-can-pay verification
- [8] verify() dispatch

<details>
<summary>Test cases (36)</summary>

- 2-of-3 parses ok
- 2-of-3 verifies with sigs 0+1
- ACP: 1000 shannon > minimum accepted
- ACP: 100 shannon = minimum accepted
- ACP: 50 shannon < 100 minimum rejected
- ACP: capacity decrease rejected
- ACP: capacity increase passes
- ACP: equal capacity passes (no minimum)
- ACP identified
- ACP: valid sig path
- blake160(empty) matches known value
- blake160('hello') matches known value
- corrupt sig rejected
- corrupt total_size rejected
- dispatch: ACP (sig path) verifies
- dispatch: secp256k1 verifies
- dispatch: unknown returns false
- keyCount=3
- lock bytes match input
- lock field found
- lock field is 65 bytes
- multisig identified
- null returns UNKNOWN
- null witness returns nullptr
- requiredFirstN=0
- secp256k1 identified
- test sign succeeded
- threshold=0 rejected
- threshold=2
- threshold>keyCount rejected
- too short lockArgs rejected
- truncated witness rejected
- unknown rejected
- valid sig verifies
- wrong lockArgs rejected
- wrong signing hash rejected

</details>

### `ckbvm_interp`

**24 passed · 0 failed · 5608ms**

**Sections:**
- [1] ELF loading
- [2] execute() — exit codes
- [3] ALU — RV64I + M extension
- [4] Memory — load/store round-trip
- [5] Branch — BEQ + JAL
- [6] Syscall — LoadTxHash
- [7] Syscall — Debug (2177)
- [8] Cycle limit enforcement
- [9] Memory fault — null page access
- [10] reset() — reuse VM between executions

<details>
<summary>Test cases (24)</summary>

- ADD/SUB: 3+4-7=0 → exit(0)
- cycle count at limit
- cycles consumed > 0
- Debug syscall: prints OK, exit(0)
- error message set
- exit(0) returns SUCCESS
- exit(-1) returns -1
- exit(1) returns FAILURE
- first execute: exit(0)
- garbage rejected
- infinite loop hits cycle limit
- isLoaded() true
- load from addr 0 causes MEM_FAULT
- LoadTxHash: buf[0]=0xAA, exit(0xAA-0xAA=0)
- load valid ELF
- loop 0..3: BEQ exits when x10==3
- MUL: 6*7=42 → exit(42)
- PC at entry point (past headers)
- SD/LD round-trip: store 42, load, subtract = 0
- second execute after reset: exit(0)
- stack pointer initialised
- still loaded after reset
- tiny ELF rejected
- XOR: 0xFF^0xFF=0 → exit(0)

</details>

### `lora_transport`

**17 passed · 0 failed · 250ms**

**Sections:**
- [1] begin() and isConnected()
- [2] ping() — loopback PING→PONG
- [3] Packet encode/decode — round trip via injectPacket
- [4] request() — single-fragment RPC
- [5] request() — large body triggers multi-fragment send
- [6] request() — multi-fragment response reassembly
- [7] Timeout — no response injected
- [8] Not connected guard

<details>
<summary>Test cases (17)</summary>

- begin() returns true
- connected after begin
- error message set on timeout
- error set when not connected
- injected PONG → ping() succeeds
- large request: correct response content
- large request: response received
- multi-frag response: bytes received
- multi-frag response: part0 present
- multi-frag response: part1 present
- not connected before begin
- ping() returns non-negative RTT
- request() returns positive byte count
- request without begin() returns -1
- response contains expected data
- seq == 1 after one ping
- timeout returns -1

</details>

---
*Generated by `test/run_tests.sh --md`*
