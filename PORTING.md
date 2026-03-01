# PORTING.md — ckb-light-esp device build notes

Notes from first PlatformIO device build attempts (esp32dev, esp32s3-standard).
Updated: 2026-03-01.

---

## Library dependency setup

ckb-light-esp is a **library**, not a sketch. Build via an example, not the repo root:

```
cd examples/minimal_watch    # or BalanceChecker, standard_utxo, etc.
pio run -e esp32dev
```

The root `platformio.ini` has no `setup()`/`loop()` — linking it directly gives:
`undefined reference to setup()`

### Local development (symlinked lib_deps)

When working from source, replace registry refs with local symlinks:

```ini
lib_deps =
    symlink:///absolute/path/to/CKB-ESP32
    symlink:///absolute/path/to/ckb-light-esp
    bblanchon/ArduinoJson @ ^7.0.0
```

### ArduinoJson include path

CKB-ESP32 ships ArduinoJson as a git submodule at `third_party/ArduinoJson/`.
PlatformIO does **not** auto-expose submodule headers. Add to `build_flags`:

```ini
build_flags =
    -I/path/to/CKB-ESP32/third_party/ArduinoJson/src
```

Or add `bblanchon/ArduinoJson @ ^7.0.0` to `lib_deps` (uses registry copy).

---

## Host shim guard (`wifi_transport.cpp`)

The Arduino compat shims (`millis()`, `delay()`, `IRAM_ATTR`) are wrapped in
`#ifdef HOST_TEST`. On device they must **not** be redeclared — Arduino.h provides
them. The guard was `#ifndef IRAM_ATTR` which misfired before Arduino.h was pulled in.

**Fixed:** shims now use `#ifdef HOST_TEST` exclusively.

---

## LoRa transport on non-LoRa profiles

`lora_transport.cpp` uses `SX1276`/`Module`/`RADIOLIB_ERR_NONE` from RadioLib.
On WiFi-only profiles (`LIGHT_PROFILE_MINIMAL`, `LIGHT_PROFILE_STANDARD`),
RadioLib is not in `lib_deps`.

**Fix applied:** device blocks in `begin()`, `_sendPacket()`, `_recvPacket()`
are guarded:
```cpp
#elif defined(LIGHT_PROFILE_LORA) || defined(LIGHT_PROFILE_LORAWAN)
    // RadioLib code
#else
    return false;  // LoRa not enabled for this profile
#endif
```

For LoRa profiles, add to `lib_deps`:
```
jgromes/RadioLib @ ^6.0.0
```

---

## `__int128` not available on Xtensa GCC

`ckbvm_interp.cpp` uses `__int128` for RV64 MULH/MULHSU/MULHU.
Xtensa GCC 8.4.0 does not support `__int128`.

**Fix applied:** replaced with portable 32x32→64 decomposition.
All 24/24 ckbvm_interp host tests still pass after this change.

---

## `ckb_blake2b_256` alias (CKB-ESP32 upstream fix)

`block_filter.cpp` calls `ckb_blake2b_256()` but CKB-ESP32 only had
`ckb_blake2b_hash()` (identical signature).

**Fix applied upstream in CKB-ESP32 `src/ckb_blake2b.h`:**
```cpp
static inline void ckb_blake2b_256(const void* data, size_t len, uint8_t out[32]) {
    ckb_blake2b_hash(data, len, out);
}
```

---

## `ckb_blake2b.h` include scope (`header_chain.cpp`)

Was inside `#else // HOST_TEST` — missing on device. Moved above the
`#ifdef HOST_TEST` block so it's included unconditionally.

---

## `ckbfs.cpp` String → const char* (CKB-ESP32 upstream fix)

`strlcpy(_ckbfs_rpc_buf, resp, ...)` where `resp` is `String`.

**Fix:** `resp.c_str()`.

---

## Example `.ino` must be in `src/`

PlatformIO requires sketch source in `src/`, not alongside `platformio.ini`.
Move or copy the `.ino` file:
```
mkdir src && cp MySketch.ino src/
```

---

## `LIGHT_STATE_READY` renamed

Example sketches using `LIGHT_STATE_READY` need updating to `LIGHT_STATE_WATCHING`.

---

## ESP32-C6 Arduino support

PlatformIO espressif32 platform v6.x does not ship C6 Arduino framework support
out of the box. Use `esp32dev` (classic) or `esp32s3box` for initial testing.
C6 support requires platform ≥ 6.4.0:
```ini
platform = espressif32@6.4.0
```

---

## PlatformIO symlink + submodule path explosion (cosmetic)

When CKB-ESP32 is installed via `symlink://`, PlatformIO follows symlinks
recursively inside the blake2b submodule, producing long repeated paths:
```
src/blake2b/blake2b/blake2b/.../blake2b.c
```
This is cosmetic — the object compiles correctly. No action needed.

---

## Tested environment

| Component | Version |
|---|---|
| PlatformIO | 6.1.x |
| espressif32 platform | 6.x |
| Arduino framework | yes (not ESP-IDF) |
| Xtensa toolchain | 8.4.0 (ESP32 / ESP32-S3) |
| Host test compiler | aarch64 g++ 11.4.0 (Orange Pi 5, RK3588) |
