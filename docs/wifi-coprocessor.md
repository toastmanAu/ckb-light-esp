# WiFi Co-Processor Wiring Guide

The WT9932-P4-Tiny has no integrated WiFi. Until the Ethernet module arrives,
an ESP32 or ESP32-C3 acts as a WiFi co-processor over SPI.

## What You Need

- 1× ESP32 (any WROOM/WROVER) **or** ESP32-C3 board
- 6× female-to-female jumper wires
- USB cable to flash the co-proc firmware

## Wiring (6 wires)

```
ESP32-P4 (WT9932-P4-Tiny)        ESP32 / ESP32-C3 (co-proc)
──────────────────────────────────────────────────────────────
GPIO 15  [MOSI] ─────────────→  GPIO 11  [MOSI]
GPIO 16  [MISO] ←─────────────  GPIO 13  [MISO]
GPIO 17  [CLK]  ─────────────→  GPIO 12  [CLK]
GPIO 18  [CS]   ─────────────→  GPIO 10  [CS]   (active low)
GPIO 19  [IN]   ←─────────────  GPIO 2   [DATA_READY]  ← co-proc pulls high when it has data
GND             ───────────────  GND
3.3V            ───────────────  3.3V  (or power co-proc from its own USB)
```

> **Note on 3.3V:** If powering both from the P4, make sure it can supply enough
> current. The ESP32 can draw up to ~240mA during WiFi TX. Safest is to power
> the co-proc from its own USB and just share GND.

## Flashing the Co-Processor Firmware

```bash
# From the repo root:
cd wifi_coprocessor

# Set target (use esp32c3 if you have a C3):
idf.py set-target esp32        # or esp32c3

# Build & flash (co-proc connected via USB):
idf.py build flash monitor
```

You should see:
```
I (xxx) ckb-wificp: CKB WiFi co-processor ready
```

## How It Works

The co-proc runs a SPI slave + WiFi station + TCP socket pool.

- All SPI transfers are fixed 256 bytes (zero-padded) — keeps the slave driver simple
- `DATA_READY` (GPIO 2) goes high when the co-proc has a response queued
- The P4 watches `DATA_READY` and initiates a SPI read when it goes high
- A background task on the co-proc polls open TCP sockets every 10ms and pushes
  received data to the response queue automatically — no need for the P4 to poll

## Protocol Summary

| Command | What it does |
|---------|-------------|
| `WIFI_CONNECT` | Connect to SSID/password |
| `WIFI_STATUS`  | Check connection + get IP |
| `TCP_CONNECT`  | Open TCP socket to IP:port |
| `TCP_SEND`     | Send data on connection |
| `TCP_POLL`     | Manual poll for RX data |
| `TCP_CLOSE`    | Close TCP connection |

## P4 Driver API

```c
// One-time init (sets up SPI master)
ckb_wifi_init();

// Connect to WiFi (blocks until connected or timeout)
uint8_t ip[4];
ckb_wifi_connect("MySSID", "MyPassword", 30000, ip);

// Open TCP connection to CKB node
uint8_t node_ip[4] = {192, 168, 68, 87};
int conn = ckb_tcp_connect(node_ip, 8115);  // 8115 = CKB P2P port

// Send data
ckb_tcp_send(conn, data, len);

// Receive data (blocks up to timeout_ms)
uint8_t buf[1024];
int n = ckb_tcp_recv(conn, buf, sizeof(buf), 5000);

// Close
ckb_tcp_close(conn);
```

## SPI Speed

10 MHz is the default — conservative for jumper wires. The light client traffic
is not high-bandwidth (handshake + block headers only), so this is plenty.
If you want to go faster after confirming stability, bump `clock_speed_hz` in
`ckb_wifi.c` to 20–40 MHz.

## When the Ethernet Module Arrives

Replace `ckb_wifi_connect()` + `ckb_tcp_connect()` calls with the standard
ESP-IDF `esp_eth` + `lwip` socket calls. The rest of the light client code
(SecIO, Yamux, protocol layer) is transport-agnostic and needs zero changes.
