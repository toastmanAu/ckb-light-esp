# TelegramSerial

Drop-in `Serial` replacement for ESP32 that sends output to a Telegram bot over WiFi.

Inherits from `Print` — works anywhere `Serial` does. Just swap `Serial` for `tg`.

## Features

- **Drop-in** — inherits `Print`, so `print()`, `println()`, `printf()` all work
- **Non-blocking** — queues messages, drains one per `update()` call
- **Rate-limited** — respects Telegram's API limits automatically
- **WiFi resilient** — auto-reconnects, retries failed sends
- **Mirror mode** — optionally echo to hardware Serial simultaneously
- **Markdown mode** — wrap output in monospace code blocks
- **Configurable** — queue size, rate limit, timeouts all adjustable via `#define`

## Installation

**Arduino Library Manager:** search for `TelegramSerial`

**Manual:** download and place in `~/Arduino/libraries/TelegramSerial/`

**PlatformIO:** add to `platformio.ini`:
```ini
lib_deps = toastmanAu/TelegramSerial
```

## Quick Start

```cpp
#include <TelegramSerial.h>

TelegramSerial tg("MyNetwork", "password", "BOT_TOKEN", "CHAT_ID");

void setup() {
    Serial.begin(115200);
    tg.begin();              // connect WiFi
    tg.println("Hello!");    // queued, sent on next update()
}

void loop() {
    tg.update();             // call every loop — drains queue
}
```

## Getting a Bot Token and Chat ID

1. Message [@BotFather](https://t.me/BotFather) → `/newbot` → copy the token
2. For a group: add your bot, then message [@userinfobot](https://t.me/userinfobot) from the group — copy the chat ID (negative number)
3. For a personal chat: start a DM with your bot, then visit `https://api.telegram.org/bot<TOKEN>/getUpdates` to find your user ID

## Constructor

```cpp
TelegramSerial tg(ssid, password, botToken, chatId);
TelegramSerial tg(ssid, password, botToken, chatId, &Serial);         // mirror to Serial
TelegramSerial tg(ssid, password, botToken, chatId, &Serial, TG_FMT_MARKDOWN); // monospace
```

## API

| Method | Description |
|---|---|
| `begin()` | Connect WiFi (blocking up to `TG_WIFI_TIMEOUT_MS`). Returns `true` if connected |
| `update()` | Drain send queue — call every `loop()` |
| `send(msg)` | Queue a message directly (bypasses line buffer) |
| `flushLine()` | Force-flush current line buffer without waiting for `\n` |
| `connected()` | Returns `true` if WiFi is up |
| `queued()` | Number of messages currently waiting to send |
| `print()` / `println()` / `printf()` | Standard Print interface — same as Serial |

## Configuration

Override before `#include <TelegramSerial.h>` or via `build_flags`:

```cpp
#define TG_LINE_BUF_SIZE      512    // max chars per message (default 512)
#define TG_QUEUE_SIZE          16    // max queued messages (default 16)
#define TG_SEND_INTERVAL_MS  1200    // min ms between sends (default 1200)
#define TG_WIFI_TIMEOUT_MS  12000    // WiFi connect timeout (default 12000)
#define TG_MAX_MSG_RETRIES      2    // retries before dropping a message (default 2)
```

## Drop-in Replacement Pattern

Any sketch that uses a configurable output target:

```cpp
#include <TelegramSerial.h>

TelegramSerial tg("ssid", "pass", "TOKEN", "CHAT_ID", &Serial);

// Change one line — everything else unchanged
#define MY_OUTPUT tg   // was: #define MY_OUTPUT Serial
```

## Notes

- Uses HTTPS (`WiFiClientSecure`) with certificate validation skipped — fine for telemetry
- Messages longer than `TG_LINE_BUF_SIZE` are truncated to fit
- If the queue fills up, the oldest message is dropped to make room for new ones
- `update()` is non-blocking — max one Telegram send per call, so your loop stays responsive
- WiFi reconnect is attempted in `update()` but won't block if it fails

## License

MIT © toastmanAu
