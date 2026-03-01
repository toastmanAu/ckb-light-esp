/*
 * TelegramSerial.h  —  Drop-in Serial replacement that forwards output to Telegram
 *
 * Inherits from Print, so it works anywhere Serial does:
 *   Serial.println("hello")  →  tg.println("hello")
 *
 * Features:
 *   - Buffers per-line, flushes on '\n' or when buffer full
 *   - Non-blocking: queues up to TG_QUEUE_SIZE messages, drains in update()
 *   - WiFi connect + auto-reconnect in begin() / update()
 *   - Optional mirror to hardware Serial (pass &Serial to constructor)
 *   - Rate-limited: min TG_SEND_INTERVAL_MS between Telegram sends
 *   - Markdown mode: pass fmt=TG_FMT_MARKDOWN to wrap in code blocks
 *   - Works as a FreeRTOS task (call update() from loop or spawn a task)
 *
 * Basic usage:
 *   TelegramSerial tg("MyNet", "pass", "BOT_TOKEN", "-1001234567890");
 *   tg.begin();            // connect WiFi + init
 *   tg.println("Hello!");  // queued, sent on next update()
 *   tg.update();           // call from loop() — drains send queue
 *
 * Drop-in for CKBTestBench (or any sketch):
 *   #define CKB_TEST_OUTPUT tg   // redirect all bench output to Telegram
 *
 * Author:  toastmanAu (Phill)
 * Repo:    https://github.com/toastmanAu/CKB-ESP32
 * License: MIT
 */

#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

// ── Config (override via build_flags or before include) ────────────────────────
#ifndef TG_LINE_BUF_SIZE
  #define TG_LINE_BUF_SIZE   512    // max chars per Telegram message
#endif
#ifndef TG_QUEUE_SIZE
  #define TG_QUEUE_SIZE      16     // max queued messages before oldest dropped
#endif
#ifndef TG_SEND_INTERVAL_MS
  #define TG_SEND_INTERVAL_MS 1200  // min ms between Telegram sends (~50 msg/min)
#endif
#ifndef TG_WIFI_TIMEOUT_MS
  #define TG_WIFI_TIMEOUT_MS  12000 // WiFi connect timeout
#endif
#ifndef TG_MAX_MSG_RETRIES
  #define TG_MAX_MSG_RETRIES  2     // retries per message before dropping
#endif

// ── Format modes ──────────────────────────────────────────────────────────────
enum TGFormat {
    TG_FMT_PLAIN    = 0,  // plain text
    TG_FMT_MARKDOWN = 1,  // MarkdownV2 — wraps output in ```code blocks```
};

// ── TelegramSerial ─────────────────────────────────────────────────────────────
class TelegramSerial : public Print {
public:
    /**
     * Constructor.
     *
     * @param ssid       WiFi network name
     * @param password   WiFi password (empty string for open networks)
     * @param botToken   Telegram bot token (from @BotFather), e.g. "123456:ABC-DEF..."
     * @param chatId     Target chat/group/channel ID, e.g. "-1001234567890" or "987654321"
     * @param mirror     Optional: pointer to a hardware Serial to also echo output (e.g. &Serial)
     * @param fmt        Output format: TG_FMT_PLAIN (default) or TG_FMT_MARKDOWN
     */
    TelegramSerial(const char* ssid,
                   const char* password,
                   const char* botToken,
                   const char* chatId,
                   Print*      mirror = nullptr,
                   TGFormat    fmt    = TG_FMT_PLAIN);

    /**
     * Connect to WiFi (blocking up to TG_WIFI_TIMEOUT_MS).
     * Call once from setup(). Returns true if connected.
     */
    bool begin();

    /**
     * Drain the send queue — call from loop() or a background task.
     * Sends at most one Telegram message per call, rate-limited.
     * Also checks WiFi and reconnects if needed.
     */
    void update();

    /**
     * Flush the current line buffer immediately (even if no newline yet).
     * Blocks until queued. Use sparingly — prefer letting println() trigger flush.
     */
    void flushLine();

    /**
     * Send a message directly (bypasses line buffer, goes to queue).
     * Returns false if queue is full.
     */
    bool send(const char* msg);
    bool send(const String& msg) { return send(msg.c_str()); }

    /** True if WiFi is connected */
    bool connected() const { return WiFi.status() == WL_CONNECTED; }

    /** Number of messages currently queued */
    uint8_t queued() const { return _qLen; }

    /** True if the send queue is full (new messages will be dropped) */
    bool queueFull() const { return _qLen >= TG_QUEUE_SIZE; }

    // ── Print interface ───────────────────────────────────────────────────────
    // Overrides Print::write() — all print/println/printf route through here.
    virtual size_t write(uint8_t c) override;
    virtual size_t write(const uint8_t* buf, size_t size) override;

private:
    // Config
    const char* _ssid;
    const char* _pass;
    const char* _token;
    const char* _chatId;
    Print*      _mirror;
    TGFormat    _fmt;

    // Line buffer
    char   _lineBuf[TG_LINE_BUF_SIZE];
    size_t _lineLen;

    // Send queue (circular, fixed-size)
    char    _queue[TG_QUEUE_SIZE][TG_LINE_BUF_SIZE];
    uint8_t _qHead, _qTail, _qLen;

    // Rate limiting
    unsigned long _lastSendMs;
    uint8_t       _retries;   // consecutive failed sends on current head message

    // Internal helpers
    bool _enqueue(const char* msg);
    bool _sendNow(const char* msg);
    void _wifiConnect();
    static void _escapeMarkdown(const char* in, char* out, size_t outSize);
};
