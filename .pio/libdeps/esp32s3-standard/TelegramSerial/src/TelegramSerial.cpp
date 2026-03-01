/*
 * TelegramSerial.cpp  —  Implementation
 */

#include "TelegramSerial.h"
#include <string.h>
#include <stdio.h>

// ── Telegram Bot API endpoint ─────────────────────────────────────────────────
// Uses HTTPS; certificate validation is skipped (setInsecure) for simplicity
// on embedded targets. Swap for a root CA if you need full verification.
static const char* TG_API_HOST = "api.telegram.org";
static const int   TG_API_PORT = 443;

// ── Constructor ───────────────────────────────────────────────────────────────
TelegramSerial::TelegramSerial(const char* ssid,
                               const char* password,
                               const char* botToken,
                               const char* chatId,
                               Print*      mirror,
                               TGFormat    fmt)
    : _ssid(ssid), _pass(password), _token(botToken), _chatId(chatId),
      _mirror(mirror), _fmt(fmt),
      _lineLen(0),
      _qHead(0), _qTail(0), _qLen(0),
      _lastSendMs(0), _retries(0)
{
    memset(_lineBuf, 0, sizeof(_lineBuf));
}

// ── begin() ──────────────────────────────────────────────────────────────────
bool TelegramSerial::begin() {
    _wifiConnect();
    return connected();
}

// ── write() — core Print interface ───────────────────────────────────────────
size_t TelegramSerial::write(uint8_t c) {
    // Mirror to hardware serial if configured
    if (_mirror) _mirror->write(c);

    // Accumulate into line buffer
    if (_lineLen < TG_LINE_BUF_SIZE - 1) {
        _lineBuf[_lineLen++] = (char)c;
        _lineBuf[_lineLen]   = '\0';
    }

    // Flush on newline or when buffer almost full
    if (c == '\n' || _lineLen >= TG_LINE_BUF_SIZE - 2) {
        flushLine();
    }

    return 1;
}

size_t TelegramSerial::write(const uint8_t* buf, size_t size) {
    // Pass byte-by-byte so newline detection works correctly.
    // Could be optimised, but Print calls are infrequent on embedded targets.
    for (size_t i = 0; i < size; i++) write(buf[i]);
    return size;
}

// ── flushLine() ───────────────────────────────────────────────────────────────
void TelegramSerial::flushLine() {
    if (_lineLen == 0) return;

    // Trim trailing newline/CR before queuing (Telegram renders \n fine but
    // multiple blank lines look messy)
    while (_lineLen > 0 &&
           (_lineBuf[_lineLen-1] == '\n' || _lineBuf[_lineLen-1] == '\r')) {
        _lineBuf[--_lineLen] = '\0';
    }

    if (_lineLen > 0) {
        _enqueue(_lineBuf);
    }

    // Reset line buffer
    _lineLen      = 0;
    _lineBuf[0]   = '\0';
}

// ── send() — direct queue insertion ──────────────────────────────────────────
bool TelegramSerial::send(const char* msg) {
    return _enqueue(msg);
}

// ── update() — drain queue, one message per call ─────────────────────────────
void TelegramSerial::update() {
    // WiFi watchdog — attempt reconnect, but don't block if it fails
    if (WiFi.status() != WL_CONNECTED) {
        _wifiConnect();
        // If still not connected after attempt, leave queue intact and return.
        // Messages will be sent on the next update() once WiFi comes back.
        if (WiFi.status() != WL_CONNECTED) return;
    }

    if (_qLen == 0) return;

    // Rate limit
    unsigned long now = millis();
    if (now - _lastSendMs < TG_SEND_INTERVAL_MS) return;

    // Pop from queue head
    const char* msg = _queue[_qHead];
    bool ok = _sendNow(msg);

    if (ok || _retries >= TG_MAX_MSG_RETRIES) {
        // Success or exhausted retries — advance queue
        _qHead = (_qHead + 1) % TG_QUEUE_SIZE;
        _qLen--;
        _retries = 0;
    } else {
        // Failed but retries remain — leave message in queue, increment counter
        _retries++;
        if (_mirror) {
            _mirror->printf("[TelegramSerial] send failed, retry %d/%d\n",
                            _retries, TG_MAX_MSG_RETRIES);
        }
    }

    _lastSendMs = millis();
}

// ── _enqueue() ───────────────────────────────────────────────────────────────
bool TelegramSerial::_enqueue(const char* msg) {
    if (!msg || msg[0] == '\0') return false;

    if (_qLen >= TG_QUEUE_SIZE) {
        // Queue full — drop oldest to make room (oldest is least useful)
        _qHead = (_qHead + 1) % TG_QUEUE_SIZE;
        _qLen--;
    }

    strncpy(_queue[_qTail], msg, TG_LINE_BUF_SIZE - 1);
    _queue[_qTail][TG_LINE_BUF_SIZE - 1] = '\0';
    _qTail = (_qTail + 1) % TG_QUEUE_SIZE;
    _qLen++;
    return true;
}

// ── _sendNow() — blocking HTTPS POST to Telegram API ─────────────────────────
bool TelegramSerial::_sendNow(const char* msg) {
    if (!msg) return false;

    // Double-check WiFi right before the HTTP call.
    // WiFi.status() is fast and avoids blocking in http.GET() if we just lost
    // the connection between update()'s check and here.
    if (WiFi.status() != WL_CONNECTED) return false;

    // Build message text
    char text[TG_LINE_BUF_SIZE + 64];
    if (_fmt == TG_FMT_MARKDOWN) {
        // Wrap in monospace code block
        char escaped[TG_LINE_BUF_SIZE];
        _escapeMarkdown(msg, escaped, sizeof(escaped));
        snprintf(text, sizeof(text), "`%s`", escaped);
    } else {
        strncpy(text, msg, sizeof(text) - 1);
        text[sizeof(text) - 1] = '\0';
    }

    // URL-encode the text for the GET request
    // Using sendMessage via GET for simplicity (works for most text)
    char urlEncoded[TG_LINE_BUF_SIZE * 3 + 64];
    size_t o = 0;
    for (size_t i = 0; text[i] && o < sizeof(urlEncoded) - 4; i++) {
        unsigned char c = (unsigned char)text[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~' ||
            c == '\n' || c == ' ') {
            if (c == ' ')       { urlEncoded[o++] = '+'; }
            else if (c == '\n') { urlEncoded[o++] = '%'; urlEncoded[o++] = '0'; urlEncoded[o++] = 'A'; }
            else                { urlEncoded[o++] = c; }
        } else {
            snprintf(urlEncoded + o, 4, "%%%02X", c);
            o += 3;
        }
    }
    urlEncoded[o] = '\0';

    // Build URL
    char url[512];
    snprintf(url, sizeof(url),
             "https://%s/bot%s/sendMessage?chat_id=%s&text=%s%s",
             TG_API_HOST, _token, _chatId, urlEncoded,
             (_fmt == TG_FMT_MARKDOWN) ? "&parse_mode=MarkdownV2" : "");

    WiFiClientSecure client;
    client.setInsecure();  // skip cert validation — fine for telemetry use

    HTTPClient http;
    http.begin(client, url);
    http.setTimeout(4000);  // 4s — fail fast so update() doesn't block the loop

    int code = http.GET();
    bool ok  = (code == 200);
    http.end();

    return ok;
}

// ── _wifiConnect() ────────────────────────────────────────────────────────────
void TelegramSerial::_wifiConnect() {
    if (WiFi.status() == WL_CONNECTED) return;
    if (_mirror) {
        _mirror->print("[TelegramSerial] Connecting to ");
        _mirror->println(_ssid);
    }
    WiFi.mode(WIFI_STA);
    WiFi.begin(_ssid, _pass);
    unsigned long t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < TG_WIFI_TIMEOUT_MS) {
        delay(250);
    }
    if (_mirror) {
        if (WiFi.status() == WL_CONNECTED) {
            _mirror->print("[TelegramSerial] Connected, IP: ");
            _mirror->println(WiFi.localIP().toString());
        } else {
            _mirror->println("[TelegramSerial] WiFi connect failed");
        }
    }
}

// ── _escapeMarkdown() — escape MarkdownV2 special chars ──────────────────────
void TelegramSerial::_escapeMarkdown(const char* in, char* out, size_t outSize) {
    // MarkdownV2 special chars that need escaping outside code spans:
    // _ * [ ] ( ) ~ ` > # + - = | { } . !
    // Inside backtick code spans, only ` and \ need escaping.
    static const char SPECIAL[] = "`\\";
    size_t o = 0;
    for (size_t i = 0; in[i] && o < outSize - 3; i++) {
        if (strchr(SPECIAL, in[i])) {
            out[o++] = '\\';
        }
        out[o++] = in[i];
    }
    out[o] = '\0';
}
