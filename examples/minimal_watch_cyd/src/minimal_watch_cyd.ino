// =============================================================================
// minimal_watch_cyd.ino — CKB address watcher with on-screen serial terminal
// Target: ESP32-2432S028R (CYD) — ILI9341 320×240 via LovyanGFX
// Profile: LIGHT_PROFILE_MINIMAL
// =============================================================================

#include <LovyanGFX.hpp>
#include <LightClient.h>

// ── CYD ILI9341 display config ────────────────────────────────────────────────
class LGFX_CYD : public lgfx::LGFX_Device {
    lgfx::Panel_ILI9341  _panel;
    lgfx::Bus_SPI        _bus;
    lgfx::Light_PWM      _light;
public:
    LGFX_CYD() {
        { auto cfg = _bus.config();
          cfg.spi_host   = HSPI_HOST;
          cfg.freq_write = 40000000;
          cfg.pin_sclk = 14; cfg.pin_mosi = 13;
          cfg.pin_miso = 12; cfg.pin_dc   = 2;
          _bus.config(cfg); _panel.setBus(&_bus); }

        { auto cfg = _panel.config();
          cfg.pin_cs = 15; cfg.pin_rst = -1; cfg.pin_busy = -1;
          cfg.panel_width = 240; cfg.panel_height = 320;
          cfg.offset_rotation = 1;
          _panel.config(cfg); }

        { auto cfg = _light.config();
          cfg.pin_bl = 21; cfg.invert = false;
          cfg.freq = 44100; cfg.pwm_channel = 7;
          _light.config(cfg); _panel.setLight(&_light); }

        setPanel(&_panel);
    }
};

// ── Scrolling terminal (manual Serial mirror — no addPrintHandler needed) ─────
#define TERM_COLS     53
#define TERM_LINES    26
#define TERM_CHAR_W    6
#define TERM_CHAR_H    8
#define TERM_HEADER_H 12
#define TERM_FG  0x07E0   /* green */
#define TERM_BG  0x0000   /* black */
#define TERM_HDR 0x1082   /* dark grey */
#define TERM_SEP 0x2945   /* dim teal */
#define TERM_MUT 0xAD75   /* light grey */

LGFX_CYD tft;
char _tbuf[TERM_LINES][TERM_COLS];
uint8_t _trow = 0, _tcol = 0;

void term_redraw() {
    tft.fillRect(0, TERM_HEADER_H, 320, 240 - TERM_HEADER_H, TERM_BG);
    tft.setTextColor(TERM_FG, TERM_BG);
    for (uint8_t r = 0; r < TERM_LINES; r++) {
        tft.setCursor(0, TERM_HEADER_H + r * TERM_CHAR_H);
        for (uint8_t c = 0; c < TERM_COLS; c++) tft.print(_tbuf[r][c]);
    }
}

void term_header(const char* label = "CYD  |  CKB Watcher") {
    tft.fillRect(0, 0, 320, TERM_HEADER_H, TERM_HDR);
    tft.setTextColor(TERM_MUT, TERM_HDR);
    tft.setTextSize(1);
    tft.setCursor(3, 2); tft.print(label);
    char upbuf[12]; uint32_t s = millis() / 1000;
    if (s < 60)        snprintf(upbuf, sizeof(upbuf), "%lus", s);
    else if (s < 3600) snprintf(upbuf, sizeof(upbuf), "%lum%02lus", s/60, s%60);
    else               snprintf(upbuf, sizeof(upbuf), "%luh%02lum", s/3600, (s%3600)/60);
    tft.setCursor(320 - (int)strlen(upbuf)*6 - 3, 2); tft.print(upbuf);
    tft.drawFastHLine(0, TERM_HEADER_H-1, 320, TERM_SEP);
}

void term_putc(char c) {
    if (c == '\r') return;
    if (c == '\n') {
        while (_tcol < TERM_COLS) _tbuf[_trow][_tcol++] = ' ';
        _tcol = 0;
        if (_trow < TERM_LINES - 1) { _trow++; return; }
        // scroll
        for (uint8_t r = 0; r < TERM_LINES-1; r++) memcpy(_tbuf[r], _tbuf[r+1], TERM_COLS);
        memset(_tbuf[TERM_LINES-1], ' ', TERM_COLS);
        term_redraw(); return;
    }
    if (_tcol >= TERM_COLS) term_putc('\n');
    _tbuf[_trow][_tcol] = c;
    tft.fillRect(_tcol*TERM_CHAR_W, TERM_HEADER_H+_trow*TERM_CHAR_H, TERM_CHAR_W, TERM_CHAR_H, TERM_BG);
    tft.setTextColor(TERM_FG, TERM_BG);
    tft.setCursor(_tcol*TERM_CHAR_W, TERM_HEADER_H+_trow*TERM_CHAR_H);
    tft.print(c); _tcol++;
}

// Mirror: call instead of Serial.print/println/printf
void tprint(const char* s)  { Serial.print(s);   for (; *s; s++) term_putc(*s); }
void tprintln(const char* s){ Serial.println(s); tprint(s); term_putc('\n'); }
void tprintf(const char* fmt, ...) {
    char buf[128]; va_list args; va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args); va_end(args);
    tprint(buf);
}

// ── App ───────────────────────────────────────────────────────────────────────
const char*    WIFI_SSID      = "your-ssid";
const char*    WIFI_PASS      = "your-password";
const char*    CKB_NODE_HOST  = "192.168.68.87";
const uint16_t CKB_PORT       = 8114;
const char*    LOCK_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
const char*    LOCK_ARGS      = "0xYOUR_20_BYTE_ARGS_HERE";

LightClient client;
uint32_t lastHeaderMs = 0;

void setup() {
    Serial.begin(115200);
    tft.init();
    tft.setTextSize(1);
    memset(_tbuf, ' ', sizeof(_tbuf));
    tft.fillScreen(TERM_BG);
    term_header();

    tprintln("=== CKB Watcher ===");
    tprintf("Node: %s:%d\n", CKB_NODE_HOST, CKB_PORT);
    tprint("WiFi...");

    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) { delay(500); tprint("."); }
    tprintf("\nIP: %s\n", WiFi.localIP().toString().c_str());

    client.begin(CKB_NODE_HOST, CKB_PORT);
    client.watchScript(LOCK_CODE_HASH, LOCK_ARGS, SCRIPT_TYPE_LOCK);
    tprintln("Syncing...");
}

void loop() {
    uint32_t now = millis();
    if (now - lastHeaderMs > 1000) { lastHeaderMs = now; term_header(); }

    client.sync();
    if (client.state() == LIGHT_STATE_WATCHING && client.hasPendingEvents()) {
        char txHash[67]; uint64_t blockNum;
        while (client.nextEvent(txHash, &blockNum))
            tprintf("TX! #%llu\n%s\n", blockNum, txHash);
    }
    delay(100);
}
