/*
 * WithTestBench.ino — redirect any sketch's output to Telegram with one define
 *
 * Pattern: define CKB_TEST_OUTPUT (or your own macro) to point at a
 * TelegramSerial instance instead of Serial. The rest of the sketch is unchanged.
 *
 * This example shows the pattern generically — works with CKBTestBench or any
 * sketch that uses a configurable output target.
 */

#include <Arduino.h>
#include <TelegramSerial.h>

#define WIFI_SSID   "YourNetwork"
#define WIFI_PASS   "YourPassword"
#define BOT_TOKEN   "123456789:ABC-YourBotTokenHere"
#define CHAT_ID     "-1001234567890"

// Create instance — mirroring to Serial so USB still works locally
TelegramSerial tg(WIFI_SSID, WIFI_PASS, BOT_TOKEN, CHAT_ID, &Serial);

// ── Redirect your sketch output ───────────────────────────────────────────────
// Any sketch that uses a configurable Print target: swap this one line.
// Example: CKBTestBench uses #define CKB_TEST_OUTPUT Serial by default.
#define MY_OUTPUT tg

// Helper for printf-style calls on any Print subclass
static void myPrintf(const char* fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    MY_OUTPUT.print(buf);
}

void runTests() {
    MY_OUTPUT.println("=== Test Run ===");
    myPrintf("Test 1: %s\n", true  ? "PASS" : "FAIL");
    myPrintf("Test 2: %s\n", false ? "PASS" : "FAIL");
    myPrintf("Test 3: %s\n", 1==1  ? "PASS" : "FAIL");
    myPrintf("Done. Heap: %u bytes free\n", ESP.getFreeHeap());
}

void setup() {
    Serial.begin(115200);
    tg.begin();
    runTests();
}

void loop() {
    tg.update();  // drain queue every loop
}
