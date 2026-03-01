// =============================================================================
// minimal_watch_cyd.ino — CKB address watcher with on-screen serial terminal
//
// Profile: LIGHT_PROFILE_MINIMAL
// Target:  ESP32-2432S028R (CYD) — ILI9341 320×240
//
// All Serial.print() output mirrors to the display automatically.
// No other display code needed.
// =============================================================================

#define WY_BOARD_CYD
#define LIGHT_PROFILE_MINIMAL

#include <WyDisplay.h>
#include <WySerialDisplay.h>
#include <LightClient.h>

// --- Config ------------------------------------------------------------------
const char* WIFI_SSID     = "your-ssid";
const char* WIFI_PASS     = "your-password";
const char* CKB_NODE_HOST = "192.168.68.87";   // ckbnode
const uint16_t CKB_PORT   = 8114;

const char* LOCK_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
const char* LOCK_ARGS      = "0xYOUR_20_BYTE_ARGS_HERE";

// --- Globals -----------------------------------------------------------------
WyDisplay        display;
WySerialDisplay  term;
LightClient      client;

void setup() {
    Serial.begin(115200);

    display.begin();
    term.begin(display.gfx);   // ← all Serial output now mirrors to screen

    Serial.println("=== CKB Watcher ===");
    Serial.printf("Board: %s\n", WY_BOARD_NAME);
    Serial.printf("Node:  %s:%d\n", CKB_NODE_HOST, CKB_PORT);
    Serial.println("Connecting WiFi...");

    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.printf("\nIP: %s\n", WiFi.localIP().toString().c_str());

    client.begin(CKB_NODE_HOST, CKB_PORT);
    client.watchScript(LOCK_CODE_HASH, LOCK_ARGS, SCRIPT_TYPE_LOCK);

    Serial.println("Syncing headers...");
}

void loop() {
    term.update();   // refresh uptime in header
    client.sync();

    if (client.state() == LIGHT_STATE_WATCHING && client.hasPendingEvents()) {
        char txHash[67];
        uint64_t blockNum;
        while (client.nextEvent(txHash, &blockNum)) {
            Serial.printf("TX! Block #%llu\n%s\n", blockNum, txHash);
        }
    }

    delay(100);
}
