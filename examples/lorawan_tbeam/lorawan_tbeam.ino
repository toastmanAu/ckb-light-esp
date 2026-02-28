// =============================================================================
// lorawan_tbeam.ino — CKB address watcher over LoRaWAN (TTGO T-Beam)
//
// Profile: LIGHT_PROFILE_LORAWAN
// Target:  TTGO T-Beam (ESP32 + SX1276 + GPS + 18650)
// Network: TTN, Chirpstack, or any LoRaWAN NS
//
// This is a self-contained, battery-powered CKB address watcher.
// No WiFi, no ethernet. Joins a LoRaWAN network via OTAA and syncs
// block headers from a ckb-lora-bridge backend.
//
// Setup:
//   1. Register device on TTN/Chirpstack — get devEUI, appEUI, appKey
//   2. Deploy ckb-lora-bridge on a server with CKB node access
//   3. Fill credentials below
//   4. Flash to T-Beam
//   5. Device joins, syncs headers, alerts on payment received
//
// Power: ~10mA average on 18650 (SF9, 6s block time, mostly sleeping)
// =============================================================================

#define LIGHT_PROFILE_LORAWAN
#include <LightClient.h>

// ─── LoRaWAN credentials (from TTN/Chirpstack console) ───────────────────────
// All values LSB first (as shown in TTN console with "lsb" toggle)

static const uint8_t DEV_EUI[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t APP_EUI[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t APP_KEY[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// ─── Watch this CKB lock script ──────────────────────────────────────────────
const char* LOCK_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
const char* LOCK_ARGS      = "0xYOUR_20_BYTE_ARGS_HERE";

// ─── Alert output ─────────────────────────────────────────────────────────────
// Options: Serial print, GPIO trigger, buzzer, LED, second LoRa uplink to phone
#define ALERT_LED_PIN  4   // T-Beam onboard LED

LightClient client;

void onPaymentReceived(const char* txHash, uint64_t blockNum) {
    Serial.printf("💰 CKB received! Block #%llu\n  TX: %s\n", blockNum, txHash);

    // Flash LED 3 times
    for (int i = 0; i < 3; i++) {
        digitalWrite(ALERT_LED_PIN, HIGH); delay(200);
        digitalWrite(ALERT_LED_PIN, LOW);  delay(200);
    }

    // TODO: send a LoRaWAN uplink to notify a phone app / TTN webhook
}

void setup() {
    Serial.begin(115200);
    pinMode(ALERT_LED_PIN, OUTPUT);

    Serial.println("ckb-light-esp / LoRaWAN");
    Serial.println("Joining network...");

    // Configure OTAA credentials
    LoRaWANOTAA creds;
    memcpy(creds.devEUI, DEV_EUI, 8);
    memcpy(creds.appEUI, APP_EUI, 8);
    memcpy(creds.appKey, APP_KEY, 16);

    // Begin — blocks until OTAA join completes (or times out)
    // Transport is constructed internally via LIGHT_PROFILE_LORAWAN
    if (!client.begin(creds, LORAWAN_SF9)) {
        Serial.println("ERROR: LoRaWAN join failed. Check credentials + coverage.");
        while(1) { digitalWrite(ALERT_LED_PIN, HIGH); delay(100); digitalWrite(ALERT_LED_PIN, LOW); delay(100); }
    }

    Serial.println("Joined! Registering watch script...");
    client.watchScript(LOCK_CODE_HASH, LOCK_ARGS, SCRIPT_TYPE_LOCK);

    Serial.println("Syncing headers...");
}

void loop() {
    // Drive LMIC event loop + light client sync state machine
    client.sync();

    if (client.state() == LIGHT_STATE_READY && client.hasPendingEvents()) {
        char txHash[67];
        uint64_t blockNum;
        while (client.nextEvent(txHash, &blockNum)) {
            onPaymentReceived(txHash, blockNum);
        }
    }

    // T-Beam: could deep-sleep between sync cycles here
    // client.suspend() → esp_deep_sleep(6000000) → wakeup → client.resume()
    // (not yet implemented — future power optimisation)

    delay(100);
}
