// =============================================================================
// minimal_watch.ino — Watch a CKB address for incoming transactions
//
// Profile: LIGHT_PROFILE_MINIMAL
// Target:  ESP32-C6, ESP32 classic
// Needs:   ~100KB RAM, ~300KB flash
//
// Connects to a CKB light/full node via WiFi.
// Watches one lock script. Prints to Serial when a tx is detected.
// No Merkle verification, no persistent UTXO storage.
// =============================================================================

#define LIGHT_PROFILE_MINIMAL
#include <LightClient.h>

// --- Config ------------------------------------------------------------------
const char* WIFI_SSID     = "your-ssid";
const char* WIFI_PASS     = "your-password";
const char* CKB_NODE_HOST = "192.168.1.100";   // your CKB node or light client
const uint16_t CKB_PORT   = 8116;

// Watch this lock script (secp256k1-blake160, default wallet lock)
// Replace with your address's lock script details
const char* LOCK_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
const char* LOCK_ARGS      = "0xYOUR_20_BYTE_ARGS_HERE";  // from your CKB address

LightClient client;

void setup() {
  Serial.begin(115200);

  // Connect WiFi
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");

  // Init light client
  client.begin(CKB_NODE_HOST, CKB_PORT);
  client.watchScript(LOCK_CODE_HASH, LOCK_ARGS, SCRIPT_TYPE_LOCK);

  Serial.println("Light client started — syncing headers...");
}

void loop() {
  client.sync();

  if (client.state() == LIGHT_STATE_READY && client.hasPendingEvents()) {
    char txHash[67];
    uint64_t blockNum;

    while (client.nextEvent(txHash, &blockNum)) {
      Serial.printf("💰 TX detected! Block #%llu\n  Hash: %s\n", blockNum, txHash);
      // Your action here — GPIO trigger, display update, notification, etc.
    }
  }

  delay(100);
}
