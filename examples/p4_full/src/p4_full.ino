// =============================================================================
// p4_full.ino — Full light client with CKB-VM on ESP32-P4
//
// Profile: LIGHT_PROFILE_FULL
// Target:  ESP32-P4 (400MHz dual RISC-V, 32MB PSRAM)
// Needs:   PSRAM enabled in partition config
//
// Demonstrates:
//   - Header sync + Eaglesong PoW verification
//   - GCS block filter matching
//   - Merkle proof verification
//   - Persistent UTXO storage (LittleFS)
//   - CKB-VM interpreter for custom lock scripts
// =============================================================================

#define LIGHT_PROFILE_FULL
#include <LightClient.h>

// --- Config ------------------------------------------------------------------
const char* WIFI_SSID     = "your-ssid";
const char* WIFI_PASS     = "your-password";
const char* CKB_NODE_HOST = "192.168.1.100";
const uint16_t CKB_PORT   = 8116;

// Watch multiple scripts
const char* SCRIPTS[][2] = {
  { "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", "0xYOUR_ARGS_1" },
  { "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", "0xYOUR_ARGS_2" },
};

LightClient client;

void setup() {
  Serial.begin(115200);

  // Confirm PSRAM available (required for FULL profile)
  if (!psramFound()) {
    Serial.println("ERROR: PSRAM not found. LIGHT_PROFILE_FULL requires PSRAM.");
    while(1) delay(1000);
  }
  Serial.printf("PSRAM: %u KB free\n", ESP.getFreePsram() / 1024);

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println("\nWiFi connected");

  client.begin(CKB_NODE_HOST, CKB_PORT);

  for (auto& s : SCRIPTS) {
    client.watchScript(s[0], s[1], SCRIPT_TYPE_LOCK);
  }

  Serial.println("Full light client started.");
}

void loop() {
  client.sync();

  Serial.printf("[%llu] State: %d | Tip: #%llu\n",
    millis(), client.state(), client.tipBlockNumber());

  if (client.hasPendingEvents()) {
    char txHash[67];
    uint64_t blockNum;
    while (client.nextEvent(txHash, &blockNum)) {
      // Verify inclusion via Merkle proof before trusting
      const char* blockHash = client.tipBlockHash();  // or fetch specific block hash
      bool verified = client.verifyInclusion(txHash, blockHash);
      Serial.printf("%s TX @ block #%llu: %s\n",
        verified ? "✅ Verified" : "⚠️  Unverified", blockNum, txHash);
    }
  }

  delay(500);
}
