/*
 * standard_utxo.ino — CKB UTXO tracker with persistent storage
 *
 * Syncs block filters, tracks live cell set for a watched address,
 * and persists UTXO state to flash (NVS/Preferences) across reboots.
 *
 * Profile: LIGHT_PROFILE_STANDARD
 * Target:  ESP32-S3 with PSRAM (recommended), ESP32 classic (tight)
 *
 * Supported boards (set ONE in platformio.ini build_flags):
 *   -DWY_BOARD_GUITION4848S040        4" 480x480 S3 panel
 *   -DWY_BOARD_WT32_SC01_PLUS         3.5" 480x320 S3 panel
 *   -DWY_BOARD_LILYGO_TDISPLAY_S3     1.9" S3 stick
 *   -DWY_BOARD_CYD                    2.8" classic ESP32 (tight RAM)
 *
 * What this does:
 *   - Connects to CKB node via WiFi
 *   - Downloads & verifies GCS compact block filters
 *   - Tracks incoming/outgoing cells for WATCH_ADDRESS
 *   - Stores UTXO set in NVS — survives reboots
 *   - Displays live balance + UTXO count on screen
 *   - Prints new tx alerts to Serial
 */

#define LIGHT_PROFILE_STANDARD
#include <Arduino.h>
#include <Preferences.h>
#include <wyltek.h>
#include <LightClient.h>
#include <LightConfig.h>
#include <wifi_transport.h>
#include <utxo_store.h>

// ── User config ───────────────────────────────────────────────────────────────
const char* WIFI_SSID     = "your-ssid";
const char* WIFI_PASS     = "your-password";
const char* CKB_NODE_HOST = "192.168.68.87";   // full node host
const uint16_t CKB_PORT   = 8114;

// Address to track — replace with yours
#define WATCH_ADDRESS "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq0scm0z"

// Sync from this block (set to current tip - N to start from recent blocks)
// Use 0 to sync from genesis (slow!) or a recent checkpoint
#define SYNC_FROM_BLOCK  18700000UL

// ── Display ───────────────────────────────────────────────────────────────────
#if defined(WY_HAS_DISPLAY) && WY_HAS_DISPLAY
  #include <WyDisplay.h>
  WyDisplay tft;

  void displayInit()  { tft.begin(); tft.fillScreen(TFT_BLACK); }

  void displayUTXO(uint64_t shannon, uint32_t utxoCount, uint32_t tipBlock) {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE); tft.setTextSize(1);
    tft.setCursor(10, 10); tft.print("CKB UTXO Tracker");

    char line[48];
    // Balance
    snprintf(line, sizeof(line), "%llu.%02llu CKB",
             (unsigned long long)(shannon/100000000ULL),
             (unsigned long long)((shannon%100000000ULL)/1000000ULL));
    tft.setTextColor(TFT_GREEN); tft.setTextSize(3);
    tft.setCursor(10, 40); tft.print(line);

    // UTXO count
    tft.setTextColor(TFT_CYAN); tft.setTextSize(2);
    snprintf(line, sizeof(line), "UTXOs: %lu", (unsigned long)utxoCount);
    tft.setCursor(10, 110); tft.print(line);

    // Tip block
    tft.setTextColor(TFT_DARKGREY); tft.setTextSize(1);
    snprintf(line, sizeof(line), "Block: %lu", (unsigned long)tipBlock);
    tft.setCursor(10, 145); tft.print(line);
  }

  void displayStatus(const char* msg) {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_YELLOW); tft.setTextSize(2);
    tft.setCursor(10, 60); tft.print(msg);
  }
#else
  void displayInit()  {}
  void displayUTXO(uint64_t sh, uint32_t cnt, uint32_t blk) {
    Serial.printf("[UTXO] balance=%llu shannon, utxos=%lu, block=%lu\n",
      (unsigned long long)sh, (unsigned long)cnt, (unsigned long)blk);
  }
  void displayStatus(const char* m) { Serial.printf("[STATUS] %s\n", m); }
#endif

// ── Globals ───────────────────────────────────────────────────────────────────
WiFiTransport  transport;
LightConfig    cfg;
LightClient    client;
UtxoStore      utxos;
Preferences    prefs;

uint32_t lastDisplayMs = 0;
const uint32_t DISPLAY_INTERVAL_MS = 5000;

// ── Callbacks ─────────────────────────────────────────────────────────────────
void onCellReceived(const char* txHash, uint32_t index, uint64_t capacity) {
  Serial.printf("[RX] +%llu shannon  tx=%s[%u]\n",
    (unsigned long long)capacity, txHash, index);
  utxos.add(txHash, index, capacity);
  // Persist updated UTXO count to NVS
  prefs.putUInt("utxo_count", utxos.count());
  prefs.putULong64("balance", utxos.totalCapacity());
}

void onCellSpent(const char* txHash, uint32_t index) {
  Serial.printf("[SPENT] tx=%s[%u]\n", txHash, index);
  utxos.remove(txHash, index);
  prefs.putUInt("utxo_count", utxos.count());
  prefs.putULong64("balance", utxos.totalCapacity());
}

// ── setup() ───────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  Serial.println("\nCKB UTXO Tracker starting...");

  displayInit();
  displayStatus("WiFi...");

  // Restore persisted state
  prefs.begin("ckb-utxo", false);
  uint32_t savedCount   = prefs.getUInt("utxo_count", 0);
  uint64_t savedBalance = prefs.getULong64("balance", 0);
  uint32_t savedBlock   = prefs.getUInt("sync_block", SYNC_FROM_BLOCK);
  Serial.printf("Restored: balance=%llu shannon, utxos=%u, from block=%u\n",
    (unsigned long long)savedBalance, savedCount, savedBlock);

  cfg.watchAddress  = WATCH_ADDRESS;
  cfg.syncFromBlock = savedBlock;
  cfg.trustedNode   = false;     // STANDARD profile verifies filters
  cfg.onCellReceived = onCellReceived;
  cfg.onCellSpent    = onCellSpent;

  char rpcUrl[64];
  snprintf(rpcUrl, sizeof(rpcUrl), "http://%s:%u", CKB_NODE_HOST, CKB_PORT);
  if (!transport.connect(WIFI_SSID, WIFI_PASS, rpcUrl)) {
    Serial.printf("WiFi failed: %s\n", transport.lastError());
    displayStatus("WiFi FAILED");
    while (1) delay(1000);
  }

  client.begin(cfg, &transport);
  displayStatus("Syncing filters...");
  Serial.println("Sync started");
}

// ── loop() ────────────────────────────────────────────────────────────────────
void loop() {
  client.poll();

  // Persist current tip block so we resume from here on next boot
  uint32_t tip = client.tipBlock();
  if (tip > 0) prefs.putUInt("sync_block", tip);

  // Update display periodically
  uint32_t now = millis();
  if (now - lastDisplayMs >= DISPLAY_INTERVAL_MS) {
    lastDisplayMs = now;
    displayUTXO(utxos.totalCapacity(), utxos.count(), tip);
  }
}
