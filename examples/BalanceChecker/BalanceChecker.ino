/*
 * BalanceChecker.ino — CKB address balance checker via LoRa or WiFi
 *
 * Shows live CKB balance for a configured address on the display.
 * Syncs via LoRa (preferred) or WiFi fallback.
 *
 * Supported boards (set ONE in platformio.ini build_flags):
 *   -DWY_BOARD_LILYGO_TDECK              T-Deck (SX1262 + 320x240 display)
 *   -DWY_BOARD_HELTEC_LORA32_V3          Heltec LoRa 32 V3 (SX1262 + OLED)
 *   -DWY_BOARD_LILYGO_TBEAM_SUPREME      T-Beam Supreme (SX1262 + OLED + GPS)
 *   -DWY_BOARD_TTGO_TBEAM_MESHTASTIC     T-Beam classic (SX1276 + OLED)
 *   -DWY_BOARD_CYD                       CYD (WiFi only, no LoRa)
 *
 * Deps (platformio.ini lib_deps):
 *   toastmanAu/CKB-ESP32
 *   toastmanAu/wyltek-embedded-builder
 *   toastmanAu/ckb-light-esp
 *   jgromes/RadioLib   (if using LoRa)
 *   adafruit/Adafruit SSD1306  (if using OLED)
 */

#include <Arduino.h>
#include <wyltek.h>          // board defines (WY_BOARD_*)
#include <LightClient.h>
#include <LightConfig.h>
#include <wifi_transport.h>
#include <lora_transport.h>

// ── User config ───────────────────────────────────────────────────────────────
// Address to watch — replace with your CKB address
#define WATCH_ADDRESS  "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq0scm0z"

// Transport selection — uncomment ONE
#define USE_LORA
// #define USE_WIFI

#ifdef USE_WIFI
const char* WIFI_SSID = "your-ssid";
const char* WIFI_PASS = "your-password";
const char* CKB_RPC   = "http://192.168.68.87:8114";
#endif

// ── Display setup ─────────────────────────────────────────────────────────────
#if defined(WY_DISPLAY_SSD1306) || defined(WY_DISPLAY_SH1106)
  #include <Adafruit_SSD1306.h>
  Adafruit_SSD1306 display(WY_DISPLAY_W, WY_DISPLAY_H, &Wire, -1);
  #define OLED_DISPLAY
  
  void displayInit() {
    #ifdef WY_VEXT_PIN
    pinMode(WY_VEXT_PIN, OUTPUT); digitalWrite(WY_VEXT_PIN, HIGH);
    delay(100);
    #endif
    Wire.begin(WY_DISPLAY_SDA, WY_DISPLAY_SCL);
    display.begin(SSD1306_SWITCHCAPVCC, WY_DISPLAY_ADDR);
    display.clearDisplay();
    display.setTextColor(WHITE);
  }
  
  void displayStatus(const char* line1, const char* line2 = nullptr, const char* line3 = nullptr) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(0, 0);   display.println(line1);
    if (line2) { display.setCursor(0, 16); display.println(line2); }
    if (line3) { display.setCursor(0, 32); display.println(line3); }
    display.display();
  }
  
  void displayBalance(uint64_t shannonBalance) {
    // Convert shannon to CKB (1 CKB = 100,000,000 shannon)
    uint64_t ckbWhole   = shannonBalance / 100000000ULL;
    uint64_t ckbDecimal = (shannonBalance % 100000000ULL) / 1000000ULL; // 2 dp
    char line1[32], line2[32];
    snprintf(line1, sizeof(line1), "CKB Balance:");
    snprintf(line2, sizeof(line2), "%llu.%02llu CKB",
             (unsigned long long)ckbWhole, (unsigned long long)ckbDecimal);
    display.clearDisplay();
    display.setTextSize(1); display.setCursor(0, 0); display.println(line1);
    display.setTextSize(2); display.setCursor(0, 20); display.println(line2);
    display.display();
  }

#elif defined(WY_HAS_DISPLAY) && WY_HAS_DISPLAY
  // TFT display (T-Deck, CYD, etc.) — use LovyanGFX via wyltek
  #include <WyDisplay.h>
  WyDisplay display;
  
  void displayInit() { display.begin(); display.fillScreen(TFT_BLACK); }
  
  void displayStatus(const char* line1, const char* line2 = nullptr, const char* line3 = nullptr) {
    display.fillScreen(TFT_BLACK);
    display.setTextColor(TFT_WHITE);
    display.setTextSize(2);
    display.setCursor(10, 20); display.print(line1);
    if (line2) { display.setCursor(10, 60); display.print(line2); }
    if (line3) { display.setCursor(10, 100); display.print(line3); }
  }
  
  void displayBalance(uint64_t shannonBalance) {
    uint64_t ckbWhole   = shannonBalance / 100000000ULL;
    uint64_t ckbDecimal = (shannonBalance % 100000000ULL) / 1000000ULL;
    char bal[32];
    snprintf(bal, sizeof(bal), "%llu.%02llu CKB",
             (unsigned long long)ckbWhole, (unsigned long long)ckbDecimal);
    display.fillScreen(TFT_BLACK);
    display.setTextColor(TFT_GREEN);
    display.setTextSize(2);
    display.setCursor(10, 20); display.print("CKB Balance");
    display.setTextSize(3);
    display.setCursor(10, 70); display.print(bal);
  }

#else
  // No display — serial output only
  void displayInit() {}
  void displayStatus(const char* l1, const char* l2=nullptr, const char* l3=nullptr) {
    Serial.printf("[STATUS] %s", l1);
    if (l2) Serial.printf(" | %s", l2);
    if (l3) Serial.printf(" | %s", l3);
    Serial.println();
  }
  void displayBalance(uint64_t shannon) {
    Serial.printf("[BALANCE] %llu shannon (%llu.%02llu CKB)\n",
      (unsigned long long)shannon,
      (unsigned long long)(shannon/100000000ULL),
      (unsigned long long)((shannon%100000000ULL)/1000000ULL));
  }
#endif

// ── Globals ───────────────────────────────────────────────────────────────────
LightConfig cfg;

#ifdef USE_LORA
  LoRaTransport transport(WY_LORA_CS, WY_LORA_RST, WY_LORA_IRQ);
#else
  WiFiTransport transport;
#endif

LightClient client;
uint64_t    lastBalance   = UINT64_MAX;
uint32_t    lastPollMs    = 0;
const uint32_t POLL_INTERVAL_MS = 30000; // poll every 30s

// ── setup() ───────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  Serial.println("\nCKB Balance Checker starting...");

  displayInit();
  displayStatus("CKB Balance", "Starting...");

  // Configure light client
  cfg.watchAddress  = WATCH_ADDRESS;
  cfg.trustedNode   = true;

#ifdef USE_LORA
  Serial.println("Transport: LoRa");
  displayStatus("CKB Balance", "LoRa init...");
  if (!transport.begin()) {
    Serial.printf("LoRa init failed: %s\n", transport.lastError());
    displayStatus("LoRa FAIL", transport.lastError());
    while (1) delay(1000);
  }
  client.begin(cfg, &transport);
#else
  Serial.println("Transport: WiFi");
  displayStatus("CKB Balance", "WiFi...");
  if (!transport.connect(WIFI_SSID, WIFI_PASS, CKB_RPC)) {
    Serial.printf("WiFi failed: %s\n", transport.lastError());
    displayStatus("WiFi FAIL", transport.lastError());
    while (1) delay(1000);
  }
  client.begin(cfg, &transport);
#endif

  displayStatus("CKB Balance", "Connected!", "Fetching...");
  Serial.println("Setup complete");
}

// ── loop() ────────────────────────────────────────────────────────────────────
void loop() {
  client.poll();

  uint32_t now = millis();
  if (now - lastPollMs < POLL_INTERVAL_MS && lastBalance != UINT64_MAX) return;
  lastPollMs = now;

  // Fetch balance for watched address
  uint64_t balance = 0;
  if (client.getBalance(WATCH_ADDRESS, &balance)) {
    if (balance != lastBalance) {
      Serial.printf("Balance: %llu shannon\n", (unsigned long long)balance);
      lastBalance = balance;
    }
    displayBalance(balance);
  } else {
    Serial.printf("Balance fetch failed: %s\n", client.lastError());
    displayStatus("CKB Balance", "Fetch failed", client.lastError());
  }
}
