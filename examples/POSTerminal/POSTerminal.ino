/*
 * POSTerminal.ino — CKB point-of-sale terminal via LoRa
 *
 * Generates a CKB payment invoice (address + amount QR code),
 * monitors the light client for incoming payments, and confirms
 * on-screen when payment is received.
 *
 * Supported boards (set ONE in platformio.ini build_flags):
 *   -DWY_BOARD_LILYGO_TDECK          Best: 320x240 colour display + touch + keyboard
 *   -DWY_BOARD_HELTEC_LORA32_V3      Good: compact, OLED only (no QR — text invoice)
 *   -DWY_BOARD_LILYGO_TBEAM_SUPREME  Good: OLED + GPS for mobile POS
 *
 * Deps (platformio.ini lib_deps):
 *   toastmanAu/CKB-ESP32
 *   toastmanAu/wyltek-embedded-builder
 *   toastmanAu/ckb-light-esp
 *   jgromes/RadioLib
 *   adafruit/Adafruit SSD1306   (OLED boards)
 *   ricmoo/QRCode               (QR generation, TFT boards)
 */

#include <Arduino.h>
#include <wyltek.h>
#include <LightClient.h>
#include <LightConfig.h>
#include <lora_transport.h>
#include <ckb_hex.h>

// ── User config ───────────────────────────────────────────────────────────────
// Merchant CKB address — replace with your address
#define MERCHANT_ADDRESS "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq0scm0z"

// Default price (shannon). 1 CKB = 100,000,000 shannon
// 1000 CKB default — change via button/keyboard at runtime
#define DEFAULT_PRICE_SHANNON  100000000000ULL  // 1000 CKB

// Minimum confirmations before showing "PAID"
#define MIN_CONFIRMATIONS  1

// Payment poll interval
#define POLL_INTERVAL_MS  10000

// ── Display ───────────────────────────────────────────────────────────────────
#if defined(WY_DISPLAY_SSD1306) || defined(WY_DISPLAY_SH1106)
  #include <Adafruit_SSD1306.h>
  Adafruit_SSD1306 oled(WY_DISPLAY_W, WY_DISPLAY_H, &Wire, -1);
  #define HAS_OLED

  void displayInit() {
    #ifdef WY_VEXT_PIN
    pinMode(WY_VEXT_PIN, OUTPUT); digitalWrite(WY_VEXT_PIN, HIGH); delay(100);
    #endif
    Wire.begin(WY_DISPLAY_SDA, WY_DISPLAY_SCL);
    oled.begin(SSD1306_SWITCHCAPVCC, WY_DISPLAY_ADDR);
    oled.clearDisplay(); oled.setTextColor(WHITE);
  }

  // OLED: can't show QR — show address + amount as text
  void showInvoice(const char* address, uint64_t shannon) {
    uint64_t ckb = shannon / 100000000ULL;
    char line[22];
    oled.clearDisplay();
    oled.setTextSize(1);
    oled.setCursor(0, 0);  oled.println("CKB INVOICE");
    oled.setCursor(0, 12); oled.println("Amount:");
    snprintf(line, sizeof(line), "%llu CKB", (unsigned long long)ckb);
    oled.setCursor(0, 22); oled.println(line);
    // Show last 12 chars of address
    oled.setCursor(0, 38); oled.println("To:");
    oled.setCursor(0, 48); oled.println(address + (strlen(address) - 12));
    oled.display();
  }

  void showPaid(uint64_t shannon) {
    oled.clearDisplay();
    oled.setTextSize(2);
    oled.setCursor(16, 10); oled.println("PAID!");
    oled.setTextSize(1);
    char line[22];
    snprintf(line, sizeof(line), "%llu CKB", (unsigned long long)(shannon/100000000ULL));
    oled.setCursor(16, 40); oled.println(line);
    oled.display();
  }

  void showStatus(const char* msg) {
    oled.clearDisplay();
    oled.setTextSize(1);
    oled.setCursor(0, 24); oled.println(msg);
    oled.display();
  }

#elif defined(WY_HAS_DISPLAY) && WY_HAS_DISPLAY
  // TFT display (T-Deck etc.)
  #include <WyDisplay.h>
  #include <WyQR.h>    // QR code rendering via wyltek
  WyDisplay tft;

  void displayInit() { tft.begin(); tft.fillScreen(TFT_BLACK); }

  void showInvoice(const char* address, uint64_t shannon) {
    // Build ckb: URI for QR
    char uri[128];
    snprintf(uri, sizeof(uri), "ckb:%s?amount=%llu",
             address, (unsigned long long)shannon);

    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE); tft.setTextSize(2);
    tft.setCursor(10, 5); tft.print("CKB Invoice");

    // QR code — centred below header
    WyQR::draw(tft, uri, 40, 30, 240);

    // Amount below QR
    char amtStr[32];
    snprintf(amtStr, sizeof(amtStr), "%llu.%02llu CKB",
             (unsigned long long)(shannon/100000000ULL),
             (unsigned long long)((shannon%100000000ULL)/1000000ULL));
    tft.setTextSize(2); tft.setTextColor(TFT_YELLOW);
    tft.setCursor(10, 210); tft.print(amtStr);
  }

  void showPaid(uint64_t shannon) {
    tft.fillScreen(TFT_GREEN);
    tft.setTextColor(TFT_BLACK); tft.setTextSize(4);
    tft.setCursor(40, 80); tft.print("PAID!");
    char amtStr[32];
    snprintf(amtStr, sizeof(amtStr), "%llu CKB",
             (unsigned long long)(shannon/100000000ULL));
    tft.setTextSize(2); tft.setCursor(50, 160); tft.print(amtStr);
  }

  void showStatus(const char* msg) {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE); tft.setTextSize(2);
    tft.setCursor(10, 110); tft.print(msg);
  }

#else
  void displayInit() {}
  void showInvoice(const char* addr, uint64_t sh) {
    Serial.printf("[INVOICE] addr=%s amount=%llu shannon\n", addr, (unsigned long long)sh);
  }
  void showPaid(uint64_t sh) {
    Serial.printf("[PAID] %llu shannon\n", (unsigned long long)sh);
  }
  void showStatus(const char* msg) { Serial.printf("[STATUS] %s\n", msg); }
#endif

// ── POS State machine ─────────────────────────────────────────────────────────
enum POSState { POS_IDLE, POS_WAITING, POS_CONFIRMED };

POSState    posState      = POS_IDLE;
uint64_t    invoiceShannon = DEFAULT_PRICE_SHANNON;
uint64_t    lastBalance   = 0;
uint32_t    lastPollMs    = 0;

LoRaTransport transport(WY_LORA_CS, WY_LORA_RST, WY_LORA_IRQ);
LightConfig cfg;
LightClient client;

// ── setup() ───────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  Serial.println("\nCKB POS Terminal starting...");

  displayInit();
  showStatus("LoRa init...");

  if (!transport.begin()) {
    Serial.printf("LoRa failed: %s\n", transport.lastError());
    showStatus("LoRa FAILED");
    while (1) delay(1000);
  }

  cfg.watchAddress = MERCHANT_ADDRESS;
  cfg.trustedNode  = true;
  client.begin(cfg, &transport);

  // Fetch baseline balance so we can detect incoming payments
  showStatus("Syncing...");
  if (client.getBalance(MERCHANT_ADDRESS, &lastBalance)) {
    Serial.printf("Baseline balance: %llu shannon\n", (unsigned long long)lastBalance);
  }

  posState = POS_IDLE;
  showInvoice(MERCHANT_ADDRESS, invoiceShannon);
  Serial.println("Ready");
}

// ── loop() ────────────────────────────────────────────────────────────────────
void loop() {
  client.poll();

#if defined(WY_BOOT_BTN)
  // Press BOOT button to reset to IDLE (ready for next customer)
  static bool lastBtn = HIGH;
  bool btn = digitalRead(WY_BOOT_BTN);
  if (lastBtn == HIGH && btn == LOW) {
    posState = POS_IDLE;
    lastPollMs = 0;
    showInvoice(MERCHANT_ADDRESS, invoiceShannon);
    Serial.println("Reset to IDLE");
  }
  lastBtn = btn;
#endif

  if (posState == POS_CONFIRMED) return; // wait for button press

  uint32_t now = millis();
  if (now - lastPollMs < POLL_INTERVAL_MS) return;
  lastPollMs = now;

  uint64_t balance = 0;
  if (!client.getBalance(MERCHANT_ADDRESS, &balance)) {
    Serial.printf("Balance fetch failed: %s\n", client.lastError());
    return;
  }

  if (balance > lastBalance) {
    uint64_t received = balance - lastBalance;
    Serial.printf("Payment detected: +%llu shannon\n", (unsigned long long)received);

    if (received >= invoiceShannon) {
      // Full payment (or over-payment)
      posState = POS_CONFIRMED;
      showPaid(received);
      Serial.println("PAID ✓");
    } else {
      // Partial payment — show remaining
      uint64_t remaining = invoiceShannon - received;
      char msg[32];
      snprintf(msg, sizeof(msg), "Part paid -%llu CKB",
               (unsigned long long)(remaining/100000000ULL));
      showStatus(msg);
      Serial.printf("Partial: still need %llu shannon\n", (unsigned long long)remaining);
    }
    lastBalance = balance;
  }
}
