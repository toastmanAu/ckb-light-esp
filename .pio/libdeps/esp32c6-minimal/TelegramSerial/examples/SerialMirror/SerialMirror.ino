/*
 * SerialMirror.ino — output to both Serial and Telegram simultaneously
 *
 * Pass &Serial as the mirror argument — every tg.print/println also goes to
 * the hardware UART so you can still watch output via USB while it goes to Telegram.
 *
 * Useful for: remote debugging, test reports, sensor readings.
 */

#include <Arduino.h>
#include <TelegramSerial.h>

#define WIFI_SSID   "YourNetwork"
#define WIFI_PASS   "YourPassword"
#define BOT_TOKEN   "123456789:ABC-YourBotTokenHere"
#define CHAT_ID     "-1001234567890"

// Pass &Serial as the 5th argument — mirrors all output to USB serial too
TelegramSerial tg(WIFI_SSID, WIFI_PASS, BOT_TOKEN, CHAT_ID, &Serial);

unsigned long counter = 0;

void setup() {
    Serial.begin(115200);
    delay(1000);

    tg.begin();  // connects WiFi; Serial mirror means you'll see status locally

    tg.println("=== Device started ===");
    tg.printf("Uptime: 0s  Heap: %u bytes\n", ESP.getFreeHeap());
}

void loop() {
    tg.update();  // always call from loop()

    // Log something every 10 seconds
    static unsigned long last = 0;
    if (millis() - last >= 10000) {
        last = millis();
        counter++;
        // Goes to both Serial (immediately) and Telegram (queued, rate-limited)
        tg.printf("[%lu] Uptime: %lus  Heap: %u\n",
                  counter, millis() / 1000, ESP.getFreeHeap());
    }
}
