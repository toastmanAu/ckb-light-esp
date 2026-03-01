/*
 * BasicSend.ino — minimal TelegramSerial example
 *
 * Sends ESP32 boot info to a Telegram chat, then reports free heap every 30s.
 *
 * Setup:
 *   1. Create a bot via @BotFather → copy the token
 *   2. Add the bot to a group, or start a DM → get the chat ID
 *      (easiest: message @userinfobot while in the group)
 *   3. Fill in the four defines below and flash
 */

#include <Arduino.h>
#include <TelegramSerial.h>

#define WIFI_SSID   "YourNetwork"
#define WIFI_PASS   "YourPassword"
#define BOT_TOKEN   "123456789:ABC-YourBotTokenHere"
#define CHAT_ID     "-1001234567890"   // group: negative  |  user: positive int

TelegramSerial tg(WIFI_SSID, WIFI_PASS, BOT_TOKEN, CHAT_ID);

void setup() {
    Serial.begin(115200);

    if (!tg.begin()) {
        Serial.println("WiFi failed — messages will queue until connected");
    }

    // Works exactly like Serial
    tg.println("ESP32 online!");
    tg.printf("Chip: %s  Rev: %d\n", ESP.getChipModel(), ESP.getChipRevision());
    tg.printf("Flash: %uMB  Heap: %u bytes\n",
              ESP.getFlashChipSize() / (1024*1024), ESP.getFreeHeap());
}

void loop() {
    tg.update();   // drain send queue — call every loop()

    static unsigned long lastReport = 0;
    if (millis() - lastReport > 30000) {
        tg.printf("Heap: %u bytes free\n", ESP.getFreeHeap());
        lastReport = millis();
    }
}
