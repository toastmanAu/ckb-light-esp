// bitchat_ble.cpp — BitChat BLE transport implementation
// toastmanAu/ckb-light-esp
//
// NimBLE-Arduino based. Runs as simultaneous peripheral (advertise) + central (scan/connect).
// All received BLE packets are fed into bc_mesh_receive().
// All relay callbacks from the mesh engine are sent to all BLE peers.

#include "bitchat_ble.h"

#ifndef HOST_TEST

// ─── Constructor ──────────────────────────────────────────────────────────────

BitchatBLE::BitchatBLE()
    : _mesh(nullptr), _server(nullptr), _service(nullptr),
      _characteristic(nullptr), _last_scan_ms(0), _scanning(false),
      _tx_count(0), _rx_count(0)
{
    memset(_peers, 0, sizeof(_peers));
    snprintf(_nickname, sizeof(_nickname), "bitchat-esp32");
}

// ─── begin ────────────────────────────────────────────────────────────────────

void BitchatBLE::begin(BitchatMesh* mesh) {
    _mesh = mesh;

    // Init NimBLE stack
    NimBLEDevice::init(_nickname);
    NimBLEDevice::setMTU(BC_BLE_MTU);
    NimBLEDevice::setPower(ESP_PWR_LVL_P3);  // +3 dBm

    // Set security params (no bonding required — BitChat uses Noise for E2E)
    NimBLEDevice::setSecurityAuth(false, false, false);  // no pair/bond/mitm

    // Init GATT server (peripheral role)
    _init_server();

    // Register relay callback with mesh
    // We need a trampoline since bc_mesh_set_callbacks takes C function pointers
    // The ctx pointer holds 'this'
    bc_mesh_set_callbacks(
        _mesh,
        _mesh->on_message,  // preserve existing callbacks
        _mesh->on_peer,
        _relay_cb,
        _mesh->on_noise,
        this                // ctx = this BitchatBLE instance
    );

    _start_advertising();

    // Start first scan immediately
    scan();
}

void BitchatBLE::setNickname(const char* nick) {
    strncpy(_nickname, nick, BC_MAX_NICKNAME);
    _nickname[BC_MAX_NICKNAME] = '\0';
    // Update BLE device name
    NimBLEDevice::init(_nickname);
}

// ─── _init_server ─────────────────────────────────────────────────────────────

void BitchatBLE::_init_server() {
    _server = NimBLEDevice::createServer();
    _server->setCallbacks(this);
    _server->setConnectParams(
        /* minInterval */ 0x18,  // 30ms
        /* maxInterval */ 0x50,  // 100ms
        /* latency */     0,
        /* timeout */     400    // 4s supervision timeout
    );

    // Create BitChat GATT service
    _service = _server->createService(BC_BLE_SERVICE_UUID);

    // Create characteristic with write + notify properties
    _characteristic = _service->createCharacteristic(
        BC_BLE_CHAR_UUID,
        NIMBLE_PROPERTY::WRITE |
        NIMBLE_PROPERTY::WRITE_NR |  // write without response (faster for relay)
        NIMBLE_PROPERTY::NOTIFY
    );
    _characteristic->setCallbacks(this);

    // CCCD descriptor is created automatically by NimBLE when NOTIFY is set

    _service->start();
}

void BitchatBLE::_start_advertising() {
    NimBLEAdvertising* pAdv = NimBLEDevice::getAdvertising();

    NimBLEAdvertisementData advData;
    advData.setFlags(BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP);
    advData.addServiceUUID(BC_BLE_SERVICE_UUID);
    // Truncated name in adv packet (limited to ~10 chars to fit in 31-byte payload)
    char shortName[12];
    snprintf(shortName, sizeof(shortName), "bc-%.8s", _nickname);
    advData.setName(shortName);

    NimBLEAdvertisementData scanRsp;
    scanRsp.setName(_nickname);  // Full name in scan response

    pAdv->setAdvertisementData(advData);
    pAdv->setScanResponseData(scanRsp);
    pAdv->setScanFilter(false, false);  // accept all connections
    pAdv->setMinInterval(0x50);   // 80ms
    pAdv->setMaxInterval(0xA0);   // 160ms
    pAdv->start();
}

// ─── tick ─────────────────────────────────────────────────────────────────────

void BitchatBLE::tick() {
    uint32_t now = millis();

    // Periodic scan (BC_BLE_SCAN_INTERVAL seconds between passes)
    if (!_scanning && (now - _last_scan_ms) > (uint32_t)(BC_BLE_SCAN_INTERVAL * 1000)) {
        scan();
    }

    // Age out dead peers
    for (int i = 0; i < BC_BLE_MAX_CONNECTIONS; i++) {
        if (_peers[i].active && _peers[i].client &&
            !_peers[i].client->isConnected()) {
            // Peer disconnected
            _peers[i].active = false;
            _peers[i].client = nullptr;
            _peers[i].charac = nullptr;
        }
    }
}

// ─── scan ─────────────────────────────────────────────────────────────────────

void BitchatBLE::scan() {
    _last_scan_ms = millis();
    _scanning = true;

    NimBLEScan* scanner = NimBLEDevice::getScan();
    scanner->setScanCallbacks(this, false);
    scanner->setActiveScan(true);        // request scan responses
    scanner->setInterval(0x50);          // 50ms scan interval
    scanner->setWindow(0x30);            // 30ms scan window
    // Filter to devices advertising the BitChat service UUID
    // NimBLE doesn't have service UUID scan filter — we filter in onResult()
    scanner->start(BC_BLE_SCAN_DURATION, false /* not blocking */);
}

// ─── stop ─────────────────────────────────────────────────────────────────────

void BitchatBLE::stop() {
    NimBLEDevice::getAdvertising()->stop();
    NimBLEDevice::getScan()->stop();
    for (int i = 0; i < BC_BLE_MAX_CONNECTIONS; i++) {
        if (_peers[i].active && _peers[i].client) {
            _peers[i].client->disconnect();
            _peers[i].active = false;
        }
    }
}

// ─── peerCount ───────────────────────────────────────────────────────────────

uint8_t BitchatBLE::peerCount() const {
    uint8_t n = 0;
    for (int i = 0; i < BC_BLE_MAX_CONNECTIONS; i++)
        if (_peers[i].active) n++;
    return n;
}

// ─── _relay_cb (static trampoline) ───────────────────────────────────────────

void BitchatBLE::_relay_cb(const uint8_t* buf, size_t len, int src_peer, void* ctx) {
    BitchatBLE* self = static_cast<BitchatBLE*>(ctx);
    if (!self) return;

    // Send to all connected peers except the source
    for (int i = 0; i < BC_BLE_MAX_CONNECTIONS; i++) {
        if (!self->_peers[i].active) continue;
        if (i == src_peer) continue;  // don't echo back to source
        self->_send_to_peer(&self->_peers[i], buf, len);
    }
}

// ─── _send_to_peer ────────────────────────────────────────────────────────────

void BitchatBLE::_send_to_peer(BLEPeer* peer, const uint8_t* buf, size_t len) {
    if (!peer || !peer->active || !peer->client || !peer->client->isConnected()) return;
    if (!peer->charac) return;

    // BLE ATT max write ~512 bytes (negotiated MTU - 3).
    // BitChat pads to block sizes — packets are always 256/512/1024/2048 bytes.
    // For 256-byte packets: fits in single BLE write.
    // For 512-byte packets: fits if MTU negotiated to 515+.
    // Larger packets: need fragmentation at this layer (not BitChat fragmentation —
    // that's handled above; this is raw BLE ATT chunking).
    //
    // In practice: 256-byte padded packets fit in one write at default MTU.
    // We use WRITE_NR (no response) for throughput.

    if (len <= BC_BLE_MTU - 3) {
        // Fits in one write
        peer->charac->writeValue(buf, len, false /* no response */);
    } else {
        // Chunk it — rare for 256/512 byte packets at MTU=512
        size_t chunk = BC_BLE_MTU - 3;
        for (size_t off = 0; off < len; off += chunk) {
            size_t sz = (len - off < chunk) ? (len - off) : chunk;
            peer->charac->writeValue(buf + off, sz, false);
            // Small delay between chunks to avoid BLE queue overflow
            delay(2);
        }
    }
    _tx_count++;
}

// ─── _connect_to ──────────────────────────────────────────────────────────────

void BitchatBLE::_connect_to(NimBLEAdvertisedDevice* device) {
    // Check if already connected
    for (int i = 0; i < BC_BLE_MAX_CONNECTIONS; i++) {
        if (_peers[i].active && _peers[i].client &&
            _peers[i].client->getPeerAddress() == device->getAddress()) {
            return;  // already connected
        }
    }

    BLEPeer* slot = _find_peer_slot();
    if (!slot) return;  // no free slots

    NimBLEClient* client = NimBLEDevice::createClient();
    if (!client->connect(device->getAddress())) {
        NimBLEDevice::deleteClient(client);
        return;
    }

    // Find BitChat service + characteristic
    NimBLERemoteService* svc = client->getService(BC_BLE_SERVICE_UUID);
    if (!svc) {
        client->disconnect();
        NimBLEDevice::deleteClient(client);
        return;
    }

    NimBLERemoteCharacteristic* charac = svc->getCharacteristic(BC_BLE_CHAR_UUID);
    if (!charac) {
        client->disconnect();
        NimBLEDevice::deleteClient(client);
        return;
    }

    // Register for notifications (receive packets from this peer)
    int slot_idx = slot - _peers;
    if (charac->canNotify()) {
        charac->subscribe(true,
            [this, slot_idx](NimBLERemoteCharacteristic* c, uint8_t* data,
                              size_t len, bool isNotify) {
                this->_on_packet_received(data, len, slot_idx);
            }
        );
        slot->subscribed = true;
    }

    slot->client       = client;
    slot->charac       = charac;
    slot->peer_id_known = false;
    slot->last_rx_ms   = millis();
    slot->active       = true;

    // Also send our announce so the remote peer adds us to their peer table
    bc_mesh_send_announce(_mesh, nullptr /* no fingerprint yet */, millis());
}

// ─── _on_packet_received ──────────────────────────────────────────────────────

void BitchatBLE::_on_packet_received(const uint8_t* data, size_t len, int peer_slot) {
    if (!data || len < 2) return;
    _rx_count++;

    if (peer_slot >= 0 && peer_slot < BC_BLE_MAX_CONNECTIONS) {
        _peers[peer_slot].last_rx_ms = millis();

        // Learn sender ID from packet (so we can skip echoing back to them)
        if (!_peers[peer_slot].peer_id_known) {
            BitchatPacket pkt;
            if (bc_packet_decode(data, len, &pkt)) {
                memcpy(_peers[peer_slot].peer_id, pkt.sender_id, BC_SENDER_ID_SIZE);
                _peers[peer_slot].peer_id_known = true;
            }
        }
    }

    // Feed into mesh relay engine
    bc_mesh_receive(_mesh, data, len, peer_slot, millis());
}

// ─── _find_peer_slot ─────────────────────────────────────────────────────────

BLEPeer* BitchatBLE::_find_peer_slot() {
    for (int i = 0; i < BC_BLE_MAX_CONNECTIONS; i++) {
        if (!_peers[i].active) return &_peers[i];
    }
    return nullptr;
}

BLEPeer* BitchatBLE::_find_peer_by_client(NimBLEClient* client) {
    for (int i = 0; i < BC_BLE_MAX_CONNECTIONS; i++) {
        if (_peers[i].active && _peers[i].client == client)
            return &_peers[i];
    }
    return nullptr;
}

// ─── NimBLEServerCallbacks ────────────────────────────────────────────────────

void BitchatBLE::onConnect(NimBLEServer* server, ble_gap_conn_desc* desc) {
    // A central connected to US (peripheral role).
    // We don't need to do much — they'll write to the characteristic to send packets.
    // Keep advertising so other peers can still find us.
    NimBLEDevice::getAdvertising()->start();
}

void BitchatBLE::onDisconnect(NimBLEServer* server) {
    NimBLEDevice::getAdvertising()->start();
}

// ─── NimBLECharacteristicCallbacks ────────────────────────────────────────────

void BitchatBLE::onWrite(NimBLECharacteristic* pChar, ble_gap_conn_desc* desc) {
    // A central wrote a packet to our characteristic.
    // In central role, we write to remote; in peripheral role, remotes write to us.
    NimBLEAttValue val = pChar->getValue();
    if (val.size() < 2) return;

    // Determine which peer slot this write came from by connection handle
    // NimBLE doesn't directly give us a client ptr here — use conn handle
    // For now, pass -1 (unknown source — won't affect relay, just won't echo back)
    _on_packet_received((const uint8_t*)val.data(), val.size(), -1);
}

// ─── NimBLEScanCallbacks ─────────────────────────────────────────────────────

void BitchatBLE::onResult(NimBLEAdvertisedDevice* advertisedDevice) {
    // Filter: only connect to devices advertising the BitChat service
    if (!advertisedDevice->isAdvertisingService(NimBLEUUID(BC_BLE_SERVICE_UUID))) {
        return;
    }

    // Don't connect if we're full
    if (peerCount() >= BC_BLE_MAX_CONNECTIONS) return;

    // Stop scan and connect
    NimBLEDevice::getScan()->stop();
    _connect_to(advertisedDevice);
}

void BitchatBLE::onScanEnd(NimBLEScanResults results) {
    _scanning = false;
}

#endif // HOST_TEST
