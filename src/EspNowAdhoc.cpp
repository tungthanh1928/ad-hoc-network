#include "EspNowAdhoc.h"

EspNowAdhoc::RecvCallback EspNowAdhoc::_recvCb = nullptr;
EspNowAdhoc::SendCallback EspNowAdhoc::_sendCb = nullptr;

EspNowAdhoc::EspNowAdhoc() {}

bool EspNowAdhoc::begin() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    if (esp_now_init() != ESP_OK) return false;
    esp_now_register_recv_cb(__recvCb);
    esp_now_register_send_cb(__sendCb);
    return true;
}

bool EspNowAdhoc::addPeer(const uint8_t* mac_addr) {
    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, mac_addr, 6);
    peer.channel = 0;
    peer.ifidx   = WIFI_IF_STA;
    peer.encrypt = false;
    return esp_now_add_peer(&peer) == ESP_OK;
}

bool EspNowAdhoc::removePeer(const uint8_t* mac_addr) {
    return esp_now_del_peer(mac_addr) == ESP_OK;
}

esp_err_t EspNowAdhoc::send(const uint8_t* mac_addr, const uint8_t* data, size_t len) {
    return esp_now_send(mac_addr, data, len);
}

void EspNowAdhoc::onReceive(RecvCallback cb) {
    _recvCb = cb;
}

void EspNowAdhoc::onSend(SendCallback cb) {
    _sendCb = cb;
}

void EspNowAdhoc::__recvCb(const uint8_t* mac, const uint8_t* data, int len) {
    if (_recvCb) _recvCb(mac, data, len);
}

void EspNowAdhoc::__sendCb(const uint8_t* mac, esp_now_send_status_t status) {
    if (_sendCb) _sendCb(mac, status);
}
