#ifndef ESP_NOW_ADHOC_H
#define ESP_NOW_ADHOC_H

#include <Arduino.h>
#include <esp_now.h>
#include <WiFi.h>
#include <functional>

class EspNowAdhoc {
public:
    using RecvCallback = std::function<void(const uint8_t* mac, const uint8_t* data, int len)>;
    using SendCallback = std::function<void(const uint8_t* mac, esp_now_send_status_t status)>;

    EspNowAdhoc();
    bool begin();
    bool addPeer(const uint8_t* mac_addr);
    bool removePeer(const uint8_t* mac_addr);
    esp_err_t send(const uint8_t* mac_addr, const uint8_t* data, size_t len);

    void onReceive(RecvCallback cb);
    void onSend(SendCallback cb);

protected:
    static RecvCallback _recvCb;
    static SendCallback _sendCb;
    static void __recvCb(const uint8_t* mac, const uint8_t* data, int len);
    static void __sendCb(const uint8_t* mac, esp_now_send_status_t status);
};

#endif // ESP_NOW_ADHOC_H
