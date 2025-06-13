#include <Arduino.h>
#include <WebServer.h>
#include <WiFi.h>
#include "EspNowAdhoc.h"
#include "AESHelper.h"
#include <vector>
#include <map>
#include <deque>
#include <random>
#include "esp_system.h"
#include "esp_spi_flash.h"

static const char* AP_PASS = "12345678";
static const uint8_t BROADCAST_MAC[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

WebServer server(80);
EspNowAdhoc espnow;

struct PeerInfo {
  String macStr;
  uint8_t mac[6];
  uint32_t lastActive;
};

std::vector<PeerInfo> peerList;
std::vector<String> msgList;
std::vector<String> logList;

// Nonce tracking for replay protection
std::map<String, uint32_t> lastNonces;

// Rate limiting data
struct RateLimitInfo {
  std::deque<uint32_t> timestamps;
};
std::map<String, RateLimitInfo> rateLimits;

const uint32_t RATE_LIMIT_WINDOW_MS = 1000;  // 1 second window
const size_t MAX_MSG_PER_WINDOW     = 10;    // Max 10 messages per second
const size_t MAX_QUEUE_SIZE = 100;

std::map<String, uint32_t> lastReplayLogTime;
const uint32_t REPLAY_LOG_INTERVAL_MS = 1000;

uint8_t myMac[6];

const uint8_t aesKey[16] = {
  0x00,0x01,0x02,0x03,
  0x04,0x05,0x06,0x07,
  0x08,0x09,0x0A,0x0B,
  0x0C,0x0D,0x0E,0x0F
};

// --- Performance measurement variables ---
uint32_t lastPerfUpdate = 0;
uint32_t bytesReceivedLastInterval = 0;
uint32_t packetsReceivedLastInterval = 0;
float currentThroughputBps = 0.0;
float currentPacketRate = 0.0;

// Performance history for CSV export
struct PerfRecord {
  uint32_t timestampMs;
  uint32_t throughputBps;
  uint32_t packetCount;
};

std::vector<PerfRecord> perfHistory;
const size_t MAX_HISTORY_SIZE = 300; // 5 minutes of data

void generateIV(uint8_t* iv, size_t len = 12) {
  for (size_t i = 0; i < len; i++) {
    iv[i] = esp_random() & 0xFF;
  }
}

String toHex(const uint8_t* data, size_t len) {
  String s; char b[3];
  for (size_t i = 0; i < len; i++) {
    snprintf(b, 3, "%02X", data[i]);
    s += b;
    if (i + 1 < len) s += " ";
  }
  return s;
}

void formatMac(const uint8_t* mac, char* buf) {
  snprintf(buf, 18,
    "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2],
    mac[3], mac[4], mac[5]
  );
}

struct Stats {
  uint32_t totalSent        = 0;
  uint32_t totalSendFail    = 0;
  uint32_t totalReceived    = 0;
  uint32_t totalDecryptFail = 0;
  uint32_t totalReplay      = 0;
  uint64_t totalSentBytes    = 0;
  uint64_t totalReceivedBytes= 0;
  std::map<String, uint32_t> sentPerPeer;
  std::map<String, uint32_t> recvPerPeer;
} stats;

uint32_t lastPingTime = 0;
const uint32_t PING_INTERVAL_MS = 500;

// --- Web handler declarations ---
void handleRoot();
void handlePeers();
void handleMessages();
void handleLogs();
void handleSend();
void handleIp();
void handleEncodedMessages();
void handleStats();
void handleMac();
void handleMemInfo();
void handleDownloadPerfCsv();

static const char htmlPage[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>ESP32 Chat GUI</title>
  <style>
    body {
      margin: 0; padding: 20px; font-family: Arial, sans-serif;
      background: #ccc;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      box-sizing: border-box;
    }
    #container {
      width: 1200px;
      height: 720px;
      background: #fff;
      border-radius: 15px;
      display: flex;
      gap: 20px;
      box-sizing: border-box;
      padding: 20px;
    }
    #left, #right {
      background: #f0f0f0;
      border-radius: 15px;
      padding: 15px;
      box-sizing: border-box;
      display: flex;
      flex-direction: column;
    }
    #left {
      flex: 1.5;
    }
    #right {
      flex: 1;
      display: flex;
      flex-direction: column;
    }
    h2 {
      margin: 0 0 12px 0;
      font-weight: bold;
      font-size: 1.4em;
      text-align: center;
    }
    select, input[type="text"] {
      width: 100%;
      padding: 8px 12px;
      font-size: 1em;
      border-radius: 15px;
      border: 1px solid #aaa;
      margin-bottom: 15px;
      outline: none;
      box-sizing: border-box;
    }
    #messages, #log, #encodedMessages {
      background: #fff;
      border-radius: 15px;
      padding: 12px;
      font-family: monospace;
      font-size: 1em;
      line-height: 1.4em;
      border: 1px solid #ddd;
      word-break: break-word;
      overflow-wrap: break-word;
      white-space: pre-wrap;
      margin-bottom: 15px;
    }
    #messages {
      flex: 1;
      overflow-y: auto;
    }
    #log {
      height: 300px;
      overflow-y: auto;
    }
    #encodedMessages {
      height: 150px;
      margin-bottom: 15px;
      overflow-y: auto;
    }
    #inputRow {
      display: flex;
      gap: 12px;
    }
    #msgInput {
      flex: 1;
      padding: 10px 15px;
      font-size: 1em;
      border-radius: 15px;
      border: 1px solid #aaa;
      outline: none;
    }
    #sendBtn {
      padding: 10px 20px;
      font-size: 1em;
      border-radius: 15px;
      background-color: #1976d2;
      border: none;
      color: white;
      cursor: pointer;
      transition: background-color 0.3s ease;
    }
    #sendBtn:hover {
      background-color: #145ea8;
    }
    #sendStatus {
      margin-top: 5px;
      font-style: italic;
      height: 20px;
      color: green;
    }
    #info p {
      margin: 5px 0;
      font-size: 1em;
    }
    #stats {
      height: auto;
      overflow-y: visible;
      margin-top: 0;
      background: #f9f9f9;
      border-radius: 12px;
      padding: 15px 20px;
      font-family: monospace;
      font-size: 0.95em;
      color: #222;
      line-height: 1.5em;
      box-shadow: 0 2px 6px rgba(0,0,0,0.1);
      border: 1px solid #ddd;
    }
    #stats h4 {
      margin: 10px 0 5px 0;
      color: #555;
      font-weight: bold;
      font-size: 1em;
    }
    #stats .section {
      margin-bottom: 10px;
    }
    #meminfo {
      margin-top: 10px;
      font-family: monospace;
      font-size: 0.9em;
      color: #444;
    }
    #downloadCsvBtn {
      margin-top: 10px;
      padding: 10px 20px;
      border-radius: 15px;
      background-color: #4caf50;
      color: white;
      border: none;
      cursor: pointer;
      font-size: 1em;
      transition: background-color 0.3s ease;
    }
    #downloadCsvBtn:hover {
      background-color: #388e3c;
    }
  </style>
</head>
<body>
  <div id="container">
    <div id="left">
      <h2>Thông tin kết nối</h2>
      <div id="info">
        <p><b>Địa chỉ MAC ESP32 host:</b> <span id="selectedPeerMac">---</span></p>
        <p><b>Địa chỉ IP client truy cập GUI:</b> <span id="espIp">---</span></p>
      </div>
      <h2>Tin nhắn mã hóa (hex)</h2>
      <div id="encodedMessages"></div>
      <h2>Danh sách peers</h2>
      <select id="peerSelect"></select>
      <div id="messages">Hiển thị tin nhắn</div>
      <div id="inputRow">
        <input type="text" id="msgInput" placeholder="Ô nhập tin nhắn" maxlength="512" />
        <button id="sendBtn">Gửi</button>
      </div>
      <div id="sendStatus"></div>
    </div>
    <div id="right">
      <h2>Log</h2>
      <div id="log">Hiển thị log</div>
      <div id="stats">
        <h3>Thống kê</h3>
        <pre id="statsContent">Đang tải thống kê...</pre>
        <button id="downloadCsvBtn">CSV</button>
        <div id="meminfo">Đang tải thông tin RAM & Flash...</div>
      </div>
    </div>
  </div>
<script>
const peerSelect = document.getElementById("peerSelect");
const messagesDiv = document.getElementById("messages");
const logDiv = document.getElementById("log");
const encodedMessagesDiv = document.getElementById("encodedMessages");
const msgInput = document.getElementById("msgInput");
const sendBtn = document.getElementById("sendBtn");
const sendStatus = document.getElementById("sendStatus");
const selectedPeerMacSpan = document.getElementById("selectedPeerMac");
const espIpSpan = document.getElementById("espIp");
const statsContent = document.getElementById("statsContent");
const memInfoDiv = document.getElementById("meminfo");
const downloadCsvBtn = document.getElementById("downloadCsvBtn");
let currentPeer = "broadcast";
let peers = [];
function updatePeers() {
  fetch("/peers").then(r => r.json()).then(data => {
    peers = data;
    populatePeers();
  });
}
function populatePeers() {
  peerSelect.innerHTML = "";
  peers.forEach(peer => {
    const opt = document.createElement("option");
    opt.value = peer;
    opt.textContent = (peer === "broadcast") ? "Gửi tới tất cả (Broadcast)" : peer;
    peerSelect.appendChild(opt);
  });
  if(!peers.includes(currentPeer)){
    currentPeer = peers.length > 0 ? peers[0] : "broadcast";
  }
  peerSelect.value = currentPeer;
}
peerSelect.addEventListener("change", () => {
  currentPeer = peerSelect.value;
});
function updateMessages() {
  fetch("/messages").then(r => r.json()).then(data => {
    messagesDiv.textContent = data.join("\n");
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  });
}
function updateLogs() {
  fetch("/logs").then(r => r.json()).then(data => {
    logDiv.textContent = data.join("\n");
    logDiv.scrollTop = logDiv.scrollHeight;
  });
}
function updateEncodedMessages(){
  fetch("/encodedMessages").then(r => r.json()).then(data => {
    encodedMessagesDiv.textContent = data.join("\n");
    encodedMessagesDiv.scrollTop = encodedMessagesDiv.scrollHeight;
  });
}
function updateIp() {
  fetch("/ip").then(r => r.text()).then(ip => {
    espIpSpan.textContent = ip;
  });
}
function updateMac() {
  fetch("/mac").then(r => r.text()).then(mac => {
    selectedPeerMacSpan.textContent = mac;
  });
}
function updateStats(){
  fetch("/stats").then(r => r.json()).then(data => {
    let html = "";
    html += `<div class="section">`;
    html += `<div>Tổng tin nhắn gửi thành công: <b>${data.totalSent}</b></div>`;
    html += `<div>Tổng tin nhắn gửi thất bại: <b>${data.totalSendFail}</b></div>`;
    html += `<div>Tổng tin nhắn nhận thành công: <b>${data.totalReceived}</b></div>`;
    html += `<div>Tin nhắn giải mã lỗi: <b>${data.totalDecryptFail}</b></div>`;
    html += `<div>Tin nhắn replay bị phát hiện: <b>${data.totalReplay}</b></div>`;
    html += `<div>Tổng bytes gửi: <b>${data.totalSentBytes}</b></div>`;
    html += `<div>Tổng bytes nhận: <b>${data.totalReceivedBytes}</b></div>`;
    html += `<div>Số peer hiện tại: <b>${data.currentPeers}</b></div>`;
    html += `<div>Băng thông hiện tại (bps): <b>${data.throughput_bps}</b></div>`;
    html += `<div>Số gói tin nhận mỗi giây: <b>${data.packet_rate}</b></div>`;
    html += `</div>`;
    html += `<h4>Tin nhắn gửi theo peer:</h4><div class="section">`;
    for(let peer in data.sentPerPeer){
      html += `<div>${peer}: <b>${data.sentPerPeer[peer]}</b></div>`;
    }
    html += `</div>`;
    html += `<h4>Tin nhắn nhận theo peer:</h4><div class="section">`;
    for(let peer in data.recvPerPeer){
      html += `<div>${peer}: <b>${data.recvPerPeer[peer]}</b></div>`;
    }
    html += `</div>`;
    statsContent.innerHTML = html;
  }).catch(() => {
    statsContent.textContent = "Lỗi tải thống kê";
  });
}
function updateMemInfo() {
  fetch("/meminfo").then(r => r.json()).then(data => {
    memInfoDiv.textContent = `RAM trống: ${data.freeHeap} / ${data.totalHeap} bytes | Flash trống: ${data.freeFlash} bytes`;
  }).catch(() => {
    memInfoDiv.textContent = "Không lấy được thông tin RAM & Flash";
  });
}
function sendMsg() {
  const m = msgInput.value.trim();
  if (!m) return;
  sendStatus.style.color = "black";
  sendStatus.textContent = "Đang gửi...";
  console.log("Sending to peer:", currentPeer);
  fetch(`/send?msg=${encodeURIComponent(m)}&to=${encodeURIComponent(currentPeer)}`)
    .then(res => {
      if (res.ok) {
        sendStatus.style.color = "green";
        sendStatus.textContent = "Gửi thành công";
        msgInput.value = "";
      } else {
        sendStatus.style.color = "red";
        sendStatus.textContent = "Gửi thất bại";
      }
    }).catch(() => {
      sendStatus.style.color = "red";
      sendStatus.textContent = "Lỗi kết nối";
    });
}
sendBtn.addEventListener("click", sendMsg);
msgInput.addEventListener("keydown", e => {
  if (e.key === "Enter") sendMsg();
});
document.getElementById("downloadCsvBtn").addEventListener("click", () => {
  window.open("/downloadPerfCsv", "_blank");
});
function updateAll() {
  updatePeers();
  updateMessages();
  updateLogs();
  updateEncodedMessages();
  updateIp();
  updateMac();
  updateStats();
  updateMemInfo();
}
setInterval(updateAll, 1000);
updateAll();
</script>
</body>
</html>
)rawliteral";

void handleRoot() {
  server.send_P(200, "text/html", htmlPage);
}

void handleMessages() {
  String j = "[";
  for (auto &m : msgList) {
    j += "\"" + m + "\",";
  }
  if (j.endsWith(","))
    j.remove(j.length() - 1);
  j += "]";
  server.send(200, "application/json", j);
}

void handleLogs() {
  String j = "[";
  for (auto &l : logList) {
    j += "\"" + l + "\",";
  }
  if (j.endsWith(","))
    j.remove(j.length() - 1);
  j += "]";
  server.send(200, "application/json", j);
}

void handlePeers() {
  String j = "[";
  for (auto &p : peerList) {
    j += "\"" + p.macStr + "\",";
  }
  if (j.endsWith(","))
    j.remove(j.length() - 1);
  j += "]";
  server.send(200, "application/json", j);
}

void handleIp() {
  server.send(200, "text/plain", server.client().remoteIP().toString());
}

void handleMac() {
  char buf[18];
  formatMac(myMac, buf);
  server.send(200, "text/plain", String(buf));
}

void handleEncodedMessages() {
  String j = "[";
  for (auto &l : logList) {
    if (l.startsWith("RECV-ENC") || l.startsWith("SENT")) {
      j += "\"" + l + "\",";
    }
  }
  if (j.endsWith(","))
    j.remove(j.length() - 1);
  j += "]";
  server.send(200, "application/json", j);
}

void handleStats() {
  String j = "{";
  j += "\"totalSent\":" + String(stats.totalSent) + ",";
  j += "\"totalSendFail\":" + String(stats.totalSendFail) + ",";
  j += "\"totalReceived\":" + String(stats.totalReceived) + ",";
  j += "\"totalDecryptFail\":" + String(stats.totalDecryptFail) + ",";
  j += "\"totalReplay\":" + String(stats.totalReplay) + ",";
  j += "\"totalSentBytes\":" + String(stats.totalSentBytes) + ",";
  j += "\"totalReceivedBytes\":" + String(stats.totalReceivedBytes) + ",";
  j += "\"currentPeers\":" + String(peerList.size()) + ",";
  j += "\"throughput_bps\":" + String(currentThroughputBps, 2) + ",";
  j += "\"packet_rate\":" + String(currentPacketRate, 2) + ",";
  j += "\"sentPerPeer\":{";
  for (auto &p : stats.sentPerPeer) {
    j += "\"" + p.first + "\":" + String(p.second) + ",";
  }
  if (j.endsWith(","))
    j.remove(j.length() - 1);
  j += "},";
  j += "\"recvPerPeer\":{";
  for (auto &p : stats.recvPerPeer) {
    j += "\"" + p.first + "\":" + String(p.second) + ",";
  }
  if (j.endsWith(","))
    j.remove(j.length() - 1);
  j += "}";
  j += "}";
  server.send(200, "application/json", j);
}

void handleMemInfo() {
  uint32_t freeH = esp_get_free_heap_size();
  uint32_t totalH = ESP.getHeapSize();
  uint32_t freeF = ESP.getFreeSketchSpace();
  String r = "{";
  r += "\"freeHeap\":" + String(freeH) + ",";
  r += "\"totalHeap\":" + String(totalH) + ",";
  r += "\"freeFlash\":" + String(freeF);
  r += "}";
  server.send(200, "application/json", r);
}

void handleSend() {
  String m = server.arg("msg"), to = server.arg("to");
  if (!m.length()) {
    server.send(400, "text/plain", "Empty");
    return;
  }

  bool isBC = (to == "broadcast" || to.length() == 0);
  uint8_t dest[6];
  String peerStr;

  if (isBC) {
    memset(dest, 0xFF, 6);
    peerStr = "broadcast";
  } else {
    if (sscanf(to.c_str(),
               "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX",
               &dest[0],&dest[1],&dest[2],
               &dest[3],&dest[4],&dest[5]) != 6) {
      server.send(400,"text/plain","Invalid MAC");
      return;
    }
    char buf[18];
    formatMac(dest, buf);
    peerStr = String(buf);
    bool ok = false;
    for (auto &p : peerList) {
      if (p.macStr == peerStr) { ok = true; break; }
    }
    if (!ok) {
      server.send(400,"text/plain","Peer not connected");
      return;
    }
  }

  size_t inLen    = m.length();
  size_t bufLen   = inLen;
  size_t nonceLen = 4;

  uint8_t iv[12];
  generateIV(iv);

  uint8_t ciphertext[bufLen], tag[16];
  if (!aesEncryptGCM(aesKey, iv,
        (const uint8_t*)m.c_str(),
        inLen, ciphertext, tag)) {
    server.send(500,"text/plain","Encryption failed");
    return;
  }

  size_t pktLen = 12 + nonceLen + bufLen + 16;
  uint8_t* pkt = new uint8_t[pktLen];
  memcpy(pkt, iv, 12);
  uint32_t nonce = ++lastNonces[peerStr];
  memcpy(pkt + 12, &nonce, nonceLen);
  memcpy(pkt + 16, ciphertext, bufLen);
  memcpy(pkt + 16 + bufLen, tag, 16);

  // Send directly instead of queuing
  esp_err_t res = espnow.send(dest, pkt, pktLen);
  uint32_t t = millis();
  char mbuf[18];
  formatMac(dest, mbuf);
  String logl = String("SENT @") + t + "ms to " + mbuf + " | CLR=" + m;
  Serial.println(logl);
  if (logList.size() >= 100) logList.erase(logList.begin());
  logList.push_back(logl);

  if (msgList.size() >= 100) msgList.erase(msgList.begin());
  msgList.push_back(String("You: ") + m);

  if (res == ESP_OK) {
    stats.totalSent++;
    stats.sentPerPeer[peerStr]++;
    stats.totalSentBytes += pktLen;
    server.send(200, "text/plain", "OK");
  } else {
    stats.totalSendFail++;
    server.send(500, "text/plain", "Send failed");
  }

  delete[] pkt; // Free memory
}

// --- Generate CSV file for performance history ---
String generatePerfCsv() {
  String csv = "Timestamp_ms,Throughput_bps,Packet_count\n";
  for (const auto& rec : perfHistory) {
    csv += String(rec.timestampMs) + ",";
    csv += String(rec.throughputBps) + ",";
    csv += String(rec.packetCount) + "\n";
  }
  return csv;
}

void handleDownloadPerfCsv() {
  String csvData = generatePerfCsv();
  server.sendHeader("Content-Disposition", "attachment; filename=perf_stats.csv");
  server.send(200, "text/csv", csvData);
}

void setup() {
  Serial.begin(115200);
  delay(500);

  esp_read_mac(myMac, ESP_MAC_WIFI_STA);
  char ssid[32];
  snprintf(ssid, sizeof(ssid),
           "ESP32_%02X%02X%02X",
           myMac[3],myMac[4],myMac[5]);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  if (!espnow.begin()) {
    Serial.println("ESP-NOW init failed");
    while (1) delay(100);
  }
  espnow.addPeer(BROADCAST_MAC);

  WiFi.softAP(ssid, AP_PASS);
  Serial.print("SoftAP SSID: "); Serial.println(ssid);
  Serial.print("AP IP: ");     Serial.println(WiFi.softAPIP());

  server.on("/",           HTTP_GET, handleRoot);
  server.on("/peers",      HTTP_GET, handlePeers);
  server.on("/messages",   HTTP_GET, handleMessages);
  server.on("/logs",       HTTP_GET, handleLogs);
  server.on("/send",       HTTP_GET, handleSend);
  server.on("/ip",         HTTP_GET, handleIp);
  server.on("/mac",        HTTP_GET, handleMac);
  server.on("/encodedMessages", HTTP_GET, handleEncodedMessages);
  server.on("/stats",      HTTP_GET, handleStats);
  server.on("/meminfo",    HTTP_GET, handleMemInfo);
  server.on("/downloadPerfCsv", HTTP_GET, handleDownloadPerfCsv);
  server.onNotFound([](){
    server.sendHeader("Location","/");
    server.send(302,"text/plain","");
  });
  server.begin();

  // Initial broadcast ping
  espnow.send(BROADCAST_MAC, (const uint8_t*)"PING", 4);

  espnow.onReceive([&](const uint8_t* mac, const uint8_t* data, int len){
    if (len <= 0) return;
    if (memcmp(mac, myMac, 6) == 0) return;

    char mbuf[18];
    formatMac(mac, mbuf);
    String macStr(mbuf);

    // Rate-limit
    uint32_t now = millis();
    auto &rl = rateLimits[macStr];
    while (!rl.timestamps.empty() &&
           now - rl.timestamps.front() > RATE_LIMIT_WINDOW_MS) {
      rl.timestamps.pop_front();
    }
    if (rl.timestamps.size() >= MAX_MSG_PER_WINDOW) {
      logList.push_back("Rate limit exceeded from " + macStr);
      return;
    }
    rl.timestamps.push_back(now);

    // Peer discovery/update
    bool found = false;
    for (auto &p : peerList) {
      if (p.macStr == macStr) {
        p.lastActive = now;
        found = true;
        break;
      }
    }
    if (!found) {
      if (peerList.size() >= 20) {
        // Remove oldest
        size_t idx = 0;
        uint32_t oldest = peerList[0].lastActive;
        for (size_t i = 1; i < peerList.size(); i++) {
          if (peerList[i].lastActive < oldest) {
            oldest = peerList[i].lastActive;
            idx = i;
          }
        }
        espnow.removePeer(peerList[idx].mac);
        peerList.erase(peerList.begin() + idx);
      }
      PeerInfo np;
      np.macStr = macStr;
      memcpy(np.mac, mac, 6);
      np.lastActive = now;
      peerList.push_back(np);
      espnow.addPeer(mac);
      logList.push_back("Discovered peer: " + macStr);
    }

    // Ignore ping
    if (len == 4 && memcmp(data, "PING", 4) == 0) return;

    if (len < 12 + 4 + 16) {
      logList.push_back("Invalid packet length from " + macStr);
      return;
    }

    // Replay protection
    uint32_t recvNonce;
    memcpy(&recvNonce, data + 12, 4);
    if (lastNonces.count(macStr) &&
        recvNonce <= lastNonces[macStr]) {
      if (!lastReplayLogTime.count(macStr) ||
          now - lastReplayLogTime[macStr] >= REPLAY_LOG_INTERVAL_MS) {
        stats.totalReplay++;
        logList.push_back("Replay detected from " + macStr);
        lastReplayLogTime[macStr] = now;
        Serial.println("Replay detected from " + macStr);
      }
      return;
    }
    lastNonces[macStr] = recvNonce;

    // Decrypt AES-GCM
    const uint8_t* iv         = data;
    const uint8_t* ciphertext = data + 12 + 4;
    size_t        cLen        = len - 12 - 4 - 16;
    const uint8_t* tag        = data + len - 16;
    std::vector<uint8_t> dec(cLen);

    bool decOk = aesDecryptGCM(
      aesKey, iv,
      ciphertext, cLen,
      tag, dec.data()
    );
    if (!decOk) {
      stats.totalDecryptFail++;
      logList.push_back("Decryption failed from " + macStr);
      Serial.println("Decryption failed from " + macStr);
      return;
    }

    String clr((char*)dec.data(), cLen);
    uint32_t t2 = millis();

    String encLine = toHex(data, len);
    String eLog = "RECV-ENC @" + String(t2) + "ms from " + macStr + " | " + encLine;
    Serial.println(eLog);
    if (logList.size() >= 100) logList.erase(logList.begin());
    logList.push_back(eLog);

    String cLog = "RECV-CLR @" + String(t2) + "ms from " + macStr + " | " + clr;
    Serial.println(cLog);
    if (logList.size() >= 100) logList.erase(logList.begin());
    logList.push_back(cLog);

    if (msgList.size() >= 100) msgList.erase(msgList.begin());
    msgList.push_back(macStr + ": " + clr);

    // Update performance metrics
    bytesReceivedLastInterval += len;
    packetsReceivedLastInterval += 1;

    stats.totalReceived++;
    stats.recvPerPeer[macStr]++;
    stats.totalReceivedBytes += len;
  });

  espnow.onSend([](const uint8_t* mac, esp_now_send_status_t status){
    char mbuf[18]; formatMac(mac, mbuf);
    String macStr(mbuf);

    bool isBC = true;
    for (int i = 0; i < 6; i++) {
      if (mac[i] != 0xFF) { isBC = false; break; }
    }
    if (isBC) return;

    String s = "Send to " + macStr + " => " + (status == ESP_NOW_SEND_SUCCESS ? "OK" : "FAIL");
    Serial.println(s);
    logList.push_back(s);

    if (status != ESP_NOW_SEND_SUCCESS) {
      stats.totalSendFail++;
    }
  });
}

void loop() {
  uint32_t now = millis();

  // Performance measurement
  if (now - lastPerfUpdate >= 10000) {
    currentThroughputBps = (float)bytesReceivedLastInterval * 8.0f;  // bit per second
    currentPacketRate = (float)packetsReceivedLastInterval;          // packets per second

    bytesReceivedLastInterval = 0;
    packetsReceivedLastInterval = 0;

    lastPerfUpdate = now;

    PerfRecord rec;
    rec.timestampMs = now;
    rec.throughputBps = (uint32_t)currentThroughputBps;
    rec.packetCount = (uint32_t)currentPacketRate;
    perfHistory.push_back(rec);

    if (perfHistory.size() > MAX_HISTORY_SIZE) {
      perfHistory.erase(perfHistory.begin());
    }
  }

  if (now - lastPingTime >= PING_INTERVAL_MS) {
    espnow.send(BROADCAST_MAC, (const uint8_t*)"PING", 4);
    lastPingTime = now;
  }

  // Remove inactive peers
  const uint32_t PEER_TIMEOUT = 10000;
  for (size_t i = 0; i < peerList.size(); ) {
    if (now - peerList[i].lastActive > PEER_TIMEOUT) {
      espnow.removePeer(peerList[i].mac);
      logList.push_back("Removed inactive peer: " + peerList[i].macStr);
      peerList.erase(peerList.begin() + i);
    } else {
      i++;
    }
  }

  server.handleClient();
}