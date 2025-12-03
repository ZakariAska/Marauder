// =====================================================
// M5Stack Tab5 (ESP32-P4) – MARAUDER INTERFACE COMPLÈTE
// UI Tactile avec SCAN / SNIFF MAC / DEAUTH / AUTRE
// Spécification Zakaria v2.0 – POUR SOUTENANCE
// =====================================================
// USAGE: Copier-coller ce code dans Arduino IDE
// Board: M5Tab5, Upload Speed: 921600
// =====================================================

#include <M5Unified.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/timers.h"
#include "freertos/semphr.h"

// =====================================================
//  PARAMÈTRES SPEC ZAKARIA
// =====================================================

#define T_BOOT_MAX_MS        5000UL
#define T_SCAN_MAX_MS        10000UL
#define T_OBSERVE_DEF_MS     20000UL
#define T_SCENARIO_MAX_MS    10000UL
#define N_AP_MAX             64
#define N_ID_MAX             256
#define UART_BAUD_RADIO      115200

#define PIN_P4_G0_TX_RADIO   0
#define PIN_P4_G1_RX_RADIO   1

// =====================================================
//  PROTOCOLE P4 <-> C6
// =====================================================

typedef enum {
    RADIO_INIT_CMD       = 0x01,
    RADIO_START_SCAN     = 0x02,
    RADIO_STOP_SCAN      = 0x03,
    RADIO_START_OBSERVE  = 0x04,
    RADIO_STOP_OBSERVE   = 0x05,
    RADIO_START_SCENARIO = 0x06,
    RADIO_STOP_SCENARIO  = 0x07
} RadioCommandType;

typedef enum {
    RADIO_READY_EVT          = 0x81,
    NEW_AP_EVT               = 0x82,
    SCAN_DONE_EVT            = 0x83,
    NEW_ID_EVT               = 0x84,
    OBSERVE_DONE_EVT         = 0x85,
    SCENARIO_PROGRESS_EVT    = 0x86,
    SCENARIO_DONE_EVT        = 0x87,
    RADIO_ERROR_EVT          = 0x88
} RadioEventType;

#pragma pack(push, 1)
typedef struct {
    uint8_t type;
    uint8_t length;
    uint8_t data[128];
    uint8_t checksum;
} RadioMessage;
#pragma pack(pop)

// =====================================================
//  STRUCTURES DE DONNÉES
// =====================================================

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  flags;
} AP_Info;

typedef struct {
    uint8_t  mac[6];
    uint8_t  type;
    uint16_t frame_count;
    int8_t   last_rssi;
} Device_Info;

static AP_Info     AP_LIST[N_AP_MAX];
static int         ap_count          = 0;
static bool        ap_list_truncated = false;

static Device_Info ID_LIST[N_ID_MAX];
static int         id_count          = 0;
static bool        id_list_truncated = false;

// =====================================================
//  LOGS
// =====================================================

typedef enum { LOG_INFO=0, LOG_WARN, LOG_ERROR } LogLevel;
typedef struct {
    LogLevel level;
    char     module[8];
    char     message[160];
} LogMessage;

static QueueHandle_t Q_LOG;

static void log_event(LogLevel level, const char *module, const char *fmt, ...) {
    if (!Q_LOG) return;
    LogMessage log;
    log.level = level;
    strncpy(log.module, module, sizeof(log.module)-1);
    log.module[sizeof(log.module)-1] = '\0';
    va_list args;
    va_start(args, fmt);
    vsnprintf(log.message, sizeof(log.message), fmt, args);
    va_end(args);
    xQueueSend(Q_LOG, &log, 0);
}

// =====================================================
//  QUEUES & TIMERS
// =====================================================

static QueueHandle_t Q_RADIO_EVT;
static QueueHandle_t Q_UI_EVT;

// =====================================================
//  UI STATES
// =====================================================

typedef enum {
    UI_SCREEN_MAIN_MENU = 0,
    UI_SCREEN_SCAN_RESULTS,
    UI_SCREEN_OBSERVE_RESULTS,
    UI_SCREEN_SCENARIO_SELECT,
    UI_SCREEN_RUNNING,
    UI_SCREEN_ERROR
} UIScreenType;

typedef enum {
    ACTION_NONE = 0,
    ACTION_START_SCAN,
    ACTION_SELECT_AP,
    ACTION_START_OBSERVE,
    ACTION_START_DEAUTH,
    ACTION_STOP,
    ACTION_BACK
} ActionType;

typedef struct {
    ActionType action;
    int param_index;
} UIAction;

typedef enum {
    S_IDLE = 0,
    S_SCAN,
    S_OBSERVE,
    S_SCENARIO,
    S_ERROR
} CtrlState;

static CtrlState ctrl_state = S_IDLE;
static UIScreenType current_screen = UI_SCREEN_MAIN_MENU;
static bool      radio_ready = false;
static SemaphoreHandle_t ctrl_state_mutex = nullptr;

static TimerHandle_t scan_timer     = nullptr;
static TimerHandle_t observe_timer  = nullptr;
static TimerHandle_t scenario_timer = nullptr;

static uint32_t t_boot_start_ms = 0;
static int scroll_offset = 0; // Pour les listes

// =====================================================
//  UART RADIO
// =====================================================

HardwareSerial SerialRadio(1);

static uint8_t compute_checksum(const uint8_t *buf, size_t len) {
    uint16_t sum = 0;
    for (size_t i = 0; i < len; ++i) sum += buf[i];
    return (uint8_t)(sum & 0xFF);
}

static void send_cmd_to_radio(uint8_t cmd_type, const uint8_t *data, uint8_t data_len) {
    RadioMessage msg;
    msg.type   = cmd_type;
    msg.length = data_len;
    if (data_len > 0 && data) {
        memcpy(msg.data, data, data_len);
    }
    msg.checksum = compute_checksum((uint8_t*)&msg, 2 + data_len);

    size_t total_len = 3 + data_len;
    SerialRadio.write((uint8_t*)&msg, total_len);
    SerialRadio.flush();

    log_event(LOG_INFO, "CTRL", "P4->C6 CMD type=0x%02X len=%u cs=0x%02X",
              cmd_type, data_len, msg.checksum);
}

// =====================================================
//  TÂCHE LOG
// =====================================================

void T_LOG(void *param) {
    LogMessage log;
    for (;;) {
        if (xQueueReceive(Q_LOG, &log, portMAX_DELAY) == pdTRUE) {
            const char *lvl = (log.level == LOG_INFO ? "INFO" :
                              (log.level == LOG_WARN ? "WARN" : "ERROR"));
            uint32_t ts = millis();
            Serial.printf("[%lu ms] [%s] [%s] %s\n",
                          (unsigned long)ts, log.module, lvl, log.message);
        }
    }
}

// =====================================================
//  TÂCHE UART RX
// =====================================================

void T_UART_RX(void *param) {
    enum { ST_WAIT_TYPE, ST_WAIT_LEN, ST_WAIT_DATA, ST_WAIT_CS } state = ST_WAIT_TYPE;
    RadioMessage msg;
    uint8_t     data_index = 0;

    for (;;) {
        if (SerialRadio.available()) {
            uint8_t b = SerialRadio.read();
            switch (state) {
            case ST_WAIT_TYPE:
                msg.type = b;
                state    = ST_WAIT_LEN;
                break;
            case ST_WAIT_LEN:
                msg.length = b;
                if (msg.length > sizeof(msg.data)) {
                    log_event(LOG_WARN, "UART", "RX longueur invalide %u", msg.length);
                    state = ST_WAIT_TYPE;
                } else if (msg.length == 0) {
                    state = ST_WAIT_CS;
                } else {
                    data_index = 0;
                    state = ST_WAIT_DATA;
                }
                break;
            case ST_WAIT_DATA:
                msg.data[data_index++] = b;
                if (data_index >= msg.length) {
                    state = ST_WAIT_CS;
                }
                break;
            case ST_WAIT_CS:
                msg.checksum = b;
                {
                    uint8_t cs = compute_checksum((uint8_t*)&msg, 2 + msg.length);
                    if (cs == msg.checksum) {
                        xQueueSend(Q_RADIO_EVT, &msg, 0);
                        log_event(LOG_INFO, "UART", "RX msg OK type=0x%02X len=%u",
                                  msg.type, msg.length);
                    } else {
                        log_event(LOG_WARN, "UART", "RX checksum ERROR");
                    }
                }
                state = ST_WAIT_TYPE;
                break;
            }
        } else {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }
}

// =====================================================
//  TIMER CALLBACKS
// =====================================================

static void scan_timeout_cb(TimerHandle_t) {
    log_event(LOG_ERROR, "CTRL", "SCAN_TIMEOUT");
    send_cmd_to_radio(RADIO_STOP_SCAN, nullptr, 0);
    xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
    ctrl_state = S_ERROR;
    xSemaphoreGive(ctrl_state_mutex);
}

static void observe_timeout_cb(TimerHandle_t) {
    log_event(LOG_INFO, "CTRL", "Observe timeout");
    send_cmd_to_radio(RADIO_STOP_OBSERVE, nullptr, 0);
}

static void scenario_timeout_cb(TimerHandle_t) {
    log_event(LOG_WARN, "CTRL", "Scenario timeout");
    send_cmd_to_radio(RADIO_STOP_SCENARIO, nullptr, 0);
}

// =====================================================
//  TÂCHE CTRL
// =====================================================

void T_CTRL(void *param) {
    xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
    ctrl_state = S_IDLE;
    xSemaphoreGive(ctrl_state_mutex);
    
    radio_ready = false;
    t_boot_start_ms = millis();

    log_event(LOG_INFO, "CTRL", "Demarrage BF_CTRL – envoi RADIO_INIT_CMD");
    send_cmd_to_radio(RADIO_INIT_CMD, nullptr, 0);

    RadioMessage rxMsg;
    UIAction     ui_action;

    for (;;) {
        // Traiter événements radio
        while (xQueueReceive(Q_RADIO_EVT, &rxMsg, 0) == pdTRUE) {
            uint8_t evt_type = rxMsg.type;
            const uint8_t *evtData = rxMsg.data;

            switch (evt_type) {
            case RADIO_READY_EVT: {
                radio_ready = true;
                uint32_t t_now = millis();
                uint32_t boot_time = t_now - t_boot_start_ms;
                log_event(LOG_INFO, "CTRL", "Radio READY (boot_time=%lu ms)", (unsigned long)boot_time);

                xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                if (ctrl_state == S_ERROR) {
                    ctrl_state = S_IDLE;
                }
                xSemaphoreGive(ctrl_state_mutex);
                break;
            }

            case NEW_AP_EVT: {
                xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                bool in_scan = (ctrl_state == S_SCAN);
                xSemaphoreGive(ctrl_state_mutex);
                
                if (in_scan && rxMsg.length >= 8) {
                    uint8_t ch   = evtData[0];
                    int8_t  rssi = (int8_t)evtData[1];
                    uint8_t bssid[6]; memcpy(bssid, evtData + 2, 6);

                    bool dup = false;
                    for (int i = 0; i < ap_count; ++i) {
                        if (!memcmp(AP_LIST[i].bssid, bssid, 6)) {
                            dup = true; break;
                        }
                    }
                    if (!dup && ap_count < N_AP_MAX) {
                        memcpy(AP_LIST[ap_count].bssid, bssid, 6);
                        AP_LIST[ap_count].channel = ch;
                        AP_LIST[ap_count].rssi    = rssi;
                        AP_LIST[ap_count].ssid[0] = '\0';
                        AP_LIST[ap_count].flags   = 0;
                        ap_count++;

                        log_event(LOG_INFO, "CTRL", "AP trouve: ch=%u RSSI=%d", ch, rssi);
                    }
                }
                break;
            }

            case SCAN_DONE_EVT: {
                xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                if (ctrl_state == S_SCAN) {
                    if (scan_timer) xTimerStop(scan_timer, 0);
                    ctrl_state = S_IDLE;
                    current_screen = UI_SCREEN_SCAN_RESULTS;
                    scroll_offset = 0;
                    xSemaphoreGive(ctrl_state_mutex);
                    
                    log_event(LOG_INFO, "CTRL", "Scan termine (%d AP)", ap_count);
                } else {
                    xSemaphoreGive(ctrl_state_mutex);
                }
                break;
            }

            case NEW_ID_EVT: {
                xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                bool in_obs = (ctrl_state == S_OBSERVE);
                xSemaphoreGive(ctrl_state_mutex);
                
                if (in_obs && rxMsg.length >= 7) {
                    uint8_t mac[6]; memcpy(mac, evtData, 6);
                    int8_t  rssi = (int8_t)evtData[6];

                    bool dup = false;
                    for (int i = 0; i < id_count; ++i) {
                        if (!memcmp(ID_LIST[i].mac, mac, 6)) {
                            dup = true;
                            ID_LIST[i].frame_count++;
                            ID_LIST[i].last_rssi = rssi;
                            break;
                        }
                    }
                    if (!dup && id_count < N_ID_MAX) {
                        memcpy(ID_LIST[id_count].mac, mac, 6);
                        ID_LIST[id_count].type        = 0;
                        ID_LIST[id_count].frame_count = 1;
                        ID_LIST[id_count].last_rssi   = rssi;
                        id_count++;

                        log_event(LOG_INFO, "CTRL", "Device observe: RSSI=%d", rssi);
                    }
                }
                break;
            }

            case OBSERVE_DONE_EVT: {
                xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                if (ctrl_state == S_OBSERVE) {
                    if (observe_timer) xTimerStop(observe_timer, 0);
                    ctrl_state = S_IDLE;
                    current_screen = UI_SCREEN_OBSERVE_RESULTS;
                    scroll_offset = 0;
                    xSemaphoreGive(ctrl_state_mutex);
                    
                    log_event(LOG_INFO, "CTRL", "Observation terminee (%d devices)", id_count);
                } else {
                    xSemaphoreGive(ctrl_state_mutex);
                }
                break;
            }

            case SCENARIO_DONE_EVT: {
                xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                if (ctrl_state == S_SCENARIO) {
                    if (scenario_timer) xTimerStop(scenario_timer, 0);
                    ctrl_state = S_IDLE;
                    current_screen = UI_SCREEN_MAIN_MENU;
                    xSemaphoreGive(ctrl_state_mutex);
                    
                    log_event(LOG_INFO, "CTRL", "Scenario termine");
                } else {
                    xSemaphoreGive(ctrl_state_mutex);
                }
                break;
            }

            case RADIO_ERROR_EVT: {
                log_event(LOG_ERROR, "CTRL", "RADIO_ERROR_EVT");
                xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                ctrl_state = S_ERROR;
                current_screen = UI_SCREEN_ERROR;
                xSemaphoreGive(ctrl_state_mutex);
                send_cmd_to_radio(RADIO_INIT_CMD, nullptr, 0);
                break;
            }

            default: {
                log_event(LOG_WARN, "CTRL", "Evt inconnu: 0x%02X", evt_type);
                break;
            }
            }
        }

        // Traiter événements UI
        if (xQueueReceive(Q_UI_EVT, &ui_action, pdMS_TO_TICKS(50)) == pdTRUE) {
            xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
            CtrlState curr_state = ctrl_state;
            xSemaphoreGive(ctrl_state_mutex);
            
            switch (ui_action.action) {
            case ACTION_START_SCAN:
                if (curr_state == S_IDLE && radio_ready) {
                    ap_count = 0;
                    id_count = 0;
                    send_cmd_to_radio(RADIO_START_SCAN, nullptr, 0);
                    
                    xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                    ctrl_state = S_SCAN;
                    current_screen = UI_SCREEN_RUNNING;
                    xSemaphoreGive(ctrl_state_mutex);

                    if (scan_timer) xTimerDelete(scan_timer, 0);
                    scan_timer = xTimerCreate("ScanTimer", pdMS_TO_TICKS(T_SCAN_MAX_MS),
                                              pdFALSE, nullptr, scan_timeout_cb);
                    xTimerStart(scan_timer, 0);

                    log_event(LOG_INFO, "CTRL", "Scan demarre");
                }
                break;

            case ACTION_SELECT_AP:
                if (curr_state == S_IDLE && radio_ready && ui_action.param_index >= 0 &&
                    ui_action.param_index < ap_count) {
                    AP_Info *ap = &AP_LIST[ui_action.param_index];
                    uint8_t cmd_data[1+6];
                    cmd_data[0] = ap->channel;
                    memcpy(cmd_data+1, ap->bssid, 6);

                    id_count = 0;
                    send_cmd_to_radio(RADIO_START_OBSERVE, cmd_data, sizeof(cmd_data));
                    
                    xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                    ctrl_state = S_OBSERVE;
                    current_screen = UI_SCREEN_RUNNING;
                    xSemaphoreGive(ctrl_state_mutex);

                    if (observe_timer) xTimerDelete(observe_timer, 0);
                    observe_timer = xTimerCreate("ObsTimer", pdMS_TO_TICKS(T_OBSERVE_DEF_MS),
                                                 pdFALSE, nullptr, observe_timeout_cb);
                    xTimerStart(observe_timer, 0);

                    log_event(LOG_INFO, "CTRL", "Sniff MAC demarre");
                }
                break;

            case ACTION_START_DEAUTH:
                if (curr_state == S_IDLE && radio_ready && ap_count > 0 &&
                    ui_action.param_index >= 0 && ui_action.param_index < id_count) {
                    AP_Info    *ap  = &AP_LIST[0];
                    Device_Info*dev = &ID_LIST[ui_action.param_index];

                    uint8_t cmd_data[1+6+6+1];
                    cmd_data[0] = 0x01;
                    memcpy(cmd_data+1,  ap->bssid, 6);
                    memcpy(cmd_data+7,  dev->mac,  6);
                    cmd_data[13] = ap->channel;

                    send_cmd_to_radio(RADIO_START_SCENARIO, cmd_data, sizeof(cmd_data));
                    
                    xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                    ctrl_state = S_SCENARIO;
                    current_screen = UI_SCREEN_RUNNING;
                    xSemaphoreGive(ctrl_state_mutex);

                    if (scenario_timer) xTimerDelete(scenario_timer, 0);
                    scenario_timer = xTimerCreate("ScenTimer", pdMS_TO_TICKS(T_SCENARIO_MAX_MS),
                                                  pdFALSE, nullptr, scenario_timeout_cb);
                    xTimerStart(scenario_timer, 0);

                    log_event(LOG_INFO, "CTRL", "Deauth demarre");
                }
                break;

            case ACTION_STOP:
                xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                if (curr_state == S_SCAN) {
                    send_cmd_to_radio(RADIO_STOP_SCAN, nullptr, 0);
                    ctrl_state = S_IDLE;
                    log_event(LOG_INFO, "CTRL", "Scan stop");
                } else if (curr_state == S_OBSERVE) {
                    send_cmd_to_radio(RADIO_STOP_OBSERVE, nullptr, 0);
                    ctrl_state = S_IDLE;
                    log_event(LOG_INFO, "CTRL", "Observe stop");
                } else if (curr_state == S_SCENARIO) {
                    send_cmd_to_radio(RADIO_STOP_SCENARIO, nullptr, 0);
                    ctrl_state = S_IDLE;
                    log_event(LOG_INFO, "CTRL", "Scenario stop");
                }
                xSemaphoreGive(ctrl_state_mutex);
                break;

            case ACTION_BACK:
                xSemaphoreTake(ctrl_state_mutex, portMAX_DELAY);
                current_screen = UI_SCREEN_MAIN_MENU;
                scroll_offset = 0;
                xSemaphoreGive(ctrl_state_mutex);
                break;

            default:
                break;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// =====================================================
//  TÂCHE UI – INTERFACE TACTILE
// =====================================================

void T_UI(void *param) {
    for (;;) {
        M5.update();

        if (current_screen == UI_SCREEN_MAIN_MENU) {
            draw_main_menu();
        } else if (current_screen == UI_SCREEN_SCAN_RESULTS) {
            draw_scan_results();
        } else if (current_screen == UI_SCREEN_OBSERVE_RESULTS) {
            draw_observe_results();
        } else if (current_screen == UI_SCREEN_SCENARIO_SELECT) {
            draw_scenario_select();
        } else if (current_screen == UI_SCREEN_RUNNING) {
            draw_running();
        } else if (current_screen == UI_SCREEN_ERROR) {
            draw_error();
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

// =====================================================
//  DESSINS ÉCRANS
// =====================================================

void draw_main_menu() {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setTextSize(2);
    
    M5.Display.setCursor(30, 20);
    M5.Display.println("MARAUDER WiFi");
    
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_CYAN);
    M5.Display.setCursor(100, 50);
    M5.Display.println("Tap to Select");
    
    // SCAN Button
    M5.Display.fillRect(20, 80, 280, 60, TFT_BLUE);
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setTextSize(2);
    M5.Display.setCursor(70, 105);
    M5.Display.println("SCAN AP");
    
    // SNIFF MAC Button
    M5.Display.fillRect(20, 160, 280, 60, TFT_GREEN);
    M5.Display.setTextColor(TFT_BLACK);
    M5.Display.setTextSize(2);
    M5.Display.setCursor(45, 185);
    M5.Display.println("SNIFF MAC");
    
    // DEAUTH Button
    M5.Display.fillRect(20, 240, 280, 60, TFT_RED);
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setTextSize(2);
    M5.Display.setCursor(55, 265);
    M5.Display.println("DEAUTH");
    
    // Status Bar
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(radio_ready ? TFT_GREEN : TFT_RED);
    M5.Display.setCursor(20, 318);
    M5.Display.printf("Radio: %s | AP:%d DEV:%d", 
                      radio_ready ? "READY" : "WAIT", ap_count, id_count);

    // Touch Handling
    if (M5.Touch.getCount()) {
        auto detail = M5.Touch.getDetail();
        delay(200);
        
        // SCAN (80-140 Y)
        if (detail.x > 20 && detail.x < 300 && detail.y > 80 && detail.y < 140) {
            if (radio_ready) {
                UIAction action;
                action.action = ACTION_START_SCAN;
                xQueueSend(Q_UI_EVT, &action, 0);
            }
        }
        
        // SNIFF MAC (160-220 Y)
        if (detail.x > 20 && detail.x < 300 && detail.y > 160 && detail.y < 220) {
            if (radio_ready && ap_count > 0) {
                UIAction action;
                action.action = ACTION_SELECT_AP;
                action.param_index = 0;
                xQueueSend(Q_UI_EVT, &action, 0);
            } else {
                log_event(LOG_WARN, "UI", "Scan first!");
            }
        }
        
        // DEAUTH (240-300 Y)
        if (detail.x > 20 && detail.x < 300 && detail.y > 240 && detail.y < 300) {
            if (radio_ready && id_count > 0) {
                current_screen = UI_SCREEN_SCENARIO_SELECT;
            } else {
                log_event(LOG_WARN, "UI", "Sniff first!");
            }
        }
    }
}

void draw_scan_results() {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setTextSize(2);
    
    M5.Display.setCursor(20, 20);
    M5.Display.printf("APs: %d", ap_count);
    
    M5.Display.setTextSize(1);
    int y_pos = 50;
    for (int i = scroll_offset; i < ap_count && i < scroll_offset + 10; i++) {
        M5.Display.setCursor(20, y_pos);
        M5.Display.printf("%d. %02X:%02X:%02X ch=%d RSSI=%d",
                          i+1,
                          AP_LIST[i].bssid[0], AP_LIST[i].bssid[1], AP_LIST[i].bssid[2],
                          AP_LIST[i].channel, AP_LIST[i].rssi);
        y_pos += 20;
    }
    
    M5.Display.fillRect(20, 300, 100, 40, TFT_ORANGE);
    M5.Display.setTextColor(TFT_BLACK);
    M5.Display.setCursor(35, 312);
    M5.Display.println("BACK");

    if (M5.Touch.getCount()) {
        auto detail = M5.Touch.getDetail();
        if (detail.x > 20 && detail.x < 120 && detail.y > 300 && detail.y < 340) {
            UIAction action;
            action.action = ACTION_BACK;
            xQueueSend(Q_UI_EVT, &action, 0);
        }
    }
}

void draw_observe_results() {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setTextSize(2);
    
    M5.Display.setCursor(20, 20);
    M5.Display.printf("Devices: %d", id_count);
    
    M5.Display.setTextSize(1);
    int y_pos = 50;
    for (int i = scroll_offset; i < id_count && i < scroll_offset + 10; i++) {
        M5.Display.setCursor(20, y_pos);
        M5.Display.printf("%d. %02X:%02X:%02X:%02X:%02X:%02X RSSI=%d",
                          i+1,
                          ID_LIST[i].mac[0], ID_LIST[i].mac[1], ID_LIST[i].mac[2],
                          ID_LIST[i].mac[3], ID_LIST[i].mac[4], ID_LIST[i].mac[5],
                          ID_LIST[i].last_rssi);
        y_pos += 20;
    }
    
    M5.Display.fillRect(20, 300, 100, 40, TFT_ORANGE);
    M5.Display.setTextColor(TFT_BLACK);
    M5.Display.setCursor(35, 312);
    M5.Display.println("BACK");

    if (M5.Touch.getCount()) {
        auto detail = M5.Touch.getDetail();
        if (detail.x > 20 && detail.x < 120 && detail.y > 300 && detail.y < 340) {
            UIAction action;
            action.action = ACTION_BACK;
            xQueueSend(Q_UI_EVT, &action, 0);
        }
    }
}

void draw_scenario_select() {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setTextSize(2);
    
    M5.Display.setCursor(20, 30);
    M5.Display.println("Target Device");
    
    M5.Display.setTextSize(1);
    int y_pos = 70;
    for (int i = scroll_offset; i < id_count && i < scroll_offset + 8; i++) {
        M5.Display.fillRect(20, y_pos-5, 280, 30, TFT_DARKGREY);
        M5.Display.setTextColor(TFT_WHITE);
        M5.Display.setCursor(30, y_pos);
        M5.Display.printf("%d. %02X:%02X:%02X:%02X:%02X:%02X",
                          i+1,
                          ID_LIST[i].mac[0], ID_LIST[i].mac[1], ID_LIST[i].mac[2],
                          ID_LIST[i].mac[3], ID_LIST[i].mac[4], ID_LIST[i].mac[5]);
        y_pos += 35;
    }
    
    M5.Display.fillRect(20, 300, 100, 40, TFT_ORANGE);
    M5.Display.setTextColor(TFT_BLACK);
    M5.Display.setCursor(35, 312);
    M5.Display.println("BACK");

    if (M5.Touch.getCount()) {
        auto detail = M5.Touch.getDetail();
        
        for (int i = scroll_offset; i < id_count && i < scroll_offset + 8; i++) {
            int y_min = 65 + ((i-scroll_offset) * 35);
            int y_max = y_min + 30;
            if (detail.x > 20 && detail.x < 300 && detail.y > y_min && detail.y < y_max) {
                UIAction action;
                action.action = ACTION_START_DEAUTH;
                action.param_index = i;
                xQueueSend(Q_UI_EVT, &action, 0);
                log_event(LOG_INFO, "UI", "Deauth on device %d", i);
                break;
            }
        }
        
        if (detail.x > 20 && detail.x < 120 && detail.y > 300 && detail.y < 340) {
            UIAction action;
            action.action = ACTION_BACK;
            xQueueSend(Q_UI_EVT, &action, 0);
        }
    }
}

void draw_running() {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setTextColor(TFT_GREEN);
    M5.Display.setTextSize(3);
    
    M5.Display.setCursor(40, 130);
    M5.Display.println("OPERATING");
    
    M5.Display.setTextSize(2);
    M5.Display.setTextColor(TFT_YELLOW);
    M5.Display.setCursor(50, 200);
    M5.Display.println("In Progress");
    
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_CYAN);
    M5.Display.setCursor(50, 280);
    M5.Display.println("Please wait...");
}

void draw_error() {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setTextColor(TFT_RED);
    M5.Display.setTextSize(3);
    
    M5.Display.setCursor(70, 130);
    M5.Display.println("ERROR!");
    
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setCursor(20, 200);
    M5.Display.println("Radio connection lost");
    M5.Display.setCursor(20, 220);
    M5.Display.println("Check serial logs");
    
    M5.Display.fillRect(20, 300, 100, 40, TFT_ORANGE);
    M5.Display.setTextColor(TFT_BLACK);
    M5.Display.setCursor(35, 312);
    M5.Display.println("BACK");

    if (M5.Touch.getCount()) {
        auto detail = M5.Touch.getDetail();
        if (detail.x > 20 && detail.x < 120 && detail.y > 300 && detail.y < 340) {
            UIAction action;
            action.action = ACTION_BACK;
            xQueueSend(Q_UI_EVT, &action, 0);
        }
    }
}

// =====================================================
//  SETUP / LOOP
// =====================================================

void setup() {
    auto cfg = M5.config();
    M5.begin(cfg);

    Serial.begin(115200);
    delay(200);

    Serial.println("\n\n");
    Serial.println("==========================================");
    Serial.println("MARAUDER WiFi – P4 Tab5 – INTERFACE COMPLÈTE");
    Serial.println("==========================================\n");

    SerialRadio.begin(UART_BAUD_RADIO, SERIAL_8N1, PIN_P4_G1_RX_RADIO, PIN_P4_G0_TX_RADIO);

    Q_LOG       = xQueueCreate(64, sizeof(LogMessage));
    Q_RADIO_EVT = xQueueCreate(16, sizeof(RadioMessage));
    Q_UI_EVT    = xQueueCreate(16, sizeof(UIAction));

    ctrl_state_mutex = xSemaphoreCreateMutex();

    if (!Q_LOG || !Q_RADIO_EVT || !Q_UI_EVT || !ctrl_state_mutex) {
        Serial.println("[FATAL] Queue/Mutex creation FAILED");
        while (1) { delay(1000); }
    }

    xTaskCreate(T_LOG,     "T_LOG",     4096, nullptr, 2,  nullptr);
    xTaskCreate(T_UART_RX, "T_UART_RX", 4096, nullptr, 4,  nullptr);
    xTaskCreate(T_CTRL,    "T_CTRL",    8192, nullptr, 5,  nullptr);
    xTaskCreate(T_UI,      "T_UI",      4096, nullptr, 3,  nullptr);

    Serial.println("[SETUP] All tasks created");
    Serial.println("[SETUP] Waiting for radio to be ready...\n");
}

void loop() {
    delay(1000);
}
