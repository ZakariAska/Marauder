# Marauder



\# Marauder – M5Stack Tab5 + ESP32-C6 Wi-Fi Tool



Custom \*\*Wi-Fi analysis tool\*\* built on:



\- \*\*M5Stack Tab5 (ESP32-P4)\*\* for the touchscreen user interface  

\- \*\*ESP32-C6\*\* as the RF “engine” (scan, sniff, deauth detection / test mode)



The project is \*\*educational\*\* and strongly inspired by the original \*\*ESP32 Marauder\*\* by \*JustCallMeKoko\* (UI concept and overall workflow).



> ⚠ \*\*Legal notice\*\*  

> This firmware is for \*\*learning and lab testing only\*\*.  

> Do not scan, sniff or deauthenticate networks/devices without explicit, written permission from the owner.



---



\## 1. Architecture



The system is split into \*\*two firmwares\*\*:



\- `Interface\_P4.ino`  

&nbsp; Runs on \*\*M5Stack Tab5 (ESP32-P4)\*\*.  

&nbsp; Responsibilities:

&nbsp; - Boot screen and main menu  

&nbsp; - Touch UI (buttons, navigation, pop-ups)  

&nbsp; - Display of scan / sniff results and logs  

&nbsp; - Control of operating modes  

&nbsp; - UART link to the ESP32-C6 (“radio” side)



\- `Nanoc6.ino`  

&nbsp; Runs on \*\*ESP32-C6 dev board\*\*.  

&nbsp; Responsibilities:

&nbsp; - Wi-Fi initialisation and configuration  

&nbsp; - Active / passive scanning  

&nbsp; - MAC / frame sniffing  

&nbsp; - \*\*Deauthentication / disassociation detection\*\*  

&nbsp; - Controlled \*\*deauth test mode\*\* (lab demo only)  

&nbsp; - Binary protocol over UART (commands from Tab5, events back to Tab5)



High-level block diagram:



```text

&nbsp;       +------------------------+

&nbsp;       |   M5Stack Tab5         |

&nbsp;       |   (ESP32-P4)           |

&nbsp;       |  - Touch UI            |

&nbsp;       |  - Menus / Logs        |

&nbsp;       |  - Scenario control    |

&nbsp;       +-----------+------------+

&nbsp;                   |  UART

&nbsp;                   |

&nbsp;       +-----------v------------+

&nbsp;       |    ESP32-C6 Board      |

&nbsp;       |  - Wi-Fi scan          |

&nbsp;       |  - Sniff (MAC/frames)  |

&nbsp;       |  - Deauth detect/test  |

&nbsp;       +------------------------+

2\. Features

2.1 Implemented (Tab5 UI – Interface\_P4.ino)



Main menu with touch buttons:



SCAN AP – trigger AP scan on the ESP32-C6 and display the list



SNIFF MAC – capture Wi-Fi frames and show detected MAC addresses



DEAUTH – access deauth-related demo / test functionality (lab only)



SCENARIO – predefined demo flows (scan → observe → detect, etc.)



Status \& log area:



State machine status (IDLE, SCAN, OBSERVE, RUNNING, ERROR, …)



Timeouts / error messages



Touch-driven navigation between:



Main menu



Scan result screen



Sniff / observation screen



Scenario selection



Running / error screens



2.2 Implemented (ESP32-C6 radio – Nanoc6.ino)



Wi-Fi initialisation (station / monitor modes depending on configuration)



UART protocol:



Commands from Tab5: start/stop scan, start sniff, enter deauth detect/test, etc.



Events to Tab5: scan complete, packets seen, deauth detected, logs, errors



Deauth / disassoc detection:



Detects DEAUTH / DISASSOC frames



Sends compact event with relevant MAC addresses to the Tab5



Deauth test mode (controlled):



Sends a limited burst of deauth frames to a target (for demo on your own lab network)



Burst length / delay configurable at compile time



Note: This is not a drop-in replacement for ESP32 Marauder, but a custom educational implementation inspired by it.



2.3 Planned / TODO



Better scan view (sorting, filtering, channel display)



Channel / RSSI visualisation on Tab5 (bars, maybe simple graphs)



More robust UART protocol (framing, checksum, retry)



Settings menu (scan interval, TX power, filters, debug level)



Screenshots / photos of UI to include in this README



3\. Hardware

3.1 Required hardware



M5Stack Tab5



ESP32-P4



Built-in LCD + capacitive touch



USB-C for power and flashing



ESP32-C6 development board



USB for flashing



Standard GPIO pinout (TX, RX, GND, 3V3/5V)



Jumper wires:



Tab5\_TX → C6\_RX



Tab5\_RX → C6\_TX



GND ↔ GND



Optional:



Common power supply (5 V / 3V3) if both boards are powered from the same source



Check the comments at the top of Interface\_P4.ino and Nanoc6.ino for the exact pins used and adapt them to your own PCB / dev kit.



4\. Software prerequisites



Arduino IDE (1.8.x or 2.x) or Arduino CLI



Espressif ESP32 board package installed via Boards Manager:



Board definition compatible with M5Stack Tab5 (ESP32-P4)



Board definition compatible with ESP32-C6



Libraries:



M5Unified

&nbsp;for Tab5 display/touch



FreeRTOS is included in the ESP32 core



Optional:



VS Code + Arduino extension

Serial terminal (115200 baud)
6. Build \& flash

6.1 Build / flash Tab5 (Interface\_P4.ino)



Open Arduino IDE.



Open Interface\_P4.ino.



In Tools → Board, select the M5Stack Tab5 / ESP32-P4 board.



In Tools → Port, select the COM port of the Tab5.



Click Verify to compile.



Click Upload to flash.



Open the Serial Monitor (115200 baud unless defined otherwise).



6.2 Build / flash ESP32-C6 (Nanoc6.ino)



Connect the ESP32-C6 dev board in USB.



Open Nanoc6.ino in Arduino IDE.



Select the correct Board for ESP32-C6.



Select the COM port of the ESP32-C6.



Compile, then upload.



Open a Serial Monitor (115200 baud) to confirm Wi-Fi / UART initialisation.



Make sure the UART pins configured in both sketches match your actual wiring.



7\. Basic usage



Connect Tab5 ↔ ESP32-C6 via UART (TX/RX crossed + common GND).



Power both boards via USB or a shared supply.



On boot, the Tab5:



Initialises display and touch



Opens the UART to the ESP32-C6



Shows the main menu



From the Tab5 touchscreen:



Start an AP scan and inspect the list of access points



Start MAC sniffing and watch detected MACs



Run a controlled deauth test scenario on a lab network



Use Serial Monitor(s) on the PC to follow:



Tab5-side logs (UI / state machine)



ESP32-C6-side logs (radio / Wi-Fi events)



8\. Legal \& ethical reminder



Some features (sniff, deauth test) are sensitive. You must:



Test only on your own networks or networks where you have explicit permission.



Respect the laws and regulations of your country and organisation.



Use this project as a pedagogical / lab tool, not as an attack tool.



You are fully responsible for how you use this code.



9\. Credits / inspirations



This project is strongly inspired by ESP32 Marauder by JustCallMeKoko and the associated community:



Concept of a portable Wi-Fi tool with a dedicated UI



Separation between UI device and Wi-Fi engine



Several ideas for menus and modes (scan, observe, deauth-related, etc.)



If you find this project useful, consider visiting and supporting the original ESP32 Marauder repositories.

