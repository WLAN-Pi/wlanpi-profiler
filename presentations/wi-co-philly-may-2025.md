---
author: "Josh Schmelzle"
date: "May 15, 2025"
paging: "-~={%d}=~-"
---

```

              d8b                         
              Y8P                         
                                          
888  888  888 888         .d8888b .d88b.  
888  888  888 888        d88P"   d88""88b 
888  888  888 888 888888 888     888  888 
Y88b 888 d88P 888        Y88b.   Y88..88P 
 "Y8888888P"  888         "Y8888P "Y88P"  
                                          
                                          
                                          
         888      d8b 888 888             
         888      Y8P 888 888             
         888          888 888             
88888b.  88888b.  888 888 888 888  888    
888 "88b 888 "88b 888 888 888 888  888    
888  888 888  888 888 888 888 888  888    
888 d88P 888  888 888 888 888 Y88b 888    
88888P"  888  888 888 888 888  "Y88888    
888                                888    
888                           Y8b d88P    
888                            "Y88P"     

```
---

```
༼ つ ◕_◕ ༽つ ▁ ▂ ▃ ▅ ▇
```

# whoami

Josh Schmelzle (_sh-mel-ts-eh_)

## locale

Pittsburgh, PA

## where i play 

- WLAN TME @ HPE Aruba Networking
- Core @ WLAN Pi
- Owner @ Big QAM, LLC

---

# Talk

## Profiling Wi-Fi 7 clients

## Agenda

### -~- Wi-Fi 7

### -=- Client capabilities

### -+- Profiling

```
▌ ▌ ▌ ▌
▌ ▌ ▌
▌ ▌
▌
```
---

# Wi-Fi 7

## Main goals

1. Improve peak throughput

2. Improve link efficiency, reliability, and latency.

## Key features aligned

### 1. Speeds

  - 4K QAM (MCS 12/13)
  - 320 MHz 

### 2. Reliability
  
  - Multi-link device (MLD) framework
      - Single-link 
      - Multi-link 
  - Multiple resource units (MRU) per client
  - Triggered uplink access (TUA)
  - Stream classification service (SCS)
  - Emergency preparedness communications services (EPCS)

---

# Wi-Fi 7

## Band support

Wi-Fi 7 clients (regular STA or 20 MHz-only client) can operate on 2.4 GHz, 5 GHz, and/or 6 GHz bands

Clients _may_ support one, two, or all three bands

### Single-band clients 

- Must operate as 802.11be in supported band
- Limited to either 2.4 GHz or 5 GHz only
  - No 6 GHz

### Dual-band clients 

- Must operate according to 802.11be in both bands
- Must support one of these combinations:
  - 2.4 GHz and 5 GHz
  - 2.4 GHz and 6 GHz
  - 5 GHz and 6 GHz

---

# Wi-Fi 7 

## Mandatory client features

- SU DL/UL in EHT PPDU format
- Multiple RU (MRU)
- Static puncturing (in 6 GHz)
- DL/UL OFDMA
- DL/UL MU-MIMO
- Packet extension
- TxBF/EHT sounding
    - DL SU
    - DL OFDMA
- WPA3-Personal
    - AKM:24 (SAE-GDH)
    - H2E for SAE PWE derivation (no HNP/looping)
- GCMP-256 ciphers
- MLD security
- Multi-link BSS updates  
    - CSA
    - B-TWT
- Multi-link reconfiguration
- TID to link mapping (T2LM)
- Basic load balancing (BSS transition management)

---

# Wi-Fi 7

## Optional client features

- SU MIMO with 2 SS
- Channel width support
  - 160 MHz in 5 GHz
  - 320 MHz in 6 GHz (along with EHT operation mode (EHT OM))
- MCS rates
  - 1K QAM
    - MCS 10
    - MCS 11
  - 4K QAM 
    - MCS 12
    - MCS 13
- TxBF DL OFDMA
- Compressed BA (C-BA) 256/512 bits
- Triggered uplink access (TUA)
- EPCS (Emergency Preparedness Communications Services) priority access
- Dynamic MU Spatial Multiplexing Power Save (SMPS)

#### Conditional mandatory not discussed

---

## Terminology

- MLO - multi-link operation 
- MLD - multi-link device
- MLE - multi-link element
- MLC - multi-link control

### MLD operation

##### MLSR - multi-link sigle-radio

- One link at a time

##### EMLSR - enhanced multi-link single-radio

- Listen on two links at a time
- Use only one link at a time

##### MLMR - multi-link multi-radio 

#### STR

- Use two links independently

#### NSTR

- Transmit or receive, on different links, at the same time

---

# Enhanced multi-link single-radio (EMLSR)

```
+---------------+                    +---------------+
|               |                    |               |
|    [RADIO]    |                    |    [RADIO]    |
|       |       |                    |       |       |
|  +---------+  |      Link 1        |  +---------+  |
|  |         |  |----- 2.4 GHz ----->|  |         |  |
|  |  Client |  |                    |  |   AP    |  |
|  |   MLD   |  |      Link 2        |  |   MLD   |  |
|  |         |  |------ 5 GHz ------>|  |         |  |
|  +---------+  |                    |  +---------+  |
+---------------+                    +---------------+
        |                                   |
        |<-Initial control frame (Link 2)---|
        |      (MU-RTS/Basic Trigger)       |
        |                                   |
        |--------EMLSR padding delay------->|
        |                                   |
        |-------EMLSR transition delay----->|
        |    (Client reconfigures radio)    |
        |                                   |
        |------Data exchange on Link 2----->|
        |       (Other link inactive)       |
        |                                   |
        |<-----Listen on all links--------->|
```


---

# STR-MLMR (Simultaneous Tx/Rx Multi-Link Multi-Radio)

```
+---------------+                    +---------------+
|  +---------+  |                    |  +---------+  |
|  | RADIO 1 |==|===== 2.4 GHz ======|==| RADIO 1 |  |
|  +---------+  |  Link 1 (Active)   |  +---------+  |
|       |       |                    |       |       |
|   STA |       |                    |   AP  |       |
|   MLD |       |                    |   MLD |       |
|       |       |                    |       |       |
|  +---------+  |                    |  +---------+  |
|  | RADIO 2 |==|===== 5 GHz ========|==| RADIO 2 |  |
|  +---------+  |  Link 2 (Active)   |  +---------+  |
+---------------+                    +---------------+
       |                                     |
       |<----    Data flow on Link 1  ------>|
       |                                     |
       |<----    Data flow on Link 2  ------>|
       |            (Concurrent)             |
```

- STR-MLMR has a dedicated radio per link
- Simultaneous transmit and receive using multiple radios
- No need to transition a radio between links to Tx or Rx

---

## Minimum viable multi-link operation

Non 20-MHz only clients must support basic multi-link operation.

### Basic multi-link opeation 

Over multiple links the ability to:

1. Discover
2. Authenticate
3. (re)Associate
4. (re)Setup of multiple links
5. support of multi-link control frames
    - block ack
    - power management

MLD client:

- Capable of supporting multiple links
- May support more than 1 link in same band
- May operate using fewer links compared to capability of the device

---

# Channel access

##### Channel access and frame exchange in a MLD is based on the capabilities exchanged during association.

## 💡

Great, same as previous generations.

This means we can analyze and profile capabilities based on the association request-response exchange.

```
+---------------+                       +---------------+
|  +---------+  |                       |  +---------+  |
|  |         |  |                       |  |         |  |
|  |         |  |<----- Signaling ------|  |         |  |
|  |  Client |  |                       |  |    AP   |  |
|  |         |  |<--- Authentication -->|  |         |  |
|  |         |  |                       |  |         |  |
|  |         |  |---- Association ----->|  |         |  |
|  +---------+  |      Request          |  +---------+  |
+---------------+                       +---------------+
```

---

## Capabilities

```
M""""""'YMM                              
M  mmmm. `M                              
M  MMMMM  M .d8888b. 88d8b.d8b. .d8888b. 
M  MMMMM  M 88ooood8 88'`88'`88 88'  `88 
M  MMMM' .M 88.  ... 88  88  88 88.  .88 
M       .MM `88888P' dP  dP  dP `88888P' 
MMMMMMMMMMM                              
```
---

# Challenges

Clients will not signal capabilities exceeding the current AP capabilities.

Capabilities are mutually exclusive and the AP needs to match or exceed the capabilities in order for the client to reveal their maximum capabilities.

---


## Where to find profiler (and these slides)

- https://github.com/wlan-pi/wlanpi-profiler/tree/tshark

## Where to find me

- schmelzle@hpe.com
- josh@joshschmelzle.com
- https://www.linkedin.com/in/schmelzle
- https://joshschmelzle.com
- https://bigqam.com

```

.___________. __    __       ___      .__   __.  __  ___ 
|           ||  |  |  |     /   \     |  \ |  | |  |/  / 
`---|  |----`|  |__|  |    /  ^  \    |   \|  | |  '  /  
    |  |     |   __   |   /  /_\  \   |  . `  | |    <   
    |  |     |  |  |  |  /  _____  \  |  |\   | |  .  \  
    |__|     |__|  |__| /__/     \__\ |__| \__| |__|\__\ 
                                                         
____    ____  ______    __    __                         
\   \  /   / /  __  \  |  |  |  |                        
 \   \/   / |  |  |  | |  |  |  |                        
  \_    _/  |  |  |  | |  |  |  |                        
    |  |    |  `--'  | |  `--'  |                        
    |__|     \______/   \______/                         
                                                         

```
