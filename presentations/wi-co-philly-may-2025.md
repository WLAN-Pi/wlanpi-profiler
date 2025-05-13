---
author: "Josh Schmelzle"
date: "May 15, 2025"
paging: "-~={%d}=~-"
---

<!--
macOS depends installation:

brew install slides 
brew install perl
brew install cpanminus
which cpanm
cpanm Graph::Easy

find /usr/local/bin /usr/bin /opt /usr/local/Cellar -name graph-easy 2>/dev/null

fish_add_path /opt/homebrew/Cellar/perl/5.40.2/bin

pip install seqdiag

Enable pre-processing on the file:

chmod +x <file>

Start presentation with:

slides <file>
-->

# whoami

Josh Schmelzle

## dayjob 

- HPE Aruba Networking

## other 

- WLAN Pi

- Big QAM, LLC

---

# Profiling Wi-Fi 7 clients

## Agenda

- Wi-Fi 7
- Client capabilities
- Profiling

---

# Wi-Fi 7

## Main goals

1. Improve peak throughput

2. Improve link efficiency, reliability, and latency.

## Key features

- Multi-link device (MLD) framework
    - Single-link (single-radio/SR)
    - Multi-link (multi-radio/MR)
- Multiple resource units (MRU) per client
- 4K QAM (MCS 12/13)
- 320 MHz 
- Triggered uplink access (TUA) and stream classification service (SCS)
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
- Basic load balancing (BSS Transition Management)

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

---

## Terminology

- MLO - multi-link operation 
- MLD - multi-link device

### MLD operation

- MLSR - multi-link sigle-radio
- EMLSR - enhanced multi-link single-radio
- MLMR - multi-link multi-radio
- STR - simultaneous transmit and receive

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

- Listens on multiple links simultaneously
- Receives initial control frame
- Switches all resources to target link for subsequent data exchange
- Uses padding delay and transition delay

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

##### Channel access and frame exchange in a MLD is based on the capabilities exchanged during association.

This means we can analyze and profile capabilities based on the association request-response exchange.

---

## Capabilities

TODO

---

# Challenges

Clients will not signal capabilities exceeding the current AP capabilities.

Capabilities are mutually exclusive and the AP needs to match or exceed the capabilities in order for the client to reveal their maximum capabilities.

---

# Thank you

###### Happy profiling!

## Where to find profiler (and these slides)

- https://wlanpi.com
- https://github.com/wlan-pi/wlanpi-profiler

## Where to find me

- schmelzle@hpe.com
- josh@joshschmelzle.com
- https://www.linkedin.com/in/schmelzle
- https://joshschmelzle.com
- https://bigqam.com
