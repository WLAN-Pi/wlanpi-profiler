Client capability logic
=======================

**Dozens of capabilities detected.**

**802.11 generational:**

- 802.11n (HT) + spatial streams
- 802.11ac (VHT) + spatial streams + MCS + 160 MHz + beamforming
- 802.11ax (HE) + spatial streams + MCS + features (SR, TWT, UORA, BSR, etc.)
- 802.11be (EHT) + spatial streams + MCS + features
  - EHT MAC: EPCS, OM Control, R-TWT, SCS Traffic Description
  - EHT PHY: MCS 15, MCS 14
  - MLE: 9 multi-link capabilities
- 6 GHz band capabilities (out-of-band)

**Management & security:**

- 802.11k (Radio Resource Management)
- 802.11r (Fast Roaming)
- 802.11v (BSS Transition Management)
- 802.11w (Protected Management Frames)
- RSNX: SAE H2E
- RSN Ciphers: Group Cipher, Pairwise Cipher(s)

**Other:**

- Max/min power
- Supported channels
- Extended capabilities: SCS, MSCS
- Randomized MAC detection
- Manufacturer/chipset heuristics

The following logic operates on an 802.11 association request frame, looking at various tagged parameter (information elements) values to determine client capabilities.

1. 802.11n: inspect tagged parameter number 45 (HT Capabilities)
    - a. is tagged parameter present? 
        - Y - 802.11n supported
        - N - 802.11n not supported
    - b. inspect octets 3 to 7 (Rx MCS sets) 
        - count Rx MCS bitmasks that are set (11111111) to determine number of streams supported
        
2. 802.11ac: inspect tagged parameter 191 (VHT Capabilities)
    - a. is tagged parameter present?
        - Y - 802.11ac supported
        - N - 802.11ac not supported
    - b. inspect octets 4 & 5 (Rx MCS map) - 
        - count Rx MCS map bit pairs not set to '11' to determine number of streams supported
        - MCS 0-7 if pairs are set to '00'
        - MCS 0-8 if pairs are set to '01'
        - MCS 0-9 if pairs are set to '11'
    - c. inspect octet 1 (one of the four vht capability octets)
        - if bit zero set to '1', client is SU Beam-formee capable
    - d. inspect octet 1 (one of the four vht capability octets)
        - extract bits 7, 6, 5 (MSB to LSB) to determine VHT Beamformee STS
        - value = (bit7 << 2) | (bit6 << 1) | bit5
    - e. inspect octet 2 (one of the four vht capability octets)
        - if bit zero set to '1', client is MU Beam-formee capable     
    - f. inspect octet 0 (one of the four vht capability octets)
        - if bit zero set to '1', client supports VHT 160 MHz 

3. 802.11k: inspect tagged parameter 70 (RM Enabled Capabilities) - RM = radio management
    - a. is tagged parameter present?
        - Y - 802.11k supported
        - N - 802.11k not supported

4. 802.11r - inspect tagged parameter 54 (Mobility Domain)
    - a. is tagged parameter present? 
        - Y - 802.11r supported
        - N - 802.11r not supported

5. 802.11v - inspect tagged parameter 127 (Extended capabilities)
    - a. is tagged parameter present?
        - N - 802.11v not supported
        - Y - 802.11v may be supported
            - does octet 3 exist in ext capabilities tagged parameter?
                - N - 802.11v not supported
                - Y - 802.11v may be supported
                    - a. is bit 3 of octet 3 set to '1'?
                        - Y - 802.11v is supported
                        - N - 802.11v not supported

6. Max/Min Power - inspect tagged parameter 33 (Power Capability)
    - a. is tagged parameter present?
        - N - unable to report max power
        - Y - inspect octet 0 & 1 of tagged parameter
            - a. octet 1 - max power in dBm
            - b. octet 0 - min power in dBm

7. Supported channels - inspect tagged parameter 6 (Supported Channels)
    - a. Step through each channel set octet-pair provided reporting start channel and other channels in range
        - Note: use step of 4 if start channel above number 14 (must be 5GHz channels), use step of 1 otherwise

8. 802.11w: inspect tagged parameter 48 (RSN capabilities) 
    - a. is bit 8 of 2nd last octet in the rsn capabilities field set?
        - Y - 11w supported
        - N - 11w not supported

9. 802.11ax: inspect extended tag number 35 (HE Capabilities)
    - a. is HE capabilities tagged parameter present? 
        - Y - 802.11ax supported
        - N - 802.11ax not supported
    - a (Y) - pass
    - a (N) - do not evaluate remaining capabilities
    - b. Number of spatial streams by inspecting octets 19 & 20 (Rx MCS map) - 
        - count Rx MCS map bit pairs not set to '11' to determine number of streams supported
    - c. MCS 10/11 support inspect NSS subfield (b.)
        - MCS 0-7: NSS bit pairs set to '00'
        - MCS 0-9: NSS bit pairs set to '01'
        - MCS 0-11: NSS bit pairs set to '10'
    - d. Punctured Preamble support: B8-B11 of HE PHY Capabilities 
        - Y - supported - if any(B0, B1, B2, B3) == true
        - N - not supported - if any(B0, B1, B2, B3) == false
    - e. HE ER (Extended Range) SU PPDU: B64 of HE PHY Capabilities
        - Y - supported 
        - N - not supported
    - f. Target Wake Time (TWT) support by inspecting octet 1 (bit 1):
        - Y - supported
        - N - not supported
    - g. Uplink OFDMA Random Access (UORA) support: B26 of HE PHY Capabilities
        - Y - supported
        - N - not supported 
    - h. Buffer Status Report (BSR) support: B19 of HE PHY Capabilities
        - Y - supported
        - N - not supported 
    - i. HE SU Beamformer: Bit 31 of HE PHY Capabilities
        - 1 - supported
        - 0 - not supported
    - j. HE SU Beamformee: Bit 32 of HE PHY Capabilities
        - 1 - supported
        - 0 - not supported
    - k. HE Beamformee STS: Bits 34-36 of HE PHY Capabilities (PHY byte 4, bits 2-4)
        - Extract bits 4, 3, 2 (MSB to LSB) from PHY capabilities byte 4
        - value = (bit4 << 2) | (bit3 << 1) | bit2
        - Maps to Wireshark field: wlan.ext_tag.he_phy_cap.beamformee_sts_lte_80mhz (mask 0x1C00)

10. 802.11ax spatial reuse: inspect spatial reuse tag number 39 (Spatial Reuse Parameter Set)
    - a. is Spatial Reuse Parameter Set tagged parameter present?
        - Y - supported
        - N - not supported

11. 802.11ax 6 GHz capabilities: inspect extend tag number 59 (HE 6 GHz band capabilities)
    - a. is HE 6 GHz band capabilities tagged parameter present?
        - Y - supported
        - N - not supported

12. Randomized MAC address - inspect OUI of 24-bit MAC address
    - a. check if any of these digits `2`, `6`, `a`, or `e` is located in the second hex position from the left
        - N - MAC is not unicast local address
        - Y - MAC is a unicast local address (private mac/randomized mac)

13. MAC address manufacturer detection through heuristics 
    - a. can MAC address be resolved by lookup of OUI in manuf db?
        - Y - Return match
        - N - investigate tagged parameter 221 (vendor specific)
            - is vendor MAC in manuf database?
                - N - Unable to match
                - Y - Check OUI matches our heuristic
                    - Y - Return match
                    - N - Unable to match

14. Chipset manufacturer detection through heuristics 
    - a. can Vendor Specific Tag 221 OUI be resolved by lookup of OUI in manuf db?
        - N - Unable to match
        - Y - Check OUI matches our heuristics
            - Y - return match
            - N - unknown / unable to match

15. Detecting 6 GHz Capability Out-of-band via Alternative Operating Class
    - a. is Supported Operating Classes tagged parameter present?
        - N - not supported
        - Y - may be supported
            - is 131 in alternative class list?
                - Y - 20 MHz channel spacing in 6 GHz operating class supported
            - is 132 in alternative class list?
                - Y - 40 MHz channel spacing in 6 GHz operating class supported
            - is 133 in alternative class list?
                - Y - 80 MHz channel spacing in 6 GHz operating class supported
            - is 134 in alternative class list?
                - Y - 160 MHz channel spacing in 6 GHz operating class supported
            - is 135 in alternative class list?
                - Y - 80+80 MHz channel spacing in 6 GHz operating class supported

16. Extended Capabilities - Stream Classification Service (SCS)
    - inspect tagged parameter 127 (Extended Capabilities), byte 6 (0-indexed), bit 6
        - a. Bit 54 overall = byte 6 (54 // 8 = 6), bit 6 (54 % 8 = 6)
        - b. is bit 6 of byte 6 set to '1'?
            - Y - SCS (Stream Classification Service) supported
            - N - SCS not supported

17. QoS R1 - Mirrored Stream Classification Service (MSCS)
    - inspect tagged parameter 127 (Extended Capabilities), byte 10 (0-indexed), bit 5
        - a. Bit 85 overall = byte 10 (85 // 8 = 10), bit 5 (85 % 8 = 5)
        - b. is bit 5 of byte 10 set to '1'?
            - Y - MSCS (Mirrored SCS) supported
            - N - MSCS not supported

18. EHT MAC Capabilities
    - inspect extended tag 106 (EHT Capabilities)
        - a. is EHT Capabilities tagged parameter present?
            - N - skip all EHT MAC capabilities
            - Y - continue to inspect EHT MAC Capabilities field (octets 3-4)
    
    - a. EPCS Priority Access - inspect octet 3, bit 0
        - Y - EPCS Priority Access supported
        - N - not supported
    
    - b. EHT OM Control - inspect octet 3, bit 1
        - Y - EHT OM (Operating Mode) Control supported
        - N - not supported
    
    - c. Restricted Target Wake Time (R-TWT) - inspect octet 4, bit 3
        - Y - Restricted TWT supported
        - N - not supported
    
    - d. SCS Traffic Description - inspect octet 4, bit 4
        - Y - SCS Traffic Description supported
        - N - not supported

19. EHT PHY Capabilities
    - inspect extended tag 106 (EHT Capabilities), EHT PHY Capabilities field
    
    - a. MCS 15 Support - inspect octet 11, bits 4-7 (4-bit field)
        - Value 0-15: MCS 15 support level
        - 0 = not supported
        - Non-zero = supported with specific configuration (see IEEE 802.11be Table 9-417r)
        - Example: Value 7 = Support in 52+26 and 106+26-tone MRUs
    
    - b. EHT DUP (MCS 14) in 6 GHz - inspect octet 11, bit 3
        - Y - EHT DUP (MCS 14) in 6 GHz supported
        - N - not supported

20. RSNX Capabilities - SAE Hash-to-Element (H2E/H2C)
    - inspect tagged parameter 244 (RSNX Capabilities), octet 0, bit 5
        - a. is RSNX Capabilities present?
            - N - not supported
            - Y - check bit 5 of first octet
                - Y - SAE Hash-to-Element (H2E) supported
                - N - not supported

21. RSN Cipher Suite - Group and Pairwise Ciphers
    - inspect tagged parameter 48 (RSN Information)
        - a. is RSN Information present?
            - N - report "Not reported"
            - Y - continue
        
        - b. Group Cipher Suite (octets 2-5)
            - Parse 4-byte cipher suite (OUI + Type)
            - Common types:
                - Type 4 = CCMP-128 (AES)
                - Type 9 = GCMP-256
                - Type 10 = GCMP-128
            - Format: "CIPHER-NAME (TYPE)" e.g., "GCMP-256 (9)"
        
        - c. Pairwise Cipher Suite List (octets 8+)
            - Count of pairwise cipher suites (2 bytes)
            - Parse each 4-byte cipher suite
            - Multiple ciphers: comma-separated
            - Format: "CIPHER1 (TYPE1), CIPHER2 (TYPE2)"
            - Example: "CCMP-128 (4), GCMP-256 (9)"

22. Multi-Link Element (MLE) - 802.11be Multi-Link Operation
    - inspect extended tag 107 (Multi-Link Element)
        - a. is MLE present?
            - N - all MLE capabilities = not supported
            - Y - continue to parse
        
        - b. Parse MLE Structure:
            ```
            Byte 0:     Extension ID (107)
            Bytes 1-2:  Multi-Link Control (16-bit LE)
            Byte 3:     Common Info Length
            Bytes 4+:   Common Info fields (variable)
            ```
        
        - c. Multi-Link Control (MLC) Type - bits 0-2 of MLC field
            - Type 0 = Basic
            - Type 1 = Probe Request
            - Type 2 = Reconfiguration  
            - Type 3 = TDLS
            - Type 4 = Priority Access
            - Type 5-7 = Reserved
        
        - d. Calculate EML/MLD Capabilities offset:
            ```
            offset = 4                    # Skip to Common Info start
            offset += 6                   # Skip MLD MAC Address
            if (MLC & 0x0010): offset += 1   # Skip Link ID Info
            if (MLC & 0x0020): offset += 1   # Skip BSS Params Change Count
            if (MLC & 0x0040): offset += 2   # Skip Medium Sync Delay
            # Now at EML Capabilities (2 bytes) + MLD Capabilities (2 bytes)
            ```
        
        - e. EML Capabilities (2 bytes at calculated offset)
            - EMLSR Support: bit 0
                - Y - Enhanced Multi-Link Single Radio supported
                - N - not supported
            
            - EMLSR Padding Delay: bits 1-3 (3-bit field)
                - Values 0-7 representing delay in microseconds
            
            - EMLSR Transition Delay: bits 4-6 (3-bit field)
                - Values 0-7 representing delay in microseconds
            
            - EMLMR Support: bit 7
                - Y - Enhanced Multi-Link Multi Radio supported
                - N - not supported
        
        - f. MLD Capabilities (2 bytes following EML Capabilities)
            - Max Simultaneous Links: bits 0-3 (4-bit field)
                - Values 0-15 representing number of links
            
            - TID-to-Link Mapping Negotiation Support: bits 10-11
                - 0 = Not supported
                - Non-zero = Supported (various modes)
            
            - Link Reconfiguration Support: bit 6
                - Y - Supported
                - N - Not supported

## JSON Schema v2.0.0 - capture source metadata

### capture_source field

Indicates the origin of the capability analysis:

**"profiler_ap"** (live capture mode)

- Capture was performed using profiler's own AP (hostapd or FakeAP mode)
- AP settings are controlled: channel, SSID, beacon content, IE configuration
- Represents a controlled test environment with known variables
- Client capabilities reflect responses to profiler's specific AP configuration

**"external"** (pcap analysis mode)

- Capture was imported from an external pcap file
- AP settings are unknown: channel, SSID, beacon content, IE configuration not controlled by profiler
- Represents real-world or uncontrolled capture environment
- Client capabilities may be influenced by unknown AP advertisement

### Why the capture source matters

Client capability advertisement can vary based on AP context:

1. **Band/frequency dependencies**

   - Client may not advertise 6 GHz capabilities when associating to 5 GHz AP
   - HT/VHT/HE/EHT capabilities depend on what the AP supports

2. **Management protocol dependencies**

   - 802.11r (Fast Transition) only advertised if AP broadcasts Mobility Domain IE
   - 802.11k/v features may be suppressed if AP doesn't support them

3. **Security context**

   - SAE H2E support may depend on AP's RSNX advertisement
   - Cipher suite selection influenced by AP's RSN IE
   - MFP

4. **Client optimization**

   - Some clients hide advanced features when connecting to legacy APs
   - Spatial stream count may be limited based on AP capabilities

### Usage recommendations

**For controlled testing:**

- Use `capture_source: "profiler_ap"` results
- A more consistent AP configuration across all tests
- Reliable baseline for comparing client capabilities

**For real-world analysis:**

- Accept `capture_source: "external"` results
- Understand and accept that capabilities are context-dependent
- Consider AP configuration when interpreting results

### Related schema fields

- `capture_ssid` - SSID of the AP (may be profiler's SSID or external)
- `capture_channel` - Channel of capture (controlled or from pcap)
- `capture_bssid` - AP MAC address
- `capture_manuf` - AP manufacturer (OUI lookup)
- `capture_band` - Frequency band (2.4, 5, 6 GHz)

