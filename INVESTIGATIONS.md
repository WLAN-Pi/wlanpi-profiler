# Development investigations & optimizations

This document consolidates some performance investigations, optimizations, and technical analyses conducted during profiler development.

**Period:** 2024-2026
**Last updated:** February 2026
**From branch:** dev

## Table of contents

1. [Discovery performance optimization](#discovery-performance-optimization)
2. [Probe response latency reduction](#probe-response-latency-reduction)
3. [AP mode implementation](#ap-mode-implementation)
4. [Wi-Fi 7 capability detection](#wifi-7-capability-detection)
5. [Driver-specific investigations](#driver-specific-investigations)

## Discovery performance optimization

### Problem statement

**Goal:** Reduce client discovery time from 10+ seconds to under 2 seconds  
**Root Cause:** Probe response latency of 40-110ms in original Python/scapy implementation  
**Target:** Millisecond probe responses for instant client discovery

### Investigation timeline

#### Phase 1: raw socket optimization

**Changes:**

- Replaced scapy's L2socket with raw AF_PACKET socket
- Direct byte-level frame transmission

**Results:**

- Socket send time: 6.5ms → 0.1ms (98.5% reduction)
- File: `profiler/fakeap.py`

**Key code change:**

```python
# Before: scapy L2socket
self.l2socket = conf.L2socket(iface=self.interface)

# After: Raw AF_PACKET socket
self.l2socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
self.l2socket.bind((self.interface, 0))
```

#### Phase 2: frame template pre-serialization

**Changes:**

- Pre-serialize frames at initialization using scapy
- Store as bytearrays with calculated offsets
- Patch only destination MAC (6 bytes) and sequence number (2 bytes) per response

**Results:**

- Total latency: 6-15ms → 0.1-0.25ms average (98% reduction)
- Frame building eliminated from hot path
- Target of <10ms massively exceeded

**Implementation:**

```python
# Pre-serialize at init
self.probe_response_template = bytearray(bytes(probe_resp_frame))

# Fast patching per response
radiotap_len = struct.unpack('<H', self.probe_response_template[2:4])[0]
addr1_offset = radiotap_len + 4
seq_offset = radiotap_len + 22

self.probe_response_template[addr1_offset:addr1_offset+6] = mac_bytes
struct.pack_into('<H', self.probe_response_template, seq_offset, seq_num /< 4)
```

#### Phase 3: buffer reuse & MAC caching 

**Changes:**

- Pre-allocated response buffers (zero allocation per response)
- LRU cache for MAC address parsing
- Lock-free sequence counters

**Results:**

- Best case: 0.224ms (20% faster for cached clients)
- Typical: 0.26-0.28ms (similar to Phase 2)
- Benefit scales with repeated client associations

**Performance on WLAN Pi (ARM64):**

```
lock:   0.13ms  (multiprocessing lock - eliminated in Phase 3)
manip:  0.14ms  (MAC/sequence patching)
send:   0.10ms  (raw socket send after Phase 1)
total:  0.27ms  (end-to-end after all optimizations)
```

### Python optimization limits

**Result:** Reduced probe response time from 40-110ms to ~0.3ms

**However:** Client discovery still took 10+ seconds on tested iOS devices

**Assertion:** The bottleneck is not the probe response latency in code - it's also the client's active scanning behavior:

- Clients send probe requests on each channel
- Wait only up to 20ms or less before moving to next channel
- Profiler in monitor mode cannot always respond fast enough before client changes channels (profiler itself responds fast, but the other layers slow injection down)
- Result: Multiple scan cycles required before client discovers the SSID

**Exploration:** Change from monitor mode (passive receive, manual transmit) to AP mode (hostapd handles probe responses at driver level)

## AP mode implementation

### Motivation

**Problem:** Even with 0.3ms Python code latency, total probe response time is ~16ms:

- Code execution: 0.3ms
- Userspace → kernel context switch: ~15ms
- Frame injection through monitor interface: variable latency

**Observation:** hostapd responds to probe requests much faster (driver-level response, no userspace overhead)

### Implementation

**Approach:** Hybrid mode using both hostapd and profiler

- **hostapd:** Runs on main interface (e.g., wlan0) for fast probe responses and beaconing
- **Monitor vif:** Secondary virtual interface (e.g., wlan0mon) created on same PHY
- **profiler:** Captures association requests via monitor vif for capability analysis
- **Requirement:** Adapter must support simultaneous AP + monitor mode on different vifs

**Key files:**

- `profiler/hostapd_manager.py` - Manages hostapd lifecycle
- `profiler/config_generator.py` - Generates hostapd.conf with max capabilities
- `profiler/manager.py` - Integrates AP mode initialization

**Configuration generation:**

```python
def generate_hostapd_config(interface, channel, ssid, band, country_code):
    """Generate hostapd config with maximum advertised capabilities"""
    # 802.11n (Wi-Fi 4)
    # 802.11ac (Wi-Fi 5) 
    # 802.11ax (Wi-Fi 6/6E)
    # 802.11be (Wi-Fi 7) - draft support
    # 802.11r (Fast roaming)
    # 802.11k (Radio Resource Management)
    # 802.11v (BSS Transition Management)
```

**Performance results:**

- Discovery time: 10+ seconds → 1-2 seconds in some cases (5-10x improvement)
- Probe response latency: Handled at driver level (much faster than userspace)

### Implementation notes

**Interface staging:**

1. Set main interface to managed mode
2. Start hostapd on main interface
3. Create monitor interface (e.g., wlan0mon) on same PHY
4. Profiler captures association requests on monitor interface

**Default Behavior:**

- **v2.0+:** AP mode is the default for faster discovery
- Legacy FakeAP mode available with `--fakeap` flag
- All existing tests continue to pass
- Adapters without simultaneous AP+monitor support can still use `--fakeap`

## Probe response latency reduction

### Detailed measurements

**Hardware:** WLAN Pi (ARM64)  
**Sample Size:** 50+ probe responses  

#### Original implementation (monitor mode)

**Latency breakdown:**

```
Frame building (scapy):  15-50ms
Lock acquisition:        0.1-0.4ms
Socket send (L2socket):  6-8ms
Total:                   40-110ms average
```

#### After phase 1 (raw sockets)

```
Frame building (scapy):  15-50ms (unchanged)
Lock acquisition:        0.13ms
Socket send (raw):       0.10ms ← 98.5% improvement
Total:                   15-50ms
```

#### After phase 2 (pre-serialization)

```
Frame patching:          0.14ms ← eliminated scapy overhead
Lock acquisition:        0.13ms
Socket send (raw):       0.10ms
Total:                   0.27-0.40ms ← 98% improvement
```

#### After phase 3 (buffer reuse)

```
Frame patching:          0.14ms (cached MAC: 0.09ms)
Lock-free sequence:      0.00ms ← eliminated lock
Socket send (raw):       0.10ms
Total:                   0.24-0.28ms ← 99% improvement
```

### Stats 

**Best case:**  0.224ms  
**Typical:**    0.26-0.28ms  
**Worst case:** 0.40ms
**Compared to original:** 99% reduction (110ms → 0.28ms)

## Wi-Fi 7 capability detection

### Implementation

**Capabilities added (18 total):**

1. **Extended Capabilities (2)**

   - `dot11aa_scs_support` - Stream Classification Service
   - `qos_r1_mscs_support` - Mirrored Stream Classification Service

2. **EHT MAC capabilities (4)**

   - `dot11be_epcs_support` - EPCS Priority Access
   - `dot11be_om_support` - EHT OM Control
   - `dot11be_rtwt_support` - Restricted Target Wake Time
   - `dot11be_scs_traffic_description_support` - SCS Traffic Description

3. **EHT PHY capabilities (2)**

   - `dot11be_mcs15_support` - MCS 15 Support (4-bit granular value, not boolean)
   - `dot11be_mcs14_support` - EHT DUP (MCS 14) in 6 GHz

4. **RSNX capabilities (1)**

   - `rsnx_sae_h2e` - SAE Hash-to-Element (H2E) aka Hash-to-Curve (H2C)

5. **RSN cipher suite (1)**

   - `group_cipher` / `pairwise_cipher` - GCMP-256 and other cipher detection

6. **Multi-Link Element (MLE) capabilities (9)**

   - `dot11be_mle` - MLE Presence
   - `dot11be_mle_mlc_type` - Multi-Link Control Type (0=Basic, 1=Preassoc, etc.)
   - `dot11be_mle_emlsr_support` - Enhanced Multi-Link Single Radio
   - `dot11be_mle_emlsr_padding_delay` - EMLSR Padding Delay
   - `dot11be_mle_emlsr_transition_delay` - EMLSR Transition Delay
   - `dot11be_mle_emlmr_support` - Enhanced Multi-Link Multi Radio
   - `dot11be_mle_max_simultaneous_links` - Maximum Simultaneous Links
   - `dot11be_mle_t2lm_negotiation_support` - TID-to-Link Mapping Negotiation
   - `dot11be_mle_link_reconfig_support` - Link Reconfiguration Support

## Driver-specific investigations

### Intel iwlwifi (AX200, AX210, BE200)

**Challenge:** Location Aware Regulatory (LAR) ignores `iw reg set XX`

**Behavior:**

- iwlwifi dynamically adjusts channel availability based on scan results
- Channels marked as "No IR" (No Initiate Radiation) until scan performed
- Without scan, injection will not work

**Solution Implemented:**

1. Set interface to managed mode
2. Perform scan: `iw wlan0 scan`
3. Create monitor subinterface (vif)
4. Set channel on monitor interface

**Sequence for injection:**

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up
sudo iw wlan0 scan > /dev/null
sudo iw phy0 interface add mon0 type monitor flags none
sudo ip link set mon0 up
sudo ip link set wlan0 down
sudo iw mon0 set freq 5180 HT20
```

NOTE: sequence for AP mode is slightly different.

**Country code integration:**

- Our implementation now detects country code from `iw reg get` AFTER interface staging
- This ensures LAR has populated the regulatory domain correctly
- Country code then passed to hostapd configuration

### MediaTek vs RealTek performance

Using legacy Fake AP code.

**Observation:** MediaTek adapters (mt76x2u, mt7921u) consistently perform better than RealTek (rtl88xxau)

**Differences:**

- MediaTek: More probe response retries, better injection reliability
- RealTek: Fewer retries, sometimes unreliable injection

**Recommendation:** Prefer MediaTek adapters for WLAN Pi profiler

### RealTek rtl88xxau

**Issue:** Does not support vif (Virtual Interface) creation

**Workaround:** Use main interface directly in monitor mode instead of creating mon0

**Sequence:**
```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw wlan0 set freq 5180 HT20
```

**Side effect:** Host device sometimes crashes on profiler exit when cleaning up interface

**Status:** Experimental support only, not recommended, does not support AP mode

## Technical findings

### Discovery performance

**Monitor mode (original):**

- Probe response latency: 40-110ms → 0.27ms (after optimization)
- Discovery time: 10+ seconds (client scanning behavior bottleneck)

**AP mode:**

- Probe response latency: Handled at driver level (much faster than userspace)

### GCMP-256 cipher detection

- Separate `group_cipher` and `pairwise_cipher` capabilities
  - Format: "CIPHER-NAME (TYPE)" e.g., "GCMP-256 (9)"
  - Supports multiple pairwise ciphers: "CCMP-128 (4), GCMP-256 (9)"
  - More granular information for security analysis

**Breaking change:** Database schema changed (db_key renamed) - requires v2.0.0

### Country code detection

**Implementation:**

- Dynamically detect from `iw reg get` instead of hardcoded "US"
- Detection happens AFTER interface staging (supports Intel LAR)
- Fail-fast if detection fails (regulatory compliance critical)
- Country code passed to hostapd configuration

**Files:**

- `profiler/status.py` - Country code detection logic
- `profiler/manager.py` - Integration into startup flow
- `profiler/config_generator.py` - Hostapd config generation

### Status & info files

**Purpose:** Enable external monitoring by other tools

**Files:**

- `/var/run/wlanpi-profiler.status` - Lifecycle state (starting/running/stopped/failed)
- `/var/run/wlanpi-profiler.info` - Operational data (channel, frequency, SSID, last profiled client)

**Format:** JSON v1.0

- Atomic writes (temp file + rename)
- Clean shutdown deletes files
- Failure states preserve files for debugging

## Lessons learned

### Performance optimization

1. **Userspace overhead matters:** Even "fast" Python code (0.3ms) + monitor mode injection is too slow when clients scan quickly
2. **Driver-level is "clutch":** hostapd responses are orders of magnitude faster than userspace injection
3. **Pre-computation wins:** Template pre-serialization eliminated 99% of hot path overhead
4. **But doesn't solve the real problem:** Client scanning behavior requires AP mode, not faster code

### Wi-Fi 7 implementation

1. **Read the spec carefully:** MLE Common Info Length field was critical but easy to miss
2. **Validate with real devices:** Unit tests alone aren't enough - need actual Wi-Fi 7 client pcaps
3. **scapy > tshark:** Direct byte parsing is more accurate and faster than subprocess regex

### Development process

1. **Measure everything:** Assumptions about bottlenecks were often wrong
2. **Optimize the right thing:** We optimized code to 0.3ms, but AP mode was a better solution
3. **Test incrementally:** Phase 1/2/3 approach allowed validating each optimization

## Future work

### Performance

- [ ] Benchmark AP mode vs monitor mode discovery times with different client types
- [ ] Profile memory usage with large pcap files

### Testing

- [ ] Integration tests for AP mode lifecycle
- [ ] Stress testing with lots of clients
- [ ] Error injection tests (interface failures, hostapd crashes, etc.)

### Driver support

- [ ] Automated driver detection and optimal staging selection
- [ ] Test with more Wi-Fi 7 adapters (Qualcomm, MediaTek 7922, etc.) on more kernels
