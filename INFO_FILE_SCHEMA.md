# Info file schema reference

## Version history

**v1.0** (2026-01-24):
- Initial schema with all fields documented above
- Added monitoring metrics (`failed_profile_count`, `total_clients_seen`)
- Added `password` field for AP modes
- Added `invalid_frame_count` for tracking frames with corrupted MAC addresses
- Added `bad_fcs_count` for tracking frames with FCS checksum mismatches

## Overview

The profiler writes operational status and monitoring metrics to a JSON file for external consumption by Web UIs, monitoring tools, FPMS, and custom scripts.

**File Location** (depends on user context):

- **Root**: `/run/wlanpi-profiler.info.json`
- **Non-root**: `~/.local/share/wlanpi-profiler/info.json` (or `$XDG_DATA_HOME/wlanpi-profiler/info.json`)

**Format**: JSON (pretty-printed with 2-space indentation)

**Update Frequency**: 

- Created on profiler startup
- Updated when clients are profiled
- Updated when monitoring metrics change
- Deleted on clean shutdown
- Preserved on crash/failure for debugging

**Note**: The XDG-based path for non-root users allows developers to run profiler without root permissions (e.g., for pcap analysis) while still getting file output for debugging.

## File lifecycle

```
Profiler Start → info file created
    ↓
Client profiled → last_profile, profile_count updated
    ↓
Unique MAC seen → total_clients_seen updated
    ↓
Auth without assoc → failed_profile_count updated
    ↓
Clean shutdown → info file deleted
Crash/failure → info file preserved
```

## Complete schema (Version 1.0)

```json
{
  "schema_version": "1.0",
  "profiler_version": "2.0.0",
  "phy": "phy0",
  "interfaces": {
    "ap": "wlan0",
    "monitor": "wlan0profiler"
  },
  "channel": 36,
  "frequency": 5180,
  "country_code": "US",
  "ssid": "Profiler 056",
  "bssid": "44:a3:bb:06:c1:29",
  "mode": "hostapd",
  "passphrase": "profiler",
  "started_at": "2026-01-24T12:00:00+00:00",
  "uptime_seconds": 120,
  "profile_count": 35,
  "failed_profile_count": 3,
  "total_clients_seen": 38,
  "invalid_frame_count": 2,
  "bad_fcs_count": 1,
  "last_profile": "aa:bb:cc:dd:ee:ff",
  "last_profile_timestamp": "2026-01-24T12:02:00+00:00"
}
```

## Field peference

### Metadata fields

#### `schema_version` (string)

- **Description**: Info file schema version
- **Value**: `"1.0"`
- **Purpose**: Track schema evolution independently from profiler version
- **Note**: Renamed from `version` to prevent ambiguity with `profiler_version`

#### `profiler_version` (string)

- **Description**: Profiler software version
- **Example**: `"2.0.0"`
- **Purpose**: Identify which profiler version generated this data

### Radio configuration

#### `phy` (string)

- **Description**: PHY device name
- **Example**: `"phy0"`, `"phy1"`
- **Purpose**: Identify the physical wireless device
- **Note**: One PHY can have multiple virtual interfaces

#### `interfaces` (object)

- **Description**: Network interfaces being used by profiler
- **Structure**:
  ```json
  {
    "ap": "wlan0",        // AP interface (null in listen_only mode)
    "monitor": "wlan0profiler"  // Monitor interface for packet capture
  }
  ```
- **Mode-specific values**:
  - **hostapd mode**: `ap="wlan0"`, `monitor="wlan0profiler"` (two separate interfaces on same PHY)
  - **fake_ap mode**: `ap="wlan0mon"`, `monitor="wlan0mon"` (same interface for both)
  - **listen_only mode**: `ap=null`, `monitor="wlan0mon"` (no AP, monitor only)
- **Purpose**: Clarify which interfaces are used for each role in dual-interface scenarios

#### `channel` (integer)

- **Description**: Wi-Fi channel number
- **Range**: 1-14 (2.4 GHz), 36-165 (5 GHz), 1-233 (6 GHz)
- **Example**: `36`, `6`, `100`

#### `frequency` (integer | null)

- **Description**: Center frequency in MHz
- **Example**: `5180`, `2437`, `5500`
- **Null**: If channel cannot be mapped to frequency (should be rare)

#### `country_code` (string)

- **Description**: Two-letter regulatory domain code (ISO 3166-1 alpha-2)
- **Example**: `"US"`, `"GB"`, `"DE"`, `"JP"`
- **Purpose**: Determines allowed channels and power limits

### AP configuration

#### `ssid` (string)

- **Description**: SSID being broadcast
- **Default**: `"Profiler XXX"` (where XXX = last 3 chars of eth0 MAC)
- **Configurable**: Yes (via CLI `--ssid` or config.ini)
- **Example**: `"Profiler 056"`, `"Test Network"`

#### `bssid` (string)

- **Description**: AP MAC address (colon-separated)
- **Example**: `"44:a3:bb:06:c1:29"`
- **Purpose**: Used for QR code generation, client targeting

#### `mode` (string)

- **Description**: Profiler operating mode
- **Values**:
  - `"hostapd"` - Default AP mode using hostapd (fastest discovery, 1-2 second client discovery)
  - `"fake_ap"` - Legacy Fake AP mode using scapy (userspace responses, slower discovery)
  - `"listen_only"` - Passive Rx-only mode (no AP, captures any assoc requests on channel)

#### `passphrase` (string | null)

- **Description**: WPA/WPA3 passphrase for AP mode
- **Default**: `"profiler"` (configurable via `--passphrase` or config.ini)
- **Null**: In `listen_only` mode (no AP, no authentication)
- **Requirements**: 8-63 characters for WPA2/WPA3 standard
- **Purpose**: Clients must authenticate with this passphrase before sending association requests
- **Security Note**: This is intentionally exposed for easy client connection (not a real production AP)
- **Field Name**: Uses "passphrase" (not "password") to match industry standard WPA terminology

### Session timing

#### `started_at` (string, ISO 8601)

- **Description**: Profiler startup timestamp (UTC with timezone)
- **Format**: `"YYYY-MM-DDTHH:MM:SS+00:00"` or `"YYYY-MM-DDTHH:MM:SSZ"`
- **Example**: `"2026-01-24T12:00:00+00:00"`
- **Timezone**: Always UTC

#### `uptime_seconds` (integer)

- **Description**: Profiler runtime duration in seconds
- **Calculation**: `now - started_at`
- **Example**: `120` (2 minutes), `3600` (1 hour)
- **Updates**: Every time info file is updated

### Profiling metrics

#### `profile_count` (integer)

- **Description**: Number of clients successfully profiled this session
- **Initial**: `0`
- **Increments**: Each time a unique client is profiled (by capability hash)
- **Persistence**: Resets to 0 on profiler restart
- **Example**: `35`

#### `failed_profile_count` (integer)

- **Description**: Number of unique clients that sent auth but never sent association request
- **Calculation**: `len(authed_macs - assoc_macs)`
- **Purpose**: Monitor profiling health - high values may indicate:
  - Client compatibility issues
  - Client moved to another channel before completing association
  - Beacon/AP parameters causing clients to abort connection
- **Initial**: `0`
- **Example**: `3`

#### `total_clients_seen` (integer)

- **Description**: Total unique MAC addresses observed from management frame requests
- **Scope**: Counts unique MACs that sent any of:
  - Probe requests
  - Authentication requests
  - Association/Reassociation requests
- **Note**: Includes all MACs, even if they only probed and never authenticated or associated
- **Purpose**: Monitor overall client discovery effectiveness
- **Initial**: `0`
- **Example**: `38`
- **Tracking**: Updates in real-time as new unique MACs are observed

#### `invalid_frame_count` (integer)

- **Description**: Number of frames filtered due to invalid/corrupted MAC addresses
- **Purpose**: Track frames with malformed addresses (all zeros, broadcast, zero OUI, etc.)
- **Initial**: `0`
- **Example**: `2`

#### `bad_fcs_count` (integer)

- **Description**: Number of frames filtered due to bad FCS (Frame Check Sequence)
- **Purpose**: Track frames with checksum mismatches indicating corruption during transmission
- **Initial**: `0`
- **Example**: `1`
- **Note**: FCS is a 4-byte CRC32 at the end of 802.11 frames; mismatch indicates data corruption

#### `last_profile` (string | null)

- **Description**: MAC address of most recently profiled client (colon-separated)
- **Example**: `"aa:bb:cc:dd:ee:ff"`
- **Null**: If no clients profiled yet this session
- **Updates**: Each time a client is profiled

#### `last_profile_timestamp` (string | null, ISO 8601)

- **Description**: Timestamp when last client was profiled (UTC with timezone)
- **Format**: Same as `started_at`
- **Example**: `"2026-01-24T12:02:00+00:00"`
- **Null**: If no clients profiled yet this session
- **Updates**: Each time a client is profiled

## Monitoring metric relationships

```
total_clients_seen ≥ (profile_count + failed_profile_count)
```

**Why?** Because `total_clients_seen` includes:

- Clients that only sent probe requests (never authed)
- Clients that authed but never sent assoc (`failed_profile_count`)
- Clients that completed profiling (`profile_count`)

**Example**:

```
total_clients_seen = 38
  ├─ Just probed: 0 (38 - 35 - 3)
  ├─ Authed but no assoc: 3 (failed_profile_count)
  └─ Successfully profiled: 35 (profile_count)
```

## Why passphrase is required in AP mode

In `hostapd` and `fake_ap` modes, the profiler creates a WPA2/WPA3-protected AP. Clients must complete authentication before sending association requests:

```
Client → AP: Probe Request
AP → Client: Probe Response
Client → AP: Authentication Request
AP → Client: Authentication Response
Client → AP: 4-way WPA handshake (uses passphrase)
AP → Client: Handshake complete
Client → AP: Association Request ← THIS is what we profile!
```

**Without a passphrase** (open network):

- Some clients send malformed or incomplete association requests
- Modern clients may refuse to connect to open networks
- We cannot guarantee capturing full client capabilities (Wi-Fi 7 requires WPA3)

**With a passphrase** (WPA2/WPA3):

- Clients complete full authentication handshake
- Association request contains complete capability information
- Ensures reliable profiling for modern devices

## Usage examples

### Bash script

```bash
#!/bin/bash
# Check if profiler is running and get current metrics

INFO_FILE="/run/wlanpi-profiler.info.json"

if [ -f "$INFO_FILE" ]; then
    # Parse JSON using jq
    PROFILED=$(jq -r '.profile_count' "$INFO_FILE")
    FAILED=$(jq -r '.failed_profile_count' "$INFO_FILE")
    SEEN=$(jq -r '.total_clients_seen' "$INFO_FILE")
    SSID=$(jq -r '.ssid' "$INFO_FILE")
    PASSPHRASE=$(jq -r '.passphrase' "$INFO_FILE")
    
    echo "Profiler SSID: $SSID"
    echo "Passphrase: $PASSPHRASE"
    echo "Clients seen: $SEEN"
    echo "Clients profiled: $PROFILED"
    echo "Failed profiles: $FAILED"
else
    echo "Profiler is not running"
fi
```

### Python script

```python
import json
from pathlib import Path

INFO_FILE = Path("/run/wlanpi-profiler.info.json")

if INFO_FILE.exists():
    with open(INFO_FILE) as f:
        info = json.load(f)
    
    print(f"Profiler SSID: {info['ssid']}")
    print(f"Passphrase: {info['passphrase']}")
    print(f"Profiling on channel {info['channel']} ({info['frequency']} MHz)")
    print(f"Clients seen: {info['total_clients_seen']}")
    print(f"Clients profiled: {info['profile_count']}")
    print(f"Failed profiles: {info['failed_profile_count']}")
    
    if info['last_profile']:
        print(f"Last profiled: {info['last_profile']} at {info['last_profile_timestamp']}")
else:
    print("Profiler is not running")
```

### QR code generation

Generate a Wi-Fi QR code for easy client connection:

```python
import json
import qrcode

with open("/run/wlanpi-profiler.info.json") as f:
    info = json.load(f)

# Generate Wi-Fi QR code string
wifi_config = f"WIFI:S:{info['ssid']};T:WPA;P:{info['passphrase']};;"

qr = qrcode.QRCode(version=1, box_size=10, border=4)
qr.add_data(wifi_config)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")
img.save("profiler_qr.png")
```

### Web UI integration

```javascript
// Fetch profiler status for web dashboard
async function getProfilerStatus() {
    const response = await fetch('/profiler/info.json');
    const info = await response.json();
    
    document.getElementById('ssid').textContent = info.ssid;
    document.getElementById('passphrase').textContent = info.passphrase;
    document.getElementById('channel').textContent = info.channel;
    document.getElementById('profile_count').textContent = info.profile_count;
    document.getElementById('failed_count').textContent = info.failed_profile_count;
    document.getElementById('total_seen').textContent = info.total_clients_seen;
    
    // Calculate uptime
    const uptimeMinutes = Math.floor(info.uptime_seconds / 60);
    document.getElementById('uptime').textContent = `${uptimeMinutes} minutes`;
}

// Poll every 5 seconds
setInterval(getProfilerStatus, 5000);
```

## Debug logging

In addition to the info file, profiler logs detailed session statistics to debug logs:

```
[DEBUG] Session stats: probes=1234, auths=56, assocs=42, unique_clients=38, failed=3, invalid_frames=2, bad_fcs=1
```

**Logged**:

- Every 60 seconds (at DEBUG level)
- On profiler shutdown (at INFO level)

**Metrics**:

- `probes` - Total probe requests received (can be >1 per MAC)
- `auths` - Total auth requests received (can be >1 per MAC)
- `assocs` - Total assoc requests received (can be >1 per MAC)
- `unique_clients` - Same as `total_clients_seen` in info file
- `failed` - Same as `failed_profile_count` in info file
- `invalid_frames` - Same as `invalid_frame_count` in info file
- `bad_fcs` - Same as `bad_fcs_count` in info file

## Related documentation

- [README.md](README.md) - General profiler usage and features
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development setup and testing
- [profiler/status.py](profiler/status.py) - Status file implementation

