# Last-session file schema reference

## Version history

**v1.0** (2026-01-26):

- Initial schema with all fields documented above
- Exit status categories: success, failed, interrupted
- Exit reason codes for common failure scenarios
- Configuration and metrics snapshot from info file
- Added `invalid_frame_count` for tracking frames with corrupted MAC addresses
- Added `bad_fcs_count` for tracking frames with FCS checksum mismatches

## Overview

The profiler writes a persistent last-session file on exit that survives reboots. This file provides post-mortem analysis capability and monitoring integration for external tools.

**File Location**: `/var/lib/wlanpi-profiler/last-session.json`

**Format**: JSON (pretty-printed with 2-space indentation)

**Permissions**: 

- Directory: `0755` (world-readable, root-writable)
- File: `0644` (world-readable, root-writable)

**Update Frequency**:

- Written once on profiler exit (clean shutdown, error, or crash)
- Never deleted (persists until next profiler run overwrites it)
- Survives system reboots

**Note**: This file is only written for live capture mode (requires root). PCAP analysis mode (`--pcap`) does not write this file.

## File lifecycle

```
Profiler Start -> runtime files created
    |
    v
Profiler Running -> runtime files updated in real-time
    |
    v
Profiler Exit -> last-session file written with final snapshot
    |            (runtime files deleted on clean exit)
    v
System Reboot -> last-session file persists, runtime files lost
    |
    v
Next Profiler Run -> last-session file overwritten with new session
```

## Complete schema (version 1.0)

```json
{
  "schema_version": "1.0",
  "profiler_version": "2.0.0",
  
  "session": {
    "started_at": "2026-01-26T12:56:17+00:00",
    "ended_at": "2026-01-26T12:56:23+00:00",
    "duration_seconds": 6
  },
  
  "exit": {
    "status": "success",
    "code": 0,
    "reason": null,
    "message": null
  },
  
  "configuration": {
    "mode": "hostapd",
    "phy": "phy1",
    "channel": 36,
    "frequency": 5180,
    "country_code": "US",
    "ssid": "Profiler 056",
    "bssid": "44:a3:bb:06:c1:29"
  },
  
  "metrics": {
    "profile_count": 0,
    "failed_profile_count": 0,
    "total_clients_seen": 1,
    "invalid_frame_count": 0,
    "bad_fcs_count": 0,
    "last_profile": null,
    "last_profile_timestamp": null
  }
}
```

## Field reference

### Metadata fields

#### `schema_version` (string)

- **Description**: Last-session file schema version
- **Value**: `"1.0"`
- **Purpose**: Track schema evolution independently from profiler version

#### `profiler_version` (string)

- **Description**: Profiler software version
- **Example**: `"2.0.0"`
- **Purpose**: Identify which profiler version generated this data

### Session timing

#### `session.started_at` (string, ISO 8601)

- **Description**: When profiler started (UTC with timezone)
- **Format**: `"YYYY-MM-DDTHH:MM:SS+00:00"`
- **Example**: `"2026-01-26T12:56:17+00:00"`

#### `session.ended_at` (string, ISO 8601)

- **Description**: When profiler exited (UTC with timezone)
- **Format**: `"YYYY-MM-DDTHH:MM:SS+00:00"`
- **Example**: `"2026-01-26T12:56:23+00:00"`

#### `session.duration_seconds` (integer)

- **Description**: Session duration in seconds
- **Calculation**: `ended_at - started_at`
- **Example**: `6`, `3600`, `86400`

### Exit information

#### `exit.status` (string)

- **Description**: Exit status category
- **Values**:
  - `"success"` - Clean shutdown (SIGINT, SIGTERM)
  - `"failed"` - Error condition detected
  - `"interrupted"` - Unexpected termination (uncaught exception)

#### `exit.code` (integer)

- **Description**: POSIX exit code
- **Values**:
  - `0` - Success
  - `1` - Error or unexpected termination

#### `exit.reason` (string | null)

- **Description**: Machine-readable reason code
- **Values**: See [Exit Reason Codes](#exit-reason-codes) table
- **Null**: For clean shutdowns (no error)

#### `exit.message` (string | null)

- **Description**: Human-readable error message
- **Example**: `"hostapd process exited with code 1"`, `"Interface wlan0 not found"`
- **Null**: For clean shutdowns (no error)

### Configuration snapshot

These fields are captured from the last known state of the profiler session.

#### `configuration.mode` (string | null)

- **Description**: Profiler operating mode
- **Values**: `"hostapd"`, `"fake_ap"`, `"listen_only"`
- **Null**: If profiler failed before mode was set

#### `configuration.phy` (string | null)

- **Description**: PHY device name
- **Example**: `"phy0"`, `"phy1"`

#### `configuration.channel` (integer | null)

- **Description**: Wi-Fi channel number
- **Range**: 1-14 (2.4 GHz), 36-165 (5 GHz), 1-233 (6 GHz)

#### `configuration.frequency` (integer | null)

- **Description**: Center frequency in MHz
- **Example**: `5180`, `2437`, `5500`

#### `configuration.country_code` (string | null)

- **Description**: Two-letter regulatory domain code (ISO 3166-1 alpha-2)
- **Example**: `"US"`, `"GB"`, `"DE"`

#### `configuration.ssid` (string | null)

- **Description**: SSID being broadcast
- **Example**: `"Profiler 056"`

#### `configuration.bssid` (string | null)

- **Description**: AP MAC address (colon-separated)
- **Example**: `"44:a3:bb:06:c1:29"`

### Profiling metrics

#### `metrics.profile_count` (integer)

- **Description**: Number of clients successfully profiled this session
- **Default**: `0`

#### `metrics.failed_profile_count` (integer)

- **Description**: Number of clients that authenticated but never sent association request
- **Default**: `0`

#### `metrics.total_clients_seen` (integer)

- **Description**: Total unique MAC addresses observed
- **Default**: `0`

#### `metrics.invalid_frame_count` (integer)

- **Description**: Number of frames filtered due to invalid/corrupted MAC addresses
- **Default**: `0`

#### `metrics.bad_fcs_count` (integer)

- **Description**: Number of frames filtered due to bad FCS (Frame Check Sequence)
- **Default**: `0`
- **Note**: FCS is a 4-byte CRC32 at the end of 802.11 frames; mismatch indicates data corruption

#### `metrics.last_profile` (string | null)

- **Description**: MAC address of most recently profiled client
- **Example**: `"aa:bb:cc:dd:ee:ff"`
- **Null**: If no clients profiled

#### `metrics.last_profile_timestamp` (string | null, ISO 8601)

- **Description**: When last client was profiled
- **Null**: If no clients profiled

## Exit status interpretation

**Important:** Check `exit.status` field, NOT `exit.code`, to distinguish between different failure modes:

| exit.code | exit.status | Meaning |
|-----------|-------------|---------|
| 0 | `"success"` | Clean shutdown (intentional) |
| 1 | `"failed"` | Expected failure (known error condition) |
| 1 | `"interrupted"` | Unexpected failure (crash, uncaught exception) |

Both `"failed"` and `"interrupted"` have exit code 1, but:

- `"failed"` means profiler detected and handled an error
- `"interrupted"` means profiler crashed unexpectedly

## Exit reason codes

These values come from the `StatusReason` enum in `profiler/status.py` and are used consistently in both `status.json` and `last-session.json`.

| Reason code | When used |
|-------------|-----------|
| `startup_complete` | Startup completed successfully (not an error) |
| `user_requested` | User requested shutdown (not an error) |
| `country_code_detection` | Regulatory domain detection failed |
| `insufficient_permissions` | Insufficient permissions to run |
| `interface_validation` | Interface validation failed |
| `config_validation` | Invalid configuration |
| `missing_tools` | Required tools not found |
| `already_running` | Another profiler instance detected |
| `file_not_found` | PCAP file, config file, or other required file not found |
| `hostapd_crashed` | Hostapd process died during operation |
| `hostapd_start_failed` | Hostapd initialization error |
| `fakeap_crashed` | Fake AP process died during operation |
| `unknown_error` | Unknown failure |

## Usage examples

### Bash script

```bash
#!/bin/bash
# Check last profiler session status

SESSION_FILE="/var/lib/wlanpi-profiler/last-session.json"

if [ -f "$SESSION_FILE" ]; then
    # Parse JSON using jq
    STATUS=$(jq -r '.exit.status' "$SESSION_FILE")
    REASON=$(jq -r '.exit.reason // "none"' "$SESSION_FILE")
    DURATION=$(jq -r '.session.duration_seconds' "$SESSION_FILE")
    PROFILED=$(jq -r '.metrics.profile_count' "$SESSION_FILE")
    
    echo "Last session status: $STATUS"
    echo "Exit reason: $REASON"
    echo "Duration: ${DURATION}s"
    echo "Clients profiled: $PROFILED"
    
    if [ "$STATUS" != "success" ]; then
        MESSAGE=$(jq -r '.exit.message // "No message"' "$SESSION_FILE")
        echo "Error message: $MESSAGE"
    fi
else
    echo "No profiler last-session file found"
fi
```

### Python script

```python
import json
from pathlib import Path

SESSION_FILE = Path("/var/lib/wlanpi-profiler/last-session.json")

if SESSION_FILE.exists():
    with open(SESSION_FILE) as f:
        session = json.load(f)
    
    exit_info = session["exit"]
    timing = session["session"]
    metrics = session["metrics"]
    
    print(f"Last session: {exit_info['status']}")
    print(f"Duration: {timing['duration_seconds']}s")
    print(f"Clients profiled: {metrics['profile_count']}")
    
    if exit_info["status"] == "success":
        print("Profiler exited cleanly")
    elif exit_info["status"] == "failed":
        print(f"Profiler failed: {exit_info['reason']}")
        if exit_info["message"]:
            print(f"  Message: {exit_info['message']}")
    elif exit_info["status"] == "interrupted":
        print(f"Profiler crashed: {exit_info['message']}")
else:
    print("Profiler has not run yet")
```

### Using jq for quick checks

```bash
# Check if last run was successful
jq -e '.exit.status == "success"' /var/lib/wlanpi-profiler/last-session.json

# Get just the exit reason
jq -r '.exit.reason' /var/lib/wlanpi-profiler/last-session.json

# Get session duration in human-readable format
jq -r '"Duration: \(.session.duration_seconds / 60 | floor)m \(.session.duration_seconds % 60)s"' /var/lib/wlanpi-profiler/last-session.json

# Check if any clients were profiled
jq '.metrics.profile_count > 0' /var/lib/wlanpi-profiler/last-session.json

# Get configuration summary
jq '{mode: .configuration.mode, channel: .configuration.channel, ssid: .configuration.ssid}' /var/lib/wlanpi-profiler/last-session.json
```

### Monitoring integration

```bash
#!/bin/bash
# Nagios/Icinga check script for profiler state

SESSION_FILE="/var/lib/wlanpi-profiler/last-session.json"

if [ ! -f "$SESSION_FILE" ]; then
    echo "UNKNOWN - No last-session file found"
    exit 3
fi

STATUS=$(jq -r '.exit.status' "$SESSION_FILE")
REASON=$(jq -r '.exit.reason // "none"' "$SESSION_FILE")

case "$STATUS" in
    "success")
        echo "OK - Last profiler run succeeded"
        exit 0
        ;;
    "failed")
        echo "WARNING - Last profiler run failed: $REASON"
        exit 1
        ;;
    "interrupted")
        echo "CRITICAL - Profiler crashed: $REASON"
        exit 2
        ;;
    *)
        echo "UNKNOWN - Unexpected status: $STATUS"
        exit 3
        ;;
esac
```

## Relationship to runtime files

The last-session file complements the runtime files:

| File | Location | Lifecycle | Purpose |
|------|----------|-----------|---------|
| `last-session.json` | `/var/lib/wlanpi-profiler/` | Persistent (survives reboot) | Post-mortem analysis |
| `status.json` | `/run/wlanpi-profiler.status.json` | Runtime (deleted on exit) | Real-time lifecycle state |
| `info.json` | `/run/wlanpi-profiler.info.json` | Runtime (deleted on exit) | Real-time operational metrics |

**When profiler is running:**

- Read `status.json` for current lifecycle state
- Read `info.json` for current operational metrics
- `last-session.json` contains data from previous run

**When profiler is stopped:**

- Runtime files are deleted (clean exit) or preserved (crash)
- `last-session.json` contains snapshot of completed session

## Schema versioning

- **Major version changes** (1.0 -> 2.0): Breaking changes (fields removed, types changed)
- **Minor version changes** (1.0 -> 1.1): Backward-compatible additions (new fields)

Consumers should check `schema_version` and handle gracefully:

```python
session = json.load(open("/var/lib/wlanpi-profiler/last-session.json"))
if session["schema_version"].startswith("1."):
    # Handle v1.x format
    pass
else:
    # Unknown schema version
    print(f"Warning: Unknown schema version {session['schema_version']}")
```

## Related documentation

- [README.md](README.md) - General profiler usage and features
- [INFO_FILE_SCHEMA.md](INFO_FILE_SCHEMA.md) - Runtime info file schema
- [PERSISTENT_STATE_DESIGN.md](PERSISTENT_STATE_DESIGN.md) - Design document for this feature
- [profiler/status.py](profiler/status.py) - Implementation

