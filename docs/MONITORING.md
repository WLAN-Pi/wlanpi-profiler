# Monitoring integration

Profiler writes JSON files for external monitoring and integration with other tools.

## Overview

Three files are written during profiler operation:

| File | Location | Lifecycle | Purpose |
|------|----------|-----------|---------|
| Status | `/run/wlanpi-profiler.status.json` | Runtime | Real-time lifecycle state |
| Info | `/run/wlanpi-profiler.info.json` | Runtime | Real-time operational metrics |
| State | `/var/lib/wlanpi-profiler/state.json` | Persistent | Post-mortem analysis |

## Status file

**Location:** `/run/wlanpi-profiler.status.json`

**Lifecycle:** Created at startup, deleted on clean exit, preserved on crash

**Purpose:** Indicates the current operational state of profiler

### Example

```json
{
  "schema_version": "1.0",
  "state": "running",
  "reason": "startup_complete",
  "startup_method": "systemd",
  "pid": 12345,
  "timestamp": "2026-01-23T12:00:00Z"
}
```

### States

- **starting** - Profiler is initializing
- **running** - Profiler is active and capturing
- **stopped** - Profiler stopped cleanly
- **failed** - Profiler encountered an error

### Startup methods

- **systemd** - Started via system service
- **cli** - Started from command line

### Use cases

- Service health monitoring
- Startup verification
- Crash detection
- External tool coordination

## Info file

**Location:** `/run/wlanpi-profiler.info.json`

**Lifecycle:** Updated every 5 seconds during operation, deleted on clean exit

**Purpose:** Provides real-time operational metrics and configuration

### Example

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
  "started_at": "2026-01-23T12:00:00Z",
  "uptime_seconds": 120,
  "profile_count": 35,
  "failed_profile_count": 3,
  "total_clients_seen": 38,
  "last_profile": "aa:bb:cc:dd:ee:ff",
  "last_profile_timestamp": "2026-01-23T12:02:00Z"
}
```

### Key fields

**Configuration:**

- `phy` - PHY device name
- `interfaces` - AP and monitor interface names
- `channel` / `frequency` - Operating channel/frequency
- `country_code` - Regulatory domain
- `ssid` / `bssid` - Network identifiers
- `mode` - Operating mode (hostapd or fakeap)
- `passphrase` - WPA2/WPA3 passphrase

**Metrics:**

- `uptime_seconds` - How long profiler has been running
- `profile_count` - Successful client profiles
- `failed_profile_count` - Failed profile attempts
- `total_clients_seen` - Unique clients detected
- `last_profile` - MAC address of most recent client
- `last_profile_timestamp` - When last client was profiled

### Use cases

- Dashboard displays
- QR code generation (contains passphrase)
- Operational monitoring
- Integration with external tools

[Complete field reference →](../INFO_FILE_SCHEMA.md)

## State file

**Location:** `/var/lib/wlanpi-profiler/state.json`

**Lifecycle:** Written on exit, survives reboots

**Purpose:** Post-mortem analysis and session history

### Example

```json
{
  "schema_version": "1.0",
  "profiler_version": "2.0.0",
  "session": {
    "started_at": "2026-01-23T12:00:00Z",
    "ended_at": "2026-01-23T12:05:00Z",
    "duration_seconds": 300
  },
  "exit": {
    "status": "success",
    "code": 0,
    "reason": null,
    "message": null
  },
  "configuration": {
    "mode": "hostapd",
    "channel": 36,
    "ssid": "Profiler 056"
  },
  "metrics": {
    "profile_count": 35,
    "total_clients_seen": 38
  }
}
```

### Exit statuses

- **success** - Clean exit
- **failed** - Error occurred
- **interrupted** - Crash or forced termination

### Use cases

- Session history tracking
- Failure analysis
- Usage statistics
- Audit logging

[Complete field reference →](../STATE_FILE_SCHEMA.md)

## File behavior details

### Atomic writes

Runtime files (status and info) use atomic write operations:

1. Write to temporary file
2. Rename to final location

This prevents readers from seeing partially written files.

### Clean shutdown

On clean exit:

- Runtime files are deleted
- State file is written with exit details

### Failure or crash

On failure or crash:

- Runtime files are preserved for debugging
- State file is written with error details

## Integration examples

### Monitoring script

```bash
#!/bin/bash
# Check if profiler is running

if [ -f /run/wlanpi-profiler.status.json ]; then
    state=$(jq -r '.state' /run/wlanpi-profiler.status.json)
    if [ "$state" = "running" ]; then
        echo "Profiler is running"
        exit 0
    else
        echo "Profiler state: $state"
        exit 1
    fi
else
    echo "Profiler not running"
    exit 1
fi
```

### Dashboard display

```python
import json
import time

# Read current metrics
with open('/run/wlanpi-profiler.info.json') as f:
    info = json.load(f)

print(f"SSID: {info['ssid']}")
print(f"Channel: {info['channel']}")
print(f"Clients profiled: {info['profile_count']}")
print(f"Uptime: {info['uptime_seconds']} seconds")
```

### QR code generation

The info file contains the passphrase needed for QR code generation:

```python
import json
import qrcode

with open('/run/wlanpi-profiler.info.json') as f:
    info = json.load(f)

# Generate Wi-Fi QR code
wifi_string = f"WIFI:S:{info['ssid']};T:WPA;P:{info['passphrase']};;"
qr = qrcode.make(wifi_string)
qr.save('/tmp/profiler-qr.png')
```

## Security considerations

- Runtime files are written to `/run/` (tmpfs, not persistent)
- State file is written to `/var/lib/` (persistent)
- Files are readable by root and wlanpi group
- Passphrase is included in info file for QR generation
- Consider file permissions when integrating with external tools

## Troubleshooting

### Files not being written

1. Check that profiler is running: `sudo service wlanpi-profiler status`
2. Verify permissions on `/run/` and `/var/lib/wlanpi-profiler/`
3. Check disk space

### Stale data in info file

The info file is updated every 5 seconds. If data appears stale:

1. Check if profiler is still running
2. Verify the file is being updated: `ls -la /run/wlanpi-profiler.info.json`

### State file not created

The state file is only written on exit. If profiler crashes, it may not be written.

## See also

- [Info file schema](../INFO_FILE_SCHEMA.md) - Complete field reference
- [State file schema](../STATE_FILE_SCHEMA.md) - Complete field reference
- [Quick start guide](user/QUICKSTART.md)
- [Configuration guide](user/CONFIGURATION.md)
