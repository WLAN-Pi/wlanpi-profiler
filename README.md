![versions](docs/images/profiler-pybadge-w-logo.svg) ![coverage-badge](coverage.svg) [![packagecloud-badge](https://img.shields.io/badge/deb-packagecloud.io-844fec.svg)](https://packagecloud.io/)

# wlanpi-profiler

Profiler is a Wi-Fi client capability analyzer tool built for the [WLAN Pi](https://github.com/WLAN-Pi/).

## What is it?

The primary purpose is to automate the collection and analysis of association request frames to understand client Wi-Fi capabilities.

Understanding client capabilities helps in:

- **WLAN design** - Factor in client capabilities (spatial streams, Tx power, frequency bands)
- **Troubleshooting** - Verify client support for 802.11k/r/v, PHY types, and channels
- **Validation** - Confirm clients can support planned network features

## Two operating modes

**1. Live capture mode (WLAN Pi / Linux)**

- Advertises a fake access point using hostapd or FakeAP
- Captures client association requests in real-time
- Requires Linux with supported Wi-Fi adapter

**2. Pcap analysis mode (cross-platform)**

- Analyzes pre-captured `.pcap` files offline
- No special hardware required - uses built-in Scapy parsing
- Works on Windows, macOS, and Linux

## What capabilities are detected?

Profiler detects **40+ client capabilities** across multiple Wi-Fi generations:

**Wi-Fi standards:**

- 802.11n (Wi-Fi 4) - HT capabilities, spatial streams
- 802.11ac (Wi-Fi 5) - VHT capabilities, MCS, 160 MHz, beamforming
- 802.11ax (Wi-Fi 6/6E) - HE capabilities, TWT, OFDMA, BSS Color
- 802.11be (Wi-Fi 7) - EHT capabilities, MLO, 320 MHz

**Management and security:**

- 802.11k - Radio resource management
- 802.11r - Fast roaming (FT)
- 802.11v - BSS transition management
- 802.11w - Protected management frames
- WPA3/SAE - Modern security with SAE Hash-to-Element

[See complete capability list](CAPABILITY_LOGIC.md)

## Quick start

### Start profiling

```bash
sudo profiler
```

### Connect a client

1. Look for SSID "Profiler xxx" (where xxx is last 3 chars of eth0 MAC)
2. Connect using passphrase: `profiler`
3. Profiler captures the association request and displays results

### View results

- **Web interface:** `http://<WLAN_Pi_IP>/profiler`
- **File system:** `/var/www/html/profiler/`
- **Terminal:** Real-time text output

[Full quick start guide →](docs/user/QUICKSTART.md)

## Installation

Profiler is included in the WLAN Pi image as a Debian package.

### Upgrade on WLAN Pi OS v3 (R4, M4, M4+, Pro)

```bash
sudo apt update
sudo apt install wlanpi-profiler
```

### Install on other systems

See [installing with pipx](INSTALLING_WITH_PIPX.md).

### Requirements

- Adapter with monitor mode and packet injection support
- Tested: mt76x2u, mt7921u (a8000), mt7921e, iwlwifi (ax200, ax210, be200)
- Elevated permissions (sudo)

## Documentation

- [Quick start guide](docs/user/QUICKSTART.md) - Get up and running
- [Configuration guide](docs/user/CONFIGURATION.md) - Customize settings
- [Command line usage](docs/user/CLI_USAGE.md) - CLI reference
- [Full documentation index](docs/README.md)

## Key features

### AP mode (default in v2.0.0)

Uses hostapd for faster client discovery (1-2 seconds vs 10+ seconds in legacy mode).

- Hostapd handles probe responses at driver level
- Monitor mode VIF captures association requests
- Requires adapter supporting simultaneous AP + monitor mode

[Learn more about AP mode →](docs/user/CONFIGURATION.md#ap-mode)

### Security modes

| Mode | WPA2 | WPA3 | 802.11r | 802.11be |
|------|------|------|---------|----------|
| ft-wpa3-mixed (default) | Yes | Yes | Yes | Yes |
| wpa3-mixed | Yes | Yes | No | Yes |
| ft-wpa2 | Yes | No | Yes | Auto-disabled |
| wpa2 | Yes | No | No | Auto-disabled |

[See all security options →](docs/user/CONFIGURATION.md#security-settings)

### External monitoring

Profiler writes JSON files for integration with other tools:

- **Status file:** `/run/wlanpi-profiler.status.json` - Real-time lifecycle state
- **Info file:** `/run/wlanpi-profiler.info.json` - Operational metrics
- **State file:** `/var/lib/wlanpi-profiler/state.json` - Persistent session data

[Learn about monitoring →](docs/MONITORING.md)

## Usage examples

### Basic usage

```bash
# Start with defaults
sudo profiler

# Use specific channel
sudo profiler -c 48

# Custom SSID
sudo profiler -s "My Profiler"
```

### Pcap analysis

```bash
# Analyze existing capture
profiler --pcap capture.pcap
```

### Common configurations

```bash
# WPA2-only clients
sudo profiler --security-mode wpa2

# Passive listening mode
sudo profiler --listen-only -c 100

# Debug logging
sudo profiler --debug
```

[More CLI examples →](docs/user/CLI_USAGE.md)

## Hardware test suite

Validate your installation with the built-in test suite:

```bash
sudo profiler test
```

Tests include:

- Hostapd binary and permissions
- Configuration and directories
- Interface discovery and capabilities
- Interface staging for monitor mode

[Testing documentation →](docs/developer/TESTING.md)

## Building from source

Developers can build Debian packages locally:

```bash
# Native architecture build
./scripts/build-package-native.sh

# Cross-architecture build
./scripts/build-package-cross.sh
```

[Development guide →](DEVELOPMENT.md)

## Contributing

Contributions are welcome! Please read the [contributing guide](CONTRIBUTING.md) for details.

## Support

- **Documentation:** [Full docs index](docs/README.md)
- **Issues:** Create a GitHub issue for bugs
- **Discussions:** Use GitHub discussions for questions and ideas
- **Known issues:** [See known issues](KNOWN_ISSUES.md)

## Acknowledgments

Thanks to Jerry Olla, Nigel Bowden, and the WLAN Pi community for their input and effort on the first versions of profiler. Without them, this project would not exist.

## License

BSD-3-Clause
