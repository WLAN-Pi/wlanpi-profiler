# Configuration guide

Profiler can be configured through command line arguments, environment variables, or a configuration file.

## Configuration file

The default configuration file location is:

```
/etc/wlanpi-profiler/config.ini
```

### Example configuration

```ini
[GENERAL]
channel: 36
interface: wlan0
ssid: My Profiler
passphrase: MyPassword
security_mode: ft-wpa3-mixed
ft_disabled: false
he_disabled: false
be_disabled: false
profiler_tlv_disabled: false
listen_only: false
hostname_ssid: false
files_path: /var/www/html/profiler
debug: false
frequency: 0
ap_mode: true
fakeap: false
```

## Configuration options

### Channel and frequency

**channel**

- Type: Integer
- Default: 36
- Description: Wi-Fi channel to broadcast on

**frequency**

- Type: Integer
- Default: 0 (disabled)
- Description: Frequency in MHz (alternative to channel)

### Interface settings

**interface**

- Type: String
- Default: wlan0
- Description: Network interface to use for profiling

### SSID configuration

**ssid**

- Type: String
- Default: "Profiler xxx" (where xxx is last 3 chars of eth0 MAC)
- Description: SSID name to broadcast

**hostname_ssid**

- Type: Boolean
- Default: false
- Description: Use the system's hostname as the SSID

### Security settings

**passphrase**

- Type: String
- Default: profiler
- Requirements: 8-63 characters
- Description: WPA2/WPA3 passphrase for client authentication

#### Configuring the passphrase

**Option 1: Configuration file**

```ini
[GENERAL]
passphrase: MySecurePassword123
```

**Option 2: Command line**

```bash
sudo profiler --passphrase "MySecurePassword123"
```

**Requirements:**

- 8-63 characters (WPA2/WPA3 standard)
- Displayed in startup banner
- Available in the [info file](../MONITORING.md) for QR code generation

**security_mode**

- Type: String
- Default: ft-wpa3-mixed
- Options: wpa2, ft-wpa2, wpa3-mixed, ft-wpa3-mixed
- Description: Security and authentication mode

| Security mode | WPA2 | WPA3 | 802.11r (FT) | 802.11ax | 802.11be |
|--------------|------|------|--------------|----------|----------|
| wpa2 | Yes | No | No | Yes | Auto-disabled |
| ft-wpa2 | Yes | No | Yes | Yes | Auto-disabled |
| wpa3-mixed | Yes | Yes | No | Yes | Yes |
| ft-wpa3-mixed | Yes | Yes | Yes | Yes | Yes |

**IEEE 802.11be constraint:**

Wi-Fi 7 requires WPA3 or WPA3-transition mode per specification. When using WPA2-only modes, 802.11be is automatically disabled with a warning.

**Override for testing:**

Use `--11be` flag or `be_disabled: false` in config.ini to enable Wi-Fi 7 with WPA2-only modes (non-standard, for testing only).

**ft_disabled** (deprecated)

- Type: Boolean
- Default: false
- Description: Disable 802.11r Fast Transition
- Note: Use `security_mode` instead

### Wi-Fi standards

**he_disabled**

- Type: Boolean
- Default: false
- Description: Disable 802.11ax (Wi-Fi 6) High Efficiency reporting

**be_disabled**

- Type: Boolean
- Default: false
- Description: Disable 802.11be (Wi-Fi 7) Extremely High Throughput reporting

### Operating modes

**ap_mode**

- Type: Boolean
- Default: true
- Description: Use hostapd AP mode for faster client discovery

**fakeap**

- Type: Boolean
- Default: false
- Description: Use legacy FakeAP mode (Scapy-based, slower but more compatible)

**listen_only**

- Type: Boolean
- Default: false
- Description: Passive listening mode (no AP broadcast, Rx only)

### Output settings

**files_path**

- Type: String
- Default: /var/www/html/profiler
- Description: Directory where analysis results are saved

**profiler_tlv_disabled**

- Type: Boolean
- Default: false
- Description: Disable profiler-specific vendor IE

### Debug options

**debug**

- Type: Boolean
- Default: false
- Description: Enable verbose debug logging

**Environment variable:**

```bash
export PROFILER_DEBUG=1
```

Or:

```bash
export PROFILER_DEBUG=true
```

## Configuration priority

Settings are applied in the following priority (highest to lowest):

1. Command line arguments
2. Environment variables
3. Configuration file settings
4. Default values

## Example configurations

### Testing Wi-Fi 7 clients (default)

```bash
sudo profiler
# Uses ft-wpa3-mixed with all features enabled
```

### Testing WPA2-only clients

```bash
sudo profiler --security-mode wpa2
# Automatically disables 11r and 11be
```

### Testing legacy clients (no fast transition)

```bash
sudo profiler --security-mode wpa3-mixed
# WPA2/WPA3 transition without 11r
```

### Force Wi-Fi 7 with WPA2 (non-standard testing)

```bash
sudo profiler --security-mode wpa2 --11be
# Shows warning about IEEE spec violation
# Use only for testing edge cases
```

### Passive listening mode

```bash
sudo profiler --listen-only -c 100
# No AP broadcast, just listen on channel 100
```

## See also

- [Command line usage](CLI_USAGE.md)
- [Quick start guide](QUICKSTART.md)
- [Monitoring integration](../MONITORING.md)
- [FAQ](FAQ.md)
