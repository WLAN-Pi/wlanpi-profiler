# Frequently asked questions

Common questions and answers about profiler.

## General questions

### What is profiler?

Profiler is a Wi-Fi client capability analyzer that captures and analyzes 802.11 association request frames to determine what features a client device supports.

### Why do I need to use a password?

In AP mode, clients must complete WPA2/WPA3 authentication before sending association requests. This ensures we capture complete client capabilities. Without authentication, some clients send incomplete or malformed association requests.

### Will the client actually connect to the profiler?

In AP mode, the client will connect briefly, but the profiler doesn't provide internet access, so the connection will fail. This is expected behavior - we only need the association request, not a full connection.

In FakeAP mode, the client will not connect at all, but we still capture the association request.

### Can I use profiler on Windows or macOS?

For live capture, profiler requires Linux with a supported Wi-Fi adapter. However, you can analyze existing pcap files on any platform:

```bash
profiler --pcap capture.pcap
```

## Installation and setup

### What adapters are supported?

Tested adapters:

- mt76x2u
- mt7921u (a8000)
- mt7921e (rz608/mt7921k, rz616/mt7922m)
- iwlwifi (ax200, ax210, be200)

Other adapters may work but are not officially supported. rtl88XXau adapters have been removed from the recommended list.

### How do I upgrade profiler?

On WLAN Pi OS v3:

```bash
sudo apt update
sudo apt install wlanpi-profiler
```

For pipx installations, see [upgrading with pipx](../UPGRADING_WITH_PIPX.md).

### Where are results saved?

Results are saved to:

- `/var/www/html/profiler/` (default)
- Web interface: `http://<WLAN_Pi_IP>/profiler`
- Or your custom `--files_path` location

## Usage questions

### How do I change the channel?

```bash
sudo profiler -c 48
```

### How do I use a custom SSID?

```bash
sudo profiler -s "My SSID"
```

### How do I change the passphrase?

Edit `/etc/wlanpi-profiler/config.ini`:

```ini
[GENERAL]
passphrase: MyNewPassword
```

Or use the command line:

```bash
sudo profiler --passphrase "MyNewPassword"
```

### What is the default passphrase?

The default passphrase is `profiler` (changed from `wlanpi123` in v2.0.0).

### How do I enable debug logging?

```bash
sudo profiler --debug
```

Or set the environment variable:

```bash
export PROFILER_DEBUG=1
sudo profiler
```

## Troubleshooting

### The client won't connect

1. Make sure you're using the correct passphrase
2. Check that the client supports the security mode (WPA2/WPA3)
3. Try disabling 802.11r: `sudo profiler --security-mode wpa3-mixed`
4. Try disabling 802.11ax: `sudo profiler --no11ax`
5. Use debug mode to see more details: `sudo profiler --debug`

### No results are showing

1. Check that your adapter supports monitor mode
2. Verify the interface is correct: `sudo profiler --list_interfaces`
3. Try a different channel
4. Check debug output: `sudo profiler --debug`
5. Verify the service is running: `sudo service wlanpi-profiler status`

### Profiler is taking too long to discover clients

AP mode (default) should discover clients in 1-2 seconds. If it's taking longer:

1. Make sure you're using AP mode (default, not `--fakeap`)
2. Check that your adapter supports simultaneous AP + monitor mode
3. Try different channels
4. Ensure the client is actively scanning

### I get "interface not found" errors

1. Check available interfaces: `sudo profiler --list_interfaces`
2. Verify your adapter is plugged in
3. Check `iw dev` to see wireless interfaces
4. Try specifying the interface explicitly: `sudo profiler -i wlan1`

### The web interface shows old results

Refresh your browser. Results are written in real-time, but the browser may cache the page.

### Profiler fails to start

1. Check that you're running with sudo
2. Verify hostapd is installed: `which hostapd`
3. Check for conflicting services using the interface
4. Review logs: `journalctl -u wlanpi-profiler.service`
5. Try resetting the interface manually

## Capabilities and results

### Why doesn't the client show all its capabilities?

Clients typically only advertise capabilities that match the network they're connecting to. For example:

- A 3 spatial stream client may only report 2 streams when connecting to a 2-stream AP
- Wi-Fi 6E capabilities may not show if the AP doesn't advertise 6 GHz support
- 802.11r support may not appear if the AP doesn't advertise mobility domain

Profiler attempts to advertise the highest-level feature sets, but some clients are conservative in their capability reporting.

### Can I trust the 802.11k reporting?

Treat 802.11k capability reporting with caution. To verify:

- Check neighbor report requests in WLC/AP debug logs
- Analyze packet captures for action frames containing neighbor reports
- Test actual roaming behavior

### What does "capture_source" mean in the JSON output?

- **profiler_ap** - Live capture from profiler's own AP (controlled environment)
- **external** - Analysis of external pcap file (unknown environment)

See [JSON schema](../README.md#output-json-schema) for details.

### Why are some capabilities missing from the report?

Not all clients support all features. The profiler only reports what the client advertises in its association request. If a capability isn't listed, the client either:

- Doesn't support it
- Doesn't advertise it to this type of network
- Has it disabled in current configuration

## Configuration

### How do I make profiler start automatically?

Enable the systemd service:

```bash
sudo systemctl enable wlanpi-profiler
```

### Where is the configuration file?

Default location: `/etc/wlanpi-profiler/config.ini`

### Can I use environment variables?

Yes, for debug logging:

```bash
export PROFILER_DEBUG=1
```

### How do I disable Wi-Fi 7 advertising?

```bash
sudo profiler --no11be
```

Or in config.ini:

```ini
[GENERAL]
be_disabled = true
```

## Advanced questions

### How do I use FakeAP mode instead of AP mode?

```bash
sudo profiler --fakeap
```

Note: FakeAP mode is slower for client discovery but works with more adapters.

### Can I run profiler without root?

No, profiler requires elevated permissions to:

- Put interfaces in monitor mode
- Open raw sockets for frame injection
- Control hostapd

### How do I analyze a pcap file?

```bash
profiler --pcap capture.pcap
```

This _should_ work on any platform without special hardware and doesn't require root.

### Where can I find more technical details?

- [Capability logic](../CAPABILITY_LOGIC.md) - How capabilities are detected
- [Interface staging](../INTERFACE_STAGING.md) - How interfaces are prepared
- [Monitoring integration](../MONITORING.md) - Status files and external integration

## Getting more help

- Check the [known issues](../KNOWN_ISSUES.md)
- Review [troubleshooting in the quick start](QUICKSTART.md#troubleshooting)
- Create a GitHub issue for bugs
