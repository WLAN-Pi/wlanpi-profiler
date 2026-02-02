# Quick start guide

Get up and running with profiler in minutes.

## Prerequisites

- WLAN Pi device with supported Wi-Fi adapter
- Elevated permissions (sudo access)

## Start the profiler

### Option 1: Using the front panel menu system (FPMS)

1. Navigate to: Menu > Apps > Profiler > Start

2. The profiler service will start broadcasting

### Option 2: Using the system service

```bash
sudo service wlanpi-profiler start
```

Check status:

```bash
sudo service wlanpi-profiler status
```

View full logs:

```bash
journalctl -u wlanpi-profiler.service
```

### Option 3: From the terminal

```bash
sudo profiler
```

Stop with `CTRL + C`.

## Profile a client

Once the profiler is started:

1. Look for the SSID broadcasting (default: "Profiler xxx" where xxx is the last 3 characters of the eth0 MAC address)

2. Connect your client using the passphrase:

   - Default passphrase: `profiler`
   - [How to customize the passphrase](CONFIGURATION.md#configuring-the-passphrase)

3. The client will attempt to connect and the profiler will capture the association request

### Why a password is required

In AP mode, clients must complete WPA2/WPA3 authentication before sending association requests. This ensures we capture complete client capabilities. Without authentication, some clients send incomplete or malformed association requests.

**Note:** The client will fail to fully connect (this is expected), but the profiler will still capture the association request containing the capability information.

## View results

Results are available in multiple locations:

### Web interface

Visit: `http://<WLAN_Pi_IP>/profiler`

### File system

Results are saved to: `/var/www/html/profiler/`

Each profiled client gets:

- Text report with capability analysis
- PCAP file containing the association frame
- Entry in daily rotating CSV report

### Real-time output

When running from the terminal, a text report prints to the screen immediately upon successful profile capture.

## Next steps

- [Configuration options](CONFIGURATION.md)
- [Command line usage](CLI_USAGE.md)
- [Understanding the output](../CAPABILITY_LOGIC.md)
- [Monitoring integration](../MONITORING.md)

## Troubleshooting

If you encounter issues:

1. Check the [FAQ](FAQ.md)
2. Run with debug logging: `sudo profiler --debug`
3. Verify your adapter is supported (see [README](../README.md))
4. Check the [known issues](../KNOWN_ISSUES.md)
