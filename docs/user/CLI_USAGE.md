# Command line usage

Complete reference for profiler command line options.

## Basic usage

```bash
sudo profiler
```

Stop with `CTRL + C`.

## Global options

```
usage: profiler [-h] [-c CHANNEL | -f FREQUENCY] [-i INTERFACE] [-s SSID] [--passphrase PASSPHRASE]
                [--config FILE] [--files_path PATH] [--hostname_ssid] [--debug] [--no-interface-prep]
                [--noAP] [--security-mode {wpa2,ft-wpa2,wpa3-mixed,ft-wpa3-mixed}] [--no11ax] [--11be | --no11be]
                [--noprofilertlv] [--wpa3_personal_transition | --wpa3_personal] [--oui_update] [--pcap PCAP]
                [--no_bpf_filters] [--list_interfaces] [--ap-mode | --fakeap] [--version]

wlanpi-profiler is an 802.11 client capabilities profiler. If installed via apt package manager, read the manual with: man wlanpi-profiler

optional arguments:
  -h, --help            show this help message and exit
  -c CHANNEL            set the channel to broadcast on
  -f FREQUENCY          set the frequency to broadcast on
  -i INTERFACE          set network interface for profiler
  -s SSID               set profiler SSID name
  --config FILE         customize path for configuration file (default: /etc/wlanpi-profiler/config.ini)
  --files_path PATH     customize default directory where analysis is saved on local system (default: /var/www/html/profiler)
  --hostname_ssid       use the WLAN Pi's hostname as SSID name (default: False)
  --debug               enable debug logging output
  --no-interface-prep, --noprep
                        disable interface preparation (profiler will not configure interface to monitor mode)
  --noAP                enable Rx only mode (default: False)
  --no11ax              turn off 802.11ax High Efficiency (HE) reporting
  --no11be              turn off 802.11be Extremely High Throughput (EHT) reporting
  --noprofilertlv       disable generation of Profiler specific vendor IE
  --wpa3_personal_transition
                        enable WPA3 Personal Transition in the RSNE for 2.4 / 5 GHz
  --wpa3_personal       enable WPA3 Personal only in the RSNE for 2.4 / 5 GHz
  --oui_update          initiates update of OUI database (requires Internet connection)
  --read PCAP           read and analyze association request frames from pcap
  --no_bpf_filters      removes BPF filters from sniffer() but may impact profiler performance
  --list_interfaces     print out a list of interfaces with an 80211 stack
  --version, -V         show program's version number and exit
```

## Usage examples

### Cross-platform pcap analysis (Windows/macOS/Linux)

Analyze any `.pcap` file without special hardware or permissions:

```bash
# Analyze a pcap file on Windows, macOS, or Linux
profiler --pcap capture.pcap

# Specify custom output directory
profiler --pcap capture.pcap --files_path ./analysis-results
```

**Output:** Creates JSON, text reports, and filtered pcaps in `~/.local/share/wlanpi-profiler/clients/<MAC>/` (or specified path or platform appropriate path for applications automatically detected)

### Live capture (WLAN Pi / Linux only)

We require elevated permissions to put the interface in monitor mode and to open raw native sockets for frame injection. Starting and stopping profiler from the WLAN Pi's front panel menu system (FPMS) will handle this for you automatically.

#### Change the channel

Don't want to use the default channel? Use the `-c` option:

```bash
# Capture frames on channel 48 using the default SSID
sudo profiler -c 48
```

#### Custom SSID

Want to use a custom SSID? Use the `-s` option:

```bash
# Capture frames on channel 36 using an SSID called 'JOIN ME'
sudo profiler -c 36 -s "JOIN ME"
```

#### Disable 802.11r for problematic clients

Having problems profiling a client? Disable .11r IE in fake AP beacon:

```bash
# Capture frames on channel 100 with 802.11r disabled
sudo profiler -c 100 --security-mode wpa3-mixed
```

#### Disable 802.11ax for legacy clients

Having problems profiling a client? Disable .11ax IE in fake AP beacon:

```bash
# Capture frames on the default channel with 802.11ax disabled
sudo profiler --no11ax
```

#### Passive listening mode

Want to capture passively? Use `--listen-only` (or `--noAP`):

```bash
# Capture frames on channel 100 without the fake AP running (Rx only, no Tx)
sudo profiler --listen-only -c 100
```

#### Analyze existing pcap

Already have association requests in a pcap? Analyze them with `--pcap`:

```bash
# Analyze an association request in a previously captured PCAP file
sudo profiler --pcap assoc_frame.pcap
```

#### Debug mode

Something not working? Use `--debug` to get more logs:

```bash
# Increase output to screen for debugging
sudo profiler --debug
```

#### List available interfaces

See what wireless interfaces are available:

```bash
sudo profiler --list_interfaces
```

#### Update OUI database

Update the MAC OUI database (requires internet):

```bash
sudo profiler --oui_update
```

## Common use cases

### Testing Wi-Fi 7 clients (default)

```bash
sudo profiler
# Uses ft-wpa3-mixed with all features enabled (11r, 11ax, 11be)
```

### Testing WPA2-only clients

```bash
sudo profiler --security-mode wpa2
# Automatically disables 11r and 11be
# Shows warning about 11be being auto-disabled
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

### Legacy FakeAP mode

```bash
sudo profiler --fakeap --interface wlan0 --channel 36
# Use legacy scapy-based mode instead of hostapd
```

## See also

- [Configuration guide](CONFIGURATION.md)
- [Quick start guide](QUICKSTART.md)
- [Monitoring integration](../MONITORING.md)
- [FAQ](FAQ.md)
