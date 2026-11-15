# Command line usage

Complete reference for profiler command line options.

## Basic usage

```bash
sudo profiler
```

Stop with `CTRL + C`.

## Shell tab-completion

The Debian package installs bash tab-completion for `profiler` to
`/usr/share/bash-completion/completions/profiler` (requires the
`bash-completion` package, which is a `Recommends` dependency). Open a new
shell and `profiler --<TAB>` will complete flags, `-i <TAB>` will complete
local interface names, and file-based options (`--config`, `--pcap`,
`--files_path`, `--hostapd-config`) complete paths.

If you installed `profiler` another way (e.g. `pipx`, a virtualenv) and want
completion, register it manually for your shell:

```bash
eval "$(register-python-argcomplete profiler)"   # bash
```

Add that line to your shell rc file (`~/.bashrc`) to make it persistent. See
the [argcomplete docs](https://kislyuk.github.io/argcomplete/) for zsh/fish/tcsh.

## Global options

```
usage: profiler [-h] [-c CHANNEL | -f FREQUENCY] [-i INTERFACE] [-s SSID] [--passphrase PASSPHRASE] [--config FILE]
                [--files_path PATH] [--hostname_ssid] [--debug] [--expert] [--no-interface-prep] [--listen-only]
                [--security-mode {wpa2,ft-wpa2,wpa3-mixed,ft-wpa3-mixed}] [--no11ax] [--11be | --no11be]
                [--noprofilertlv] [--oui_update] [--pcap PCAP] [--no_bpf_filters] [--list-interfaces] [--ap-mode |
                --fakeap] [--version]
                {test} ...

wlanpi-profiler is an 802.11 client capabilities profiler. If installed via package manager, read the manual with: man wlanpi-profiler

positional arguments:
  {test}                available commands
    test                run on-device hardware tests

options:
  -h, --help            show this help message and exit
  -c CHANNEL            set the channel to broadcast on
  -f FREQUENCY          set the frequency to broadcast on
  -i INTERFACE          set network interface for profiler
  -s SSID               set profiler SSID name
  --passphrase PASSPHRASE
                        set AP passphrase (8-63 chars, default: profiler)
  --config FILE         customize path for configuration file (default: /etc/wlanpi-profiler/config.ini)
  --files_path PATH     customize directories where analysis is saved (can be specified multiple times, default:
                        /var/www/html/profiler and /root/.local/share/wlanpi-profiler)
  --hostname_ssid       use the WLAN Pi's hostname as SSID name (default: False)
  --debug               enable debug logging output
  --expert              enable expert mode (includes hostapd debug output)
  --no-interface-prep, --noprep
                        disable interface preparation (profiler will not configure interface to monitor mode)
  --listen-only, --noAP
                        listen-only mode (passive Rx, no AP)
  --security-mode {wpa2,ft-wpa2,wpa3-mixed,ft-wpa3-mixed}
                        security mode for AP: wpa2, ft-wpa2, wpa3-mixed, ft-wpa3-mixed (default: ft-wpa3-mixed). Note:
                        802.11be auto-disabled for wpa2/ft-wpa2 (Wi-Fi 7 requires WPA3)
  --no11ax              turn off 802.11ax High Efficiency (HE) reporting
  --11be                enable 802.11be Extremely High Throughput (Wi-Fi 7) reporting (override auto-disable for WPA2
                        modes)
  --no11be              turn off 802.11be Extremely High Throughput (EHT) reporting
  --noprofilertlv       disable generation of Profiler specific vendor IE
  --oui_update          initiates update of OUI database (requires Internet connection)
  --pcap PCAP           analyze association request frames from pcap
  --no_bpf_filters      removes BPF filters from sniffer() but may impact profiler performance
  --list-interfaces, --list_interfaces
                        print out a list of interfaces with an 80211 stack
  --ap-mode             use hostapd AP mode for fast discovery (default behavior, requires monitor VIF support)
  --fakeap              use legacy FakeAP mode (Scapy/monitor-only, slower discovery but works with more adapters)
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
profiler --list-interfaces
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
sudo profiler --fakeap -i wlan0 -c 36
# Use legacy scapy-based mode instead of hostapd
```

Not available on Qualcomm ath12k radios (WCN785x): the driver drops injected frames, so the profiler refuses `--fakeap` there.

## See also

- [Configuration guide](CONFIGURATION.md)
- [Quick start guide](QUICKSTART.md)
- [Monitoring integration](../MONITORING.md)
- [FAQ](FAQ.md)
