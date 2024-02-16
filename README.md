![versions](docs/images/profiler-pybadge-w-logo.svg) ![coverage-badge](coverage.svg) [![packagecloud-badge](https://img.shields.io/badge/deb-packagecloud.io-844fec.svg)](https://packagecloud.io/)

# wlanpi-profiler

Profiler is a Wi-Fi client capability analyzer tool built for the [WLAN Pi](https://github.com/WLAN-Pi/).

The primary purpose is to automate the collection and analysis of association request frames.

It performs two primary functions:

1. advertises a "fake" Access Point
2. "profiles" any attempted client association requests (which contain the claimed capabilities of the client) 

## Why?

Understanding the various client capabilities found in a particular environment helps in the Wireless LAN definition, design, and troubleshooting/validation process.

The WLAN designer may desire to factor in the capabilities of expected clients in their design output. How many spatial streams? What is the client Tx power? What frequency bands does it support? 

The WLAN troubleshooter may understand better the issues they are uncovering when knowing the capabilities of the client. Does the client support .11k/r/v? Which PHYs does the client support? What channels does the client support?

The profiler helps to more quickly answer these questions for you.

## Client capabilities will vary

Capabilities across each client type will vary; depending on factors like client chipset, the number of antennas, power mode (e.g. iOS Low Power Mode), age of the client, driver, supplicant, etc.

Each client includes its capability details in the 802.11 association frame sent from the client to an access point. By capturing this frame, it is possible to decode and report on the client's claimed capabilities.

However, please note that the client will match the capabilities advertised by an access point. For instance, a 3 spatial stream client will tell a 2 spatial stream AP it only supports 2 spatial streams.

The profiler attempts to address this problem by advertising the highest-level feature sets.   

## Getting started with profiler on a WLAN Pi

The first step is to start the profiler, which will broadcast a fake AP. The client will send an association frame when attempting to connect to the fake AP. The capabilities of a client are then determined based on profiler analyzing the association frame. 

If running directly from a terminal, once profiled, a text report prints in real-time to the screen, and results write to a local directory on the WLAN Pi host. If running from FPMS, you should see a banner display for a few moments. 

Once we've profiled a client, profiler saves the results which consist of a text report and the association frame in PCAP format. Profiler also appends the result to a daily rotating `.csv` report.

1. Start the profiler:

    - Ensure a supported WLAN NIC is plugged into the WLAN Pi

    1. Starting the profiler service using the Front Panel Menu System (FPMS):
        - Navigate to `Menu` > `Apps` > `Profiler` > `Start`

    2. Starting the service manually:
        - `sudo service wlanpi-profiler start|stop|status`
        - Want to view more of the journal scrollback from `service wlanpi-profiler status` output?

            ```
            journalctl -u wlanpi-profiler.service
            ```

    3. Starting from the terminal:
        - `sudo profiler`


    - How to view CLI usage and man page from the shell:

        ```
        profiler -h
        man wlanpi-profiler
        ```

2. Profile the client:

    - once the profiler is started, the configured SSID will broadcast (default: "WLAN Pi")

    - connect a client and enter any random 8 characters for the PSK

    - note the client will expectedly fail authentication but we should receive the association request

3. Viewing the results:

    - You can look on the WebUI (http://<IPv4_of_WLANPi>/profiler) or on the filesystem at `/var/www/html/profiler`.

## Installation

profiler is included in the [WLAN Pi](https://github.com/WLAN-Pi/) image as a Debian package, but if you want to install it manually, here is what you need:

General requirements:

- adapter (and driver) which supports both monitor mode and packet injection
  - mt76x2u, mt7921u (a8000), mt7921e (rz608/mt7921k, rz616/mt7922m), and iwlwifi (ax200, ax210, be200) are tested regularly (everything else is experimental and not officially supported).
  - removed from the recommended list are rtl88XXau adapters (certain comfast adapters for example), but they should still work. with that said, don't open a bug report here for a rtl88XXau card.
- elevated permissions

Package requirements:

- Python version 3.9 or higher
- `iw`, `iproute2`, `pciutils`, `usbutils`, `kmod`, `wpa_cli`, and `wpasupplicant` tools installed on the host. most distributions already come with these.

### Upgrading WLAN Pi OS v3 (C4, M4, Pro) installs.

Got your hands on a WLAN Pi C4, M4, or Pro? We build and deploy a Debian package for `wlanpi-profiler` to our package archive. Get the latest version by running `sudo apt update` and `sudo apt install wlanpi-profiler`.

### Upgrading existing WLAN Pi OS v2 (NEO2) installs via pipx:

Are you reading this and have a NEO2 WLAN Pi? You can upgrade your existing profiler install, but there are some manual things you need to do first. Check out the [upgrading with pipx](UPGRADING_WITH_PIPX.md) instructions.

### Don't have a WLAN Pi? Installing via pipx:

Don't have a WLAN Pi? Have a Linux host handy? Try the [installing wlanpi-profiler using pipx](INSTALLING_WITH_PIPX.md) instructions.

# Usage from the CLI

You can start profiler directly from the command line like this:

```
sudo profiler
```

Stop with `CTRL + C`.

Usage:

```
$ profiler -h
usage: profiler [-h] [-c CHANNEL | -f FREQUENCY] [-i INTERFACE] [-s SSID] [--config FILE]
                [--files_path PATH] [--hostname_ssid] [--debug] [--logging [{debug,warning}]]
                [--noprep] [--noAP] [--no11r] [--no11ax] [--oui_update] [--read PCAP] 
                [--no_bpf_filters] [--list_interfaces] [--version]

options:
  -h, --help            show this help message and exit
  -c CHANNEL            set the channel to broadcast on
  -f FREQUENCY          set the frequency to broadcast on
  -i INTERFACE          set network interface for profiler
  -s SSID               set profiler SSID name
  --config FILE         customize path for configuration file 
                            (default: /etc/wlanpi-profiler/config.ini)
  --files_path PATH     customize default directory where analysis is saved on local system
                            (default: /var/www/html/profiler)
  --hostname_ssid       use the WLAN Pi's hostname as SSID name (default: False)
  --debug               enable debug logging output
  --logging [{debug,warning}]
                        change logging output
  --noprep              disable interface preperation (default: False)
  --noAP                enable Rx only mode (default: False)
  --no11r               turn off 802.11r Fast Transition (FT) reporting
  --no11ax              turn off 802.11ax High Efficiency (HE) reporting
  --oui_update          initiates update of OUI database (requires Internet connection)
  --read PCAP           read and analyze association request frames from pcap
  --no_bpf_filters      removes BPF filters from sniffer() but may impact profiler performance
  --list_interfaces     print out a list of interfaces with an 80211 stack
  --version, -V         show program's version number and exit
```

## Usage Examples

We require elevated permissions to put the interface in monitor mode and to open raw native sockets for frame injection. Starting and stopping profiler from the WLAN Pi's Front Panel Menu System (FPMS) will handle this for you automatically. 

Don't want to use the default channel? You can change it with the `-c` option:

```
# capture frames on channel 48 using the default SSID
sudo profiler -c 48
```

Want to use a custom SSID? You can use the `-s` option to specify your own SSID:

```
# capture frames on channel 36 using an SSID called 'JOIN ME'
sudo profiler -c 36 -s "JOIN ME"
```

Having problems profiling a client? We can disable .11r IE in fake AP beacon like this:

```
# capture frames on channel 100 with 802.11r disabled for clients that don't like 802.11r
sudo profiler -c 100 --no11r
```

Having problems profiling a client? We can disable .11ax IE in fake AP beacon like this:

```
# capture frames on the default channel with 802.11ax disabled for clients that don't like 802.11ax
sudo profiler --no11ax
```

Do you want to capture passively? We can do that! If we use `--noAP`, we will listen for any association request on a given channel.

```
# capture frames on channel 100 without the fake AP running (Rx only, no Tx)
sudo profiler --noAP -c 100
```

Already have some association requests in a pcap? We can analyze them. Use `--read <file.pcap>` to feed them into profiler:

```
# analyze an association request in a previously captured PCAP file
sudo profiler --read assoc_frame.pcap
```

Something not working? Use `--debug` to get more logs printed to the shell.

```
# increase output to screen for debugging
sudo profiler --debug
```

## Feature: overriding defaults with configuration file support

To change the default operation of the script (without passing in CLI args), on the WLAN Pi, a configuration file can be found at `/etc/wlanpi-profiler/config.ini`. 

This can be used as a way to modify settings loaded at runtime such as channel, SSID, and interface. 

## Feature: client capabilities diff

When a client is profiled, a hash of the capabilities is calculated and stored in memory. 

If subsequent association requests are seen from the same client, the previously calculated hash is compared to what is already in memory.

If the hash is the same, the additional association request is ignored. 

If the hash is different, capabilities are profiled and a text diff of the client report is saved.

## Feature: MAC OUI database update

A lookup feature is included to show the manufacturer of the client based on the 6-byte MAC OUI. this is a wrapper around a Python module called `manuf` which uses a local flat file for OUI lookup. 

If you find that some clients are not identified in the results, the flat file may need to be updated.

When the WLAN Pi has connectivity to the internet, this can be done from the CLI of the WLAN Pi:

```
sudo profiler --oui_update
```

## Notes and Warnings

- A client will generally only report the capabilities it has that match the network it associates to.
    - If you want the client to report all of its capabilities, it must associate with a network that supports those capabilities (e.g, a 3 spatial stream client will not report it supports 3 streams if the AP it associates with supports only 1 or 2 streams).
    - The fake AP created by the profiler attempts to simulate a fully-featured AP, but there may be cases where it does not behave as expected.
- Treat reporting of 802.11k capabilities with caution. To be sure verify through other means like:
    - Check neighbor report requests from a WLC/AP debug.
    - Gather and analyze a packet capture for action frames containing the neighbor report.
- While we try our best to make this as accurate as possible, we do not guarantee the accuracy of reporting. **Trust, but verify.**

# Thanks 

- Jerry Olla, Nigel Bowden, and the WLAN Pi Community for all their input and effort on the first versions of the profiler. Without them, this project would not exist.

# Contributing

Want to contribute? Thanks! Please take a few moments to [read this](CONTRIBUTING.md).

# Discussions and Issues

Please use GitHub discussions for dialogue around features and ideas that do not exist. Create issues for problems found running profiler.
