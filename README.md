![versions](docs/images/profiler-pybadge-w-logo.svg) ![tests](https://github.com/wlan-pi/profiler/workflows/tests/badge.svg) ![coverage-badge](coverage.svg) [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)

# wlanpi-profiler

Profiler is a Wi-Fi client capability analyzer tool built for the [WLAN Pi](https://github.com/WLAN-Pi/).

The primary purpose is to automate the collection and analysis of association request frames.

It performs two primary functions:

1. advertises a "fake" Access Point
2. "profiles" any attempted client association requests (which contain the client's claimed capabilities) 

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

## Getting started

Start the profiler. It will broadcast a fake AP.

When the client attempts association to the profilers fake AP, it will send an association frame. 

The capabilities of a client are determined based on the tool analyzing the association frame. 

If running directly from a terminal, once profiled, a text report prints in real-time to the screen, and results write to a local directory on the WLAN Pi host. 

Saved results include a copy of the text report and the association frame in PCAP format, and the result is appended to a rotating `.csv` report.

1. Start the profiler:

    - Ensure a supported WLAN NIC is plugged into the WLAN Pi

    1. Starting the profiler service using the Front Panel Menu System (FPMS):
        - Navigate to `Menu` > `Apps` > `Profiler` > `Start`

    2. Starting the service manually:
        - `sudo service wlanpi-profiler start|stop|status`
    3. Starting from the terminal:
        - `sudo profiler`

2. Profile the client:

    - once the profiler is started, the configured SSID will broadcast (default: "WLAN Pi")

    - connect a client and enter any random 8 characters for the PSK

    - note the client will expectedly fail authentication but we should receive the association request

3. Viewing the results:

    - You can look on the WebUI (http://<IPv4_of_WLANPi>/profiler) or on the filesystem at `/var/www/html/profiler`.

## Installation

profiler is included in the [WLAN Pi](https://github.com/WLAN-Pi/) image, but if you want to install it manually, here is what you need.

General requirements:

- adapter (and driver) which supports both monitor mode and packet injection
  - mt76x2u (recommended) and rtl88XXau adapters are tested regularly (everything else is experimental and not officially supported)
- elevated permissions

Package requirements:

- Python version 3.7 or higher
- `iw`, `netstat`, and `tcpdump` tools installed on the host

### Manual installation example with pipx (this will change to debian packaging in the near future)

```
sudo -i

# install depends
apt-get install python3 python3-pip python3-venv git iw netstat tcpdump

# install pipx
python3 -m pip install pipx
python3 -m pipx ensurepath

# install profiler from github
pipx install git+https://github.com/WLAN-Pi/profiler.git

# set reg domain (some adapters/drivers require this in order to Tx in 5 GHz bands)
iw reg set US
```

And starting profiler looks like this:

```
sudo profiler
```

Stop with `CTRL + C`.

# Usage

```
usage: profiler [-h] [-c CHANNEL] [-i INTERFACE] [-s SSID]
                [--config FILE] [--files_path PATH] [--hostname_ssid]
                [--logging [{debug,warning}]] [--noprep] [--noAP] [--no11r]
                [--no11ax] [--oui_update] [--read PCAP] [--version]

wlanpi-profiler is an 802.11 client capabilities profiler. Read the manual with: man wlanpi-profiler

optional arguments:
  -h, --help            show this help message and exit
  -c CHANNEL            set the operating channel to broadcast on
  -i INTERFACE          set network interface for profiler
  -s SSID               set profiler SSID name
  --config FILE         customize path for configuration file (default: /etc/wlanpi-profiler/config.ini)
  --files_path PATH     customize default directory where analysis is saved on local system (default: /var/www/html/profiler)
  --hostname_ssid       use the WLAN Pi's hostname as SSID name (default: False)
  --logging [{debug,warning}]
                        change logging output
  --noprep              disable interface preperation (default: False)
  --noAP                enable Rx only mode (default: False)
  --no11r               turn off 802.11r Fast Transition (FT) reporting
  --no11ax              turn off 802.11ax High Efficiency (HE) reporting
  --oui_update          initiates update of OUI database (requires Internet connection)
  --read PCAP           read and analyze association request frames from pcap
  --version, -V         show program's version number and exit
```

## Usage Examples

We require elevated permissions to put the interface in monitor mode and to open raw native sockets for frame injection. Starting and stopping profiler from the WLAN Pi's Front Panel Menu System (FPMS) will handle this for you automatically. 

```
# capture frames on channel 48 using the default SSID
sudo profiler -c 48
```

```
# capture frames on channel 36 using an SSID called 'JOIN ME'
sudo profiler -c 36 -s "JOIN ME"
```

```
# capture frames on channel 100 with 802.11r disabled for clients that don't like 802.11r
sudo profiler -c 100 --no11r
```

```
# capture frames on the default channel with 802.11ax disabled for clients that don't like 802.11ax
sudo profiler --no11ax
```

```
# capture frames on channel 100 without the fake AP running (Rx only, no Tx)
sudo profiler --noAP -c 100
```

```
# analyze an association request in a previously captured PCAP file (must be the only frame in the file)
sudo profiler --read assoc_frame.pcap
```

```
# increase output to screen for debugging
sudo profiler --logging debug
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