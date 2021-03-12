![versions](docs/images/profiler2-pybadge-w-logo.svg) ![tests](https://github.com/joshschmelzle/profiler2/workflows/tests/badge.svg) ![coverage-badge](coverage.svg) [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)

# wlanpi-profiler

wlanpi-profiler is a Wi-Fi client capability analyzer tool built for the [WLAN Pi](https://github.com/WLAN-Pi/).

The primary purpose is to automate the collection and analysis of association request frames.

It performs two primary functions:

1. advertises a "fake" Access Point
2. "profiles" any attempted client association requests (which contain the client's claimed capabilities) 

## why?

Understanding the various client capabilities found in a particular environment is helps the Wireless LAN design and troubleshooting process.

The WLAN designer may desire to factor the capabilities of expected clients in their design output.

The WLAN troubleshooter may understand better issues they are uncovering when knowing the capabilities of the client.

## this matters because capabilities vary

Capabilities across each client type may vary; depending on factors like client chipset, the number of antennas, power mode (e.g. iOS Low Power Mode), age of the client, driver, supplicant, etc.

Each client includes its capability details in the 802.11 association frame sent from the client to an access point. By capturing this frame, it is possible to decode and report on the client's claimed capabilities.

However, please note that the client will match the capabilities advertised by an access point. For instance, a 3 spatial stream client will tell a 2 spatial stream AP it only supports 2 spatial streams.

The profiler attempts to address this problem by advertising the highest-level feature sets.   

## how to get started?

When the client attempts association to the profilers fake AP, it will send an association frame. 

The capabilities of a client are determined based on the tool analyzing the association frame. 

If running directly from a terminal, once profiled, a text report prints in real-time to the screen and results write to a local directory on the WLAN Pi host. 

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

    - once profiler is started, the configured SSID will broadcast (default: "WLAN Pi")

    - connect a client and enter any random 8 characters for the PSK

    - note the client will expectedly fail authentication but we should receive the association request

3. Viewing the results:

    - You can look on the WebUI (http://<IPv4_of_WLANPi>/profiler) or on the filesystem at `/var/www/html/profiler`.

## installation

profiler is already included in the [WLAN Pi](https://github.com/WLAN-Pi/) image, but if you want to install it yourself, here is what you need.

General requirements:

- adapter (and driver) which supports both monitor mode and packet injection
  - mt76x2u (recommended) and rtl88XXau are tested regularly (everything else is experimental and not officially supported)
- elevated permissions

Package requirements:

- Python version 3.7 or higher
- `iw`, `netstat`, and `tcpdump` tools installed on the host

### manual installation example with pipx (this will change in the near future)

```
sudo -i

# install depends
apt-get install python3 python3-pip python3-venv git iw netstat tcpdump

# install pipx
python3 -m pip install pipx
python3 -m pipx ensurepath

# install profiler from github
pipx install git+https://github.com/WLAN-Pi/profiler2.git

# set reg domain (some adapters/drivers require this in order to Tx in 5 GHz bands)
iw reg set US
```

And run the profiler2 console script like this:

```
sudo profiler
```

# usage

Elevated permissions are required to prep the interface in monitor mode and for scapy to open a raw native socket for frame injection. You must run profiler with elevated permissions e.g. `sudo profiler`. Launching profiler from the WLAN Pi FPMS will handle this for you.

```
usage: profiler [-h] [-i INTERFACE] [--noprep] [-c CHANNEL]
                [-s SSID | --hostname_ssid | --noAP] [--11r | --no11r]
                [--11ax | --no11ax] [--read <FILE>] [--config <FILE>]
                [--files_path <PATH>] [--oui_update]
                [--logging [{debug,warning}]] [--version]

a Wi-Fi client analyzer for identifying supported 802.11 capabilities

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE          set network interface for profiler (default: None)                                                                     
  --noprep              disable interface preperation (default: False)
  -c CHANNEL            802.11 channel to broadcast on
  -s SSID               set profiler SSID
  --hostname_ssid       use the WLAN Pi's hostname as SSID name
  --noAP                enable listen only mode (Rx only)
  --11r                 turn on 802.11r Fast Transition (FT) reporting (override --config file)
  --no11r               turn off 802.11r Fast Transition (FT) reporting
  --11ax                turn on 802.11ax High Efficiency (HE) reporting (override --config file)
  --no11ax              turn off 802.11ax High Efficiency (HE) reporting   
  --read <FILE>         analyze first packet of pcap (expecting an association request frame)
  --config <FILE>       customize path for configuration file (default: /etc/wlanpi-profiler/config.ini)
  --files_path <PATH>   customize default directory where analysis is saved on local system (default: /var/www/html/profiler)
  --oui_update          initiates Internet update of OUI database
  --logging [{debug,warning}]
                        change logging output
  --version, -V         show program's version number and exit
```

## usage examples

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

## feature: overriding defaults with configuration file support

To change the default operation of the script (without passing in CLI args), on the WLAN Pi, a configuration file can be found at `/etc/wlanpi-profiler/config.ini`. 

This can be used as a way to modify settings loaded at runtime such as channel, SSID, and interface. 

## feature: client capabilities diff

When a client is profiled, a hash of the capabilities is calculated and stored in memory. 

If subsequent association requests are seen from the same client, the previously calculated hash is compared to what is already in memory.

If the hash is the same, the additional association request is ignored. 

If the hash is different, capabilities are profiled and a text diff of the client report is saved.

## feature: MAC OUI database update

A lookup feature is included to show the manufacturer of the client based on the 6-byte MAC OUI. this is a wrapper around a Python module called `manuf` which uses a local flat file for OUI lookup. 

If you find that some clients are not identified in the results, the flat file may need to be updated.

When the WLAN Pi has connectivity to the internet, this can be done from the CLI of the WLAN Pi:

```
sudo profiler --oui_update
```

## caveats and warnings

- A client will generally only report the capabilities it has that match the network it associates to.
    - If you want the client to report all of its capabilities, it must associate with a network that supports those capabilities (e.g, a 3 spatial stream client will not report it supports 3 streams if the AP it associates with supports only 1 or 2 streams).
    - The profiler fake AP attempts to simulate a fully-featured AP, but there may be cases where it does not behave as expected.
- Treat reporting of 802.11k capabilities with caution. to be sure, verify through other means like:
    - Check neighbor report requests from a WLC/AP debug.
    - Gather and analyze a packet capture for action frames containing the neighbor report.
- While we try our best to make this as accurate as possible, we do not guarantee the accuracy of reporting. **Trust, but verify.**

# thanks!

- Jerry Olla, Nigel Bowden, and the WLAN Pi Community for all their input and effort on the first versions of the profiler. Without them, this project would not exist.

## contributing

Want to contribute? Thanks! Please take a few moments to [read this](CONTRIBUTING.md).
