![versions](docs/images/profiler2-pybadge-w-logo.svg) ![tests](https://github.com/joshschmelzle/profiler2/workflows/tests/badge.svg) ![coverage-badge](coverage.svg) [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)

# profiler2

profiler2 is a Wi-Fi client capability analyzer built for the [WLAN Pi](https://github.com/WLAN-Pi/).

it performs two primary functions:

1. creates a "fake" Access Point (default SSID is `WLAN Pi`)
2. analyze attempted client association requests 

the association request is a Layer 2 frame containing reported capabilities of the Wi-Fi client. profiler automates collection and analysis of these capabilities.

## why?

understanding client capabilities is an important part of the Wireless LAN design process. the designer can optimize their design output based on capabilities of expected clients. 

## capabilities vary

capabilities across each client type may vary; depending on factors like client chipset, number of antennas, power mode (e.g iOS Low Power Mode), age of client, driver, etc.

each client includes its capability details in the 802.11 association frame sent from the client to an access point. by capturing this frame, it is possible to decode and report on the clients claimed capabilities.

please note that the client will match the capabilities advertised by an access point. for instance, a 3 spatial stream client will tell a 2 spatial stream AP that it only supports 2 spatial streams. the profiler attempts to address this issue by advertising the highest feature sets.  

## profiling results (*WARNING* subject to change in future versions)

the client's capabilities are analyzed based on the client's association frame. the client will send an association frame when it attempts to associate to the profiler's fake AP. 

once profiled, a textual report prints in real-time to the screen, and results write to a directory on the WLAN Pi server. results include a copy of the report and also the association frame in PCAP format. 

when profiled, a hash of the capabilities is calculated. if a subsequent association requests is seen, the hash is compared to what is in memory. if the hash is the same, it is ignored. if the hash is different, the request is profiled.

## viewing reports (*WARNING* subject to change in future versions)

report files are can be viewed and downloaded from the WebUI of the WLAN PI by browsing to `http://<wlanpi_ip_address>/profiler`.

# installation

requirements:

- minimum Python version required is 3.7 or higher
- `netstat`, and `tcpdump` tools installed on host
- adapter + driver that supports both monitor mode and packet injection

installation with pip (recommended): 

```
# get code:
git clone <repo>

# install package
cd <repo dir>
sudo python3 -m pip install .

# run the console script like:
sudo profiler
```

### running the profiler without pip install (development/optional):

- first make sure `scapy`, and `manuf` py3 modules are installed (`cd <repo> && python3 -m pip install -r requirements.txt`)

```
# get code
git clone <repo>
cd <repo>

sudo python3 -m profiler2 
sudo python3 -m profiler2 <optional params>
sudo python3 -m profiler2 -c 40 -s "Jerry Pi" -i wlan2 --no11r --logging debug
```

- note that the development method requires you to use the package name `profiler2` to launch profiler, rather than `profiler` when installed. this is because `profiler` is the console_scripts entry point while the package name is `profiler2`.

# usage

```
usage: profiler [-h] [-i INTERFACE] [--noprep] [-c CHANNEL]
                [-s SSID | --hostname_ssid | --noAP] [--11r | --no11r]
                [--11ax | --no11ax] [--pcap <FILE>] [--config <FILE>]
                [--files_path <PATH>] [--clean] [--yes] [--oui_update]
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
  --11r                 turn on 802.11r Fast Transition (FT) reporting
                        (override --config file)
  --no11r               turn off 802.11r Fast Transition (FT) reporting
  --11ax                turn on 802.11ax High Efficiency (HE) reporting
                        (override --config file)
  --no11ax              turn off 802.11ax High Efficiency (HE) reporting
  --pcap <FILE>         analyze first packet of pcap (expecting an association
                        request frame)
  --config <FILE>       customize path for configuration file (default:
                        /etc/profiler2/config.ini)
  --files_path <PATH>   customize default directory where analysis is saved on
                        local system (default: /var/www/html/profiler)
  --clean               deletes CSV reports
  --yes                 automatic yes to prompts
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
# analyze an association request in a previously captured PCAP file (must be only frame in file)
sudo profiler --pcap assoc_frame.pcap
```

```
# increase screen output for debugging
sudo profiler --logging debug
```

## MAC OUI database update

A lookup feature is included to show the manufacturer of the client based on the 6-byte MAC OUI. This is enabled by a wrapper around a Python module called `manuf`. 

`manuf` uses a local flat file for OUI lookup. If you find that some clients are not identified in the results, the OUI file may need to be updated.

With connectivity to the Internet, this can be done from the CLI of the WLAN Pi:

```
sudo profiler --oui_update
```

## configuration

to change the default operation of the script (without passing in CLI args), a configuration file called `config.ini` can be found in the script directory. this can be used as a way to modify the channel, SSID, and interface used by the script. note that the profiler must be restarted to use updated values from the config file. 

## caveats

- a client will generally only report the capabilities it has that match the network it associates to.
    - if you want the client to report all of its capabilities, it must associate with a network that supports those capabilities (e.g, a 3 spatial stream client will not report it supports 3 streams if the AP it associates with supports only 1 or 2 streams).
    - the profiler fake AP attempts to simulate a fully featured AP, but there may be cases where it does not behave as expected.
- treat reporting of 802.11k capabilities with caution. to be sure, verify through other means like:
    - check neighbor report requests from a WLC/AP debug.
    - gather and analyze a packet capture for action frames containing neighbor report.
- while we try our best to make this as accurate as possible, we do not guarantee this reports accurate info. trust, but verify.

## thanks

- Nigel Bowden and the WLAN Pi Community for all their input and effort on the first versions of the profiler.

## contributing

Want to contribute? Thanks! Please take a few moments to [read this](CONTRIBUTING.md).
