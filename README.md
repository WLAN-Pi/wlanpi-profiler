[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md) ![versions](https://github.com/joshschmelzle/profiler2/blob/main/docs/images/profiler2-pybadge-w-logo.svg)

# profiler2

profiler2 is a Wi-Fi client capability analyzer built for the [WLAN Pi](https://github.com/WLAN-Pi/) platform.

it does two primary things:

- create a "fake" Access Point broadcasting a network name (SSID: default is `WLAN Pi`)
- analyzes association requests from Wi-Fi clients that attempt association to the fake AP

when the client attempts to connect, it will send an association frame. the purpose of this package is to automate the analysis and reporting of the client's 802.11 capabilities.

## why is this useful?

understanding client capabilities is a important part of the Wireless LAN (WLAN) design process. it helps the designer better optimize the design based on client capabilities.

## capabilities

capabilities across each client type may vary, depending on factors like client chipset, number of antennas, power mode (e.g iOS Low Power Mode), age of client, driver, etc.

each client includes its capability details in the 802.11 association frame sent from the client to an access point. by capturing this frame, it is possible to decode and report on the clients claimed capabilities.

please note that the client will match the capabilities advertised by an access point. for instance, a 3 spatial stream client will tell a 2 spatial stream AP that it only supports 2 spatial streams. the profiler attempts to address this issue by advertising the highest feature sets.  

## profiling (*WARNING* subject to change in future versions)

the client's capabilities are analyzed based on the client's association frame. the client will send an association frame when it attempts to associate to the profiler's fake AP. 

once profiled, a textual report prints in real-time to the screen, and results write to a directory on the WLAN Pi server. results include a copy of the report and also the association frame in PCAP format. 

note that further association requests by a profiled client are ignored until the profiler script/service is restarted.

## reports (*WARNING* subject to change in future versions)

report files are dumped in the following web directories for browsing:

- `http://<wlanpi_ip_address>/profiler/clients`
    - one directory per client MAC containing text report and PCAP
- `http://<wlanpi_ip_address>/profiler/reports`
    - contains a CSV report of all clients for each session

# installation

pre-reqs:

- minimum Python version required is 3.7 or higher
- `netstat`, `tcpdump`, and `airmon-ng` tools installed on host

installation with pip (recommended method): 

```
# get code
git clone <repo>
cd <repo>
sudo python3 -m pip install .
sudo profiler
```

running the profiler without pip install (development/optional):

- first make sure `scapy`, and `manuf` Py3 modules are installed (pip install method handles this)
- note that the package name is `profiler2` while the console script name is `profiler`

```
# get code
git clone <repo>
cd <repo>

sudo python3 -m profiler2 
sudo python3 -m profiler2 <optional params>
sudo python3 -m profiler2 -c 40 -s "Jerry Pi" -i wlan2 --no11r --logging debug
```

# usage

```
usage: profiler [-h] [-i INTERFACE] [-c CHANNEL]
                [-s SSID | --hostname_ssid] [--pcap <FILE>] [--noAP]
                [--11r | --no11r] [--11ax | --no11ax] [--noprep]
                [--config <FILE>] [--menu_file <FILE>]
                [--files_root <PATH>] [--clean] [--oui_update]
                [--logging [{debug,warning}]] [--version]

a Wi-Fi client analyzer for identifying supported 802.11 capabilities

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE          set network interface for profiler
  -c CHANNEL            802.11 channel to broadcast on
  -s SSID               set network identifier for profiler SSID
  --hostname_ssid       use the WLAN Pi's hostname for the SSID
  --pcap <FILE>         analyze first packet of pcap (expecting an association
                        request frame)
  --noAP                enable listen only mode (Rx only)
  --11r                 turn on 802.11r Fast Transition (FT) reporting
                        (override --config file)
  --no11r               turn off 802.11r Fast Transition (FT) reporting
  --11ax                turn on 802.11ax High Efficiency (HE) reporting
                        (override --config file)
  --no11ax              turn off 802.11ax High Efficiency (HE) reporting
  --noprep              disable interface preperation
  --config <FILE>       customize path for configuration file
  --menu_file <FILE>    customize menu report file location for WLAN Pi FPMS
  --files_root <PATH>   customize default root directory for reporting and
                        pcaps
  --clean               deletes CSV reports
  --oui_update          initiates Internet update of OUI database
  --logging [{debug,warning}]
                        change logging output
  --version, -V         show program's version number and exit
```

## examples

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

- Contributors (see AUTHORS.rst)
- Nigel Bowden and the WLAN Pi Community for all their input and effort on the first versions of the profiler
