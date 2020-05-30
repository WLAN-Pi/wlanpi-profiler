[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md) ![versions](https://github.com/joshschmelzle/profiler2/blob/master/docs/images/profiler2-pybadge-w-logo.svg)

# profiler2

profiler2 is a Wi-Fi client capability analyzer for the WLAN Pi platform.

it does two primary things:

- create a "fake" Access Point broadcasting a network name (SSID: default is `WLAN Pi`)
- analyzes association requests from Wi-Fi clients that attempt association to the fake AP

when the client attempts to connect, it will send an association frame which is used to analyze the client's 802.11 capabilities.

## why is this useful?

understanding client capabilities is a important part of the Wireless LAN (WLAN) design process. it helps the designer better optimize the design based on client capabilities.

## capabilities

capabilities across each client type may vary, depending on factors like client chipset, number of antennas, power mode (e.g iOS Low Power Mode), age of client, etc.

each client includes capability details in an 802.11 association frame sent to an access point. by capturing this frame, it is possible to decode and then report on the clients capabilities. 

one big caveat here is that the client will match the capabilities advertised by an access point. for instance, a 3 spatial stream client will tell a 2 spatial stream AP that it only supports 2 spatial streams. the profiler attempts to address this issue by advertising the highest feature sets.  

## profiling (*WARNING* some of the details are likely to change in future versions)

the capabilities are analyzed from the association frame sent from the client when it attempts to associate to the profiler's fake AP.

once profiled, a textual report prints in real-time to the screen, and results write to a directory on the WLAN Pi server. results include a copy of the report and also the association frame in PCAP format. 

note that further association requests by a profiled client are ignored until the profiler is restarted.

## reports (*WARNING* some of the details are likely to change in future versions)

report files are dumped in the following web directories for browsing:

- `http://<wlanpi_ip_address>/profiler/clients`
    - one directory per client MAC containing text report and PCAP
- `http://<wlanpi_ip_address>/profiler/reports`
    - contains a CSV report of all clients for each session

# installation

pre-reqs:

- minimum Python version required is 3.7 or higher
- `netstat`, `tcpdump`, and `airmon-ng` tools installed

pip install method (recommended): 

```
# get code
git clone <repo>
cd <repo>
sudo python3 -m pip install .
sudo profiler
```

run profiler without pip install (optional/for development):

- first make sure `scapy`, and `manuf-ng` Py3 modules are installed (pip install method handles this for you)

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
usage: profiler [-h] [-i INTERFACE] [-c CHANNEL] [-s SSID | --host_ssid]
                [--file <FILE>] [--config <FILE>] [--noAP] [--no11ax]
                [--no11r] [--menu_mode] [--menu_file <FILE>]
                [--files_root <PATH>] [--clean] [--oui_update]
                [--logging [{debug,warning}]] [--version]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE          set network interface for profiler
  -c CHANNEL            802.11 channel to broadcast on
  -s SSID               set network identifier for profiler SSID
  --host_ssid           use the WLAN Pi's hostname as profiler SSID
  --file <FILE>         read in first packet of pcap (expecting an association
                        request frame)
  --config <FILE>       specify path for configuration file
  --noAP                enable listen only mode (Rx only)
  --no11ax              turn off 802.11ax High Efficiency (HE) reporting
  --no11r               turn off 802.11r Fast Transition (FT) reporting
  --menu_mode           enable WLAN Pi FPMS menu reporting
  --menu_file <FILE>    change menu report file location for WLAN Pi FPMS
  --files_root <PATH>   default root directory for reporting and pcaps
  --clean               cleans out the old CSV reports
  --oui_update          initiates Internet update of OUI database
  --logging [{debug,warning}]
                        increase output for debugging
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
sudo profiler --file assoc_frame.pcap
```

```
# debugging
sudo profiler --logging debug
```

## MAC OUI database update

MAC OUI lookup is included in the reports to show the manufacturer of the client based on the 6-byte MAC OUI. This feature is provided by a Python module called "manuf-ng". It uses a local MAC OUI database file to lookup the OUI.

If you find that some clients are not being profiled with a manufacturer, the OUI file may need to be updated. This can be done from the CLI of the WLAN Pi:

```
sudo profiler --oui_update
```

## configuration

to change the default operation of the script, a configuration file called `config.ini` can be found in the script directory. this can be used as a way to modify the channel, SSID, and interface used by the script. to leverage any configuration file changes the profiler must be restarted.  

## caveats

- we try our best to make this as accurate as possible, however this project is maintained by unpaid volunteers. this is not guaranteed to report accurate info.
- a client will generally only report the capabilities it has that match the network it associates to.
    - if you want the client to report all of its capabilities, it must associate with a network that supports those capabilities (e.g, a 3 spatial stream client will not report it supports 3 streams if the AP it associates with supports only 1 or 2 streams).
    - the profiler fake AP attempts to simulate a fully featured AP, but there may be cases where it does not behave as expected.
- treat reporting of 802.11k capabilities with caution. to be sure, verify through other means like:
    - check neighbor report requests from a WLC/AP debug
    - gather and analyze a packet capture for action frames containing neighbor report

## thanks

- Nigel Bowden and the WLAN Pi Community (including Kobe Watkins, Philipp Ebbecke, Jerry Olla) for all their input and effort on the first versions of the profiler
