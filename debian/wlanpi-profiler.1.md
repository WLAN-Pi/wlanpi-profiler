% WLANPI-PROFILER(1) Wi-Fi client capabilities analyzer tool

# NAME

wlanpi-profiler - Wi-Fi client capabilities analyzer tool

# DESCRIPTION

wlanpi-profiler is an 802.11 client capabilities profiler.

It automates the collection and analysis of the association request frame, which contains the claimed capabilities of the client. 

This is accomplished by creating a fake AP to which a client can send its association request to.

Note that wlanpi-profiler requires elevated permissions to stage the wireless interface and open native raw sockets for frame injection.

# SYNOPSIS

**profiler** [ _OPTIONS_ ]

_OPTIONS_ := { -h | -c | -f | -i | -s | --passphrase | --config | --files_path | --hostname_ssid | --debug | --expert | --no-interface-prep | --listen-only | --security-mode | --no11ax | --11be | --no11be | --noprofilertlv | --oui_update | --pcap | --no_bpf_filters | --list_interfaces | --ap-mode | --fakeap | --version }

# OPTIONS

**-h, --help**

: Show help message and exit.

**-c**

: Set the operating channel to broadcast on. Channels are usually numbered starting at 1, and you may use **iw(8)** to get the total number of channels and list the available channels. Depending on regulatory settings, some channels may not be available. You may need to set a regulatory domain [see **iw(8)** or **crda(8)**] in order to use a 5 GHz channel.

> Examples:

>> **sudo profiler -c 11**

>> **sudo profiler -c 149**

**-f**

: Set the operating frequency to broadcast on (alternative to -c).

> Example:

>> **sudo profiler -f 5180**

**-i**

: Set the interface to use.

> Example:

>> **sudo profiler -i wlan1**

**-s**

: Set the SSID (or Network Name).

> Example:

>> **sudo profiler -s Test**

>> **sudo profiler -s "Bruh! Far out!"**

**--passphrase**

: Set the AP passphrase (8-63 characters). Default is "profiler".

> Example:

>> **sudo profiler --passphrase mypassword**

**--config**

: Set the configuration file. Default is /etc/wlanpi-profiler/config.ini

> Example:

>> **profiler --config** _FILE_

**--files_path**

: Set where the profiled flat files output to. Can be specified multiple times. Defaults are /var/www/html/profiler and /root/.local/share/wlanpi-profiler

> Example:

>> **profiler --files_path** _PATH_

**--hostname_ssid**

: Set the SSID name as the current hostname.

**--debug**

: Enable debug logging output.

**--expert**

: Enable expert mode (includes hostapd debug output).

**--no-interface-prep, --noprep**

: Bypass interface preparation. Assumes you've already staged the wireless interface in monitor mode on the desired channel.

**--listen-only, --noAP**

: Turns off the beacon process and passively listens for any association request frames on the given channel (Rx only, no Tx).

**--security-mode**

: Set the security mode for the AP. Options: wpa2, ft-wpa2, wpa3-mixed, ft-wpa3-mixed. Default is ft-wpa3-mixed. Note: 802.11be is auto-disabled for wpa2/ft-wpa2 modes (Wi-Fi 7 requires WPA3).

> Examples:

>> **sudo profiler --security-mode wpa2**

>> **sudo profiler --security-mode wpa3-mixed**

**--no11ax**

: Disables and removes 802.11ax (HE) Information Elements from the profiler beacon. This is for profiling older clients.

**--11be**

: Enable 802.11be (EHT/Wi-Fi 7) reporting. Overrides auto-disable for WPA2 modes.

**--no11be**

: Disables and removes 802.11be (EHT/Wi-Fi 7) Information Elements from the profiler beacon.

**--noprofilertlv**

: Disable generation of Profiler specific vendor IE.

**--oui_update**

: Updates the OUI database (requires Internet connection).

**--pcap**

: Analyze association request frames from a pcap file (cross-platform, no special hardware required).

> Example:

>> **profiler --pcap** _FILE_

**--no_bpf_filters**

: Removes BPF filters from sniffer() but may impact profiler performance.

**--list_interfaces**

: Print out a list of interfaces with an 802.11 stack.

**--ap-mode**

: Use hostapd AP mode for fast discovery (default behavior, requires monitor VIF support).

**--fakeap**

: Use legacy FakeAP mode (Scapy/monitor-only, slower discovery but works with more adapters).

**--version, -V**

: Print version and exit.

# LOCALE

This version of wlanpi-profiler is only available in English.

# FILES

/etc/wlanpi-profiler/config.ini

/var/www/html/profiler

/root/.local/share/wlanpi-profiler

# AUTHORS

wlanpi-profiler is developed and maintained by Josh Schmelzle, with the assistance
from a list of wonderful contributors.

# REPORTING BUGS

Bugs and issues can be reported on GitHub:

https://github.com/wlan-pi/profiler

# COPYRIGHT

Copyright © 2024-2026 Josh Schmelzle. License BSD-3-Clause.

# SEE ALSO

iw(8) crda(8)
