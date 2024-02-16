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

_OPTIONS_ := { -c | -i | -s | --config | --files_path | --hostname_ssid | --noprep | --noAP | --no11r | --no11ax | --oui_update | --read | --version | --logging debug }

# OPTIONS

**-c**

: Set the operating channel to broadcast on. Channels  are  usually  numbered starting at 1, and you may use **iw(8)** to get the total number of channels and list the available channels. Depending on regulatory settings, some channels may not be available. You may need to set a regulatory domain [see **iw(8)** or **crda(8)**] in order to use a 5 GHz channel.

> Examples:

>> **sudo profiler -c 11**

>> **sudo profiler -c 149**

**-i**

: Set the interface to use.

> Example:

>> **sudo profiler -i wlan1**

**-s**

: Set the SSID (or Network Name).

> Example:

>> **sudo profiler -s Test**

>> **sudo profiler -s "Bruh! Far out!"**

**--config**

: Set the configuration file. Default is /etc/wlanpi-profiler/config.ini

> Example:

>> **profiler --config** _FILE_

**--files_path**

: Set where the profiled flat files output to. Default is /var/www/html/profiler

> Example:

>> **profiler --config** _PATH_

**--hostname_ssid**

: Set the SSID name as the current hostname.

**--noprep**

: Bypass interface preparation. Assumes you've already staged the wireless interface in monitor mode on the desired channel.

**--noAP**

: Turns off the beacon process and passively listens for any association request frames on the given channel.


**--no11r**

: Disables and removes 802.11r Information Elements from the profiler beacon. This is for profiling older clients.


**--no11ax**

: Disables and removes 802.11ax Information Elements from the profiler beacon. This is for profiling older clients.

**--oui_update**

: Updates manuf oui lookup database file.

**--read**

: Look for and analyze any association requests contained within a pcap file.

> Example:

>> **profiler --read** _FILE_

**--version**

: Print version.

# LOCALE

This version of wlanpi-profiler is only available in English.

# FILES

/etc/wlanpi-profiler

/var/www/html/profiler

/opt/wlanpi-profiler

# AUTHORS

wlanpi-profiler is developed and maintained by Josh Schmelzle, with the assistance
from a list of wonderful contributors.

# REPORTING BUGS

Bugs and issues can be reported on GitHub:

https://github.com/wlan-pi/profiler

# COPYRIGHT

Copyright © 2024 Josh Schmelzle. License BSD-3-Clause.

# SEE ALSO

iw(8) crda(8)