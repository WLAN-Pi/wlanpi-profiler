% WLANPI-PROFILER(1) Wi-Fi client capabilities analyzer tool

# NAME

wlanpi-profiler - Wi-Fi client capabilities analyzer tool

# SYNOPSIS

**profiler** [-h] [-c CHANNEL] [-i INTERFACE] [-s SSID] [--config <FILE>]
                [--files_path <PATH>] [--hostname_ssid]
                [--logging [{debug,warning}]] [--noprep] [--noAP] [--no11r]
                [--no11ax] [--oui_update] [--read <FILE>] [--version]

# DESCRIPTION

wlanpi-profiler is an 802.11 client capabilities profiler. Its purpose is to automate the collection and analysis of the association request frame, which contains the capabilities the client indicates support for. This is accomplished by creating a fake AP to which the client can send an association request to.

# RETURN VALUES

wlanpi-profiler uses the following exit codes:

+ 0: All profiles successfully analyzed with no issues.

# LOCALE

This version of wlanpi-profiler is only available in English.

# AUTHORS

wlanpi-profiler is developed and maintained by Josh Schmelzle, with assistance
from a long list of wonderful contributors.

# REPORTING BUGS

Bugs and issues can be reported on GitHub:

https://github.com/joshschmelzle/profiler2

# COPYRIGHT

Copyright 2019-2021, Josh Schmelzle and contributors.