# -*- coding: utf-8 -*-
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2020-2021 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.interface
~~~~~~~~~~~~~~~~~~

wlan interface data class
"""

import logging
import os
import subprocess
# standard library imports
from collections import namedtuple
from copy import copy
from typing import Dict, List

# app imports
from .constants import _20MHZ_CHANNEL_LIST
from .helpers import flag_last_object, run_cli_cmd


class InterfaceError(Exception):
    pass


class Interface:
    """WLAN Interface data class"""

    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__.lower())
        self.name = ""
        self.frequency = ""
        self.is_mon = False
        self.no_interface_prep = False
        #self.channel = self.get_channel()

    def setup(self):
        self.check_interface(self.name)
        self.frequency = self.get_frequency()
        self.channel = self.get_channel()
        if not self.channel:
            self.log.warning("could not determine channel")
        self.mac = self.get_mac().lower()
        self.mode = self.get_mode().lower()
        if self.mode not in ("managed", "monitor"):
            raise InterfaceError("%s is mode is not managed or monitor" % self.name)
        self.operstate = self.get_operstate().lower()
        self.phy_id = self.get_phy_id()
        self.phy = f"phy{self.phy_id}"
        if not self.no_interface_prep: 
            self.mon = f"mon{self.phy_id}"
            self.is_mon = True
        self.driver = self.get_driver()
        self.driver_info = self.get_ethtool_info()
        self.driver_version = self.get_driver_version()
        self.firmware_version = self.get_firmware_version()
        self.copy = copy(self)
        self.checks()
        self.log_debug()

    def check_reg_domain(self) -> None:
        """Check and report the set regulatory domain"""
        regdomain_result = run_cli_cmd(["iw", "reg", "get"])
        regdomain = [line for line in regdomain_result.split("\n") if "country" in line]
        if "UNSET" in "".join(regdomain):
            if "iwlwifi" not in self.driver:
                self.log.warning(
                    "reg domain appears unset. consider setting it with 'iw reg set XX'"
                )
                self.log.warning(
                    "https://wireless.wiki.kernel.org/en/users/documentation/iw#updating_your_regulatory_domain"
                )
        else:
            self.log.debug("reg domain set to %s", " ".join(regdomain))
            self.log.debug("see 'iw reg get' for details")

    def run_command(self, command) -> str:
        try:
            cp = subprocess.run(
                command, encoding="utf-8", shell=False, capture_output=True
            )
            return cp.stdout
        except OSError:
            raise InterfaceError("problem running %s: %s", command, cp.stderr)

    def run_commands(self, commands) -> None:
        try:
            for cmd in commands:
                cp = subprocess.run(
                    cmd, encoding="utf-8", shell=False, capture_output=True
                )
                if cp.stderr:
                    if "monitor" in cmd:
                        cp = subprocess.run(
                            ["iw", "dev", f"{self.name}", "set", "type", "monitor"],
                            encoding="utf-8",
                            shell=False,
                            capture_output=True,
                        )
        except OSError:
            msg = (
                "error setting %s interface config: %s",
                self.name,
                "\n".join(
                    [line for line in cp.stderr.split("\n") if line.strip() != ""]
                ),
            )
            self.log.exception(msg, exc_info=None)
            raise InterfaceError(msg)

    def restore_interface(self) -> None:
        """Delete monitor interface and restore interface"""
        commands = [
            ["iw", "dev", f"{self.mon}", "del"],
            # ["iw", "phy", f"{self.phy}", "interface", "add", f"{self.name}", "type", "managed"],
            # ["ip", "link", "set", f"{self.name}", "down"],
            # ["iw", "dev", f"{self.name}", "set", "type", "managed"],
            # ["ip", "link", "set", f"{self.name}", "up"],
        ]
        self.run_commands(commands)

    def scan(self) -> None:
        """Perform scan in attempt to enable a disabled channel"""
        iwlwifi_scan_commands = [
            ["ip", "link", "set", f"{self.name}", "down"],
            ["iw", "dev", f"{self.name}", "set", "type", "managed"],
            ["ip", "link", "set", f"{self.name}", "up"],
            ["iw", f"{self.name}", "scan"],
        ]
        self.log.debug("performing scan on %s", self.name)
        self.run_commands(iwlwifi_scan_commands)

    def stage_interface(self, freq: str) -> None:
        """Prepare the interface for monitor mode and injection"""
        wpa_cli_version = self.run_command(["wpa_cli", "-v"])
        self.log.debug("%s", wpa_cli_version.splitlines()[0])

        # if channel is disabled, a scan may enable it (iwlwifi like AX210)
        for _band, channels in self.get_channels_status().items():
            for ch in channels:
                if freq == ch.freq:
                    if ch.disabled or ch.no_ir:
                        self.scan()
                    break
            else:
                continue
            break

        staging_commands = [
            ["wpa_cli", "-i", f"{self.name}", "terminate"],
            [
                "iw",
                f"{self.phy}",
                "interface",
                "add",
                f"{self.mon}",
                "type",
                "monitor",
                "flags",
                "none",
            ],
            ["ip", "link", "set", f"{self.mon}", "up"],
            ["ip", "link", "set", f"{self.name}", "down"],
            ["iw", f"{self.mon}", "set", "freq", f"{freq}", "HT20"],
        ]
        self.run_commands(staging_commands)


    def get_channels_status(self) -> Dict:
        iw_version = self.run_command(["iw", "--version"])
        ip_version = self.run_command(["ip", "-V"])
        self.log.debug("%s", iw_version.strip())
        self.log.debug("%s", ip_version.strip())
        iw_phy_channels = self.run_command(["iw", "phy", f"{self.phy}", "channels"])
        freq = ""
        ch = ""
        no_ir = False
        band = ""
        disabled = False
        first_band = True
        first_channel_in_band = True
        bands = {}
        channels = []
        channel = namedtuple("channel", ["freq", "ch", "no_ir", "disabled"])

        for line, last_line in flag_last_object(iw_phy_channels.splitlines()):
            line = line.strip().lower()
            if first_band:
                first_band = False
                if line.startswith("band "):
                    band = line.split(" ")[1]
                    continue
            if first_channel_in_band:
                first_channel_in_band = False
                if line.startswith("*"):
                    freq = line.split()[1]
                    ch = line.split()[3].replace("[", "").replace("]", "")
                    continue
            if line.startswith("*"):
                channels.append(channel(freq, ch, no_ir, disabled))
                # reset vars
                freq = ""
                ch = ""
                no_ir = False
                disabled = False
                if "disabled" in line:
                    disabled = True
                freq = line.split()[1]
                ch = line.split()[3].replace("[", "").replace("]", "")
                continue
            if line.startswith("band "):
                channels.append(channel(freq, ch, no_ir, disabled))
                bands[band] = channels
                # reset channels list
                channels = []
                # reset channel flag
                disabled = False
                first_channel_in_band = True
                band = line.split(" ")[1]
            if line.startswith("no ir"):
                no_ir = True
                continue
            if last_line:
                channels.append(channel(freq, ch, no_ir, disabled))
                bands[band] = channels
        return bands

    def checks(self) -> None:
        """Perform self checks and warn as neccessary"""
        if self.no_interface_prep:
            if "monitor" not in self.mode:
                self.log.warning(
                    "%s mode is in %s mode when we expected monitor mode",
                    self.name,
                    self.mode,
                )

        if self.no_interface_prep:
            if "up" not in self.operstate:
                self.log.warning(
                    "%s operating state is %s when we expect up",
                    self.name,
                    self.operstate,
                )

        self.check_reg_domain()

    def check_interface(self, interface: str) -> str:
        """Check that the interface we've been asked to run on actually exists"""
        discovered_interfaces = []
        for iface in os.listdir("/sys/class/net"):
            iface_path = os.path.join("/sys/class/net", iface)
            device_path = os.path.join(iface_path, "device")
            if os.path.isdir(device_path):
                if "ieee80211" in os.listdir(device_path):
                    discovered_interfaces.append(iface)
        if interface not in discovered_interfaces:
            self.log.warning(
                "%s interface does not claim ieee80211 support. here are some interfaces which do: %s",
                interface,
                ", ".join(discovered_interfaces),
            )
            raise InterfaceError(f"{interface} is not a valid interface")
        else:
            self.log.debug("%s claims to support ieee80211", interface)
            return interface

    def log_debug(self) -> None:
        """Send debug information to logger"""
        self.log.debug(
            "mac: %s, channel: %s, driver: %s, version: %s, firmware-version: %s",
            self.mac,
            self.channel,
            self.driver,
            self.driver_version,
            self.firmware_version,
        )

    def get_ethtool_info(self) -> str:
        """Gather ethtool information for interface"""
        ethtool = run_cli_cmd(["ethtool", "-i", f"{self.name}"])
        return ethtool.strip()

    def get_driver(self) -> str:
        """Gather driver information for interface"""
        driver = run_cli_cmd(
            ["readlink", "-f", f"/sys/class/net/{self.name}/device/driver"]
        )
        return driver.split("/")[-1].strip()

    def get_driver_version(self) -> str:
        """Gather driver version for interface"""
        out = ""
        for line in self.driver_info.lower().splitlines():
            if line.startswith("version:"):
                out = line.split(" ")[1]
        return out

    def get_firmware_version(self) -> str:
        """Gather driver firmware version for interface"""
        out = ""
        for line in self.driver_info.lower().splitlines():
            if line.startswith("firmware-version:"):
                out = line.split(" ")[1]
        return out

    def get_mac(self) -> str:
        """Gather MAC address for a given interface"""
        mac = run_cli_cmd(["cat", f"/sys/class/net/{self.name}/address"])
        return mac.strip()

    def get_frequency(self):
        """Determine which frequency the interfac is set to"""
        return self.parse_iw_dev_iface_info(get_frequency=True)

    def get_channel(self):
        """Determine which channel the interface is set to"""
        return self.parse_iw_dev_iface_info(get_channel=True)

    def parse_iw_dev_iface_info(self, get_frequency=False, get_channel=False):
        """Determine what channel or frequency the interface is set to"""
        if get_frequency:
            self.log.debug("getting frequency from iw dev <iface> info")
        if get_channel:
            self.log.debug("getting channel from iw dev <iface> info")
        iw_dev_iface_info = self.run_command(["iw", "dev", f"{self.name}", "info"])
        for line in iw_dev_iface_info.splitlines():
            line = line.lower().strip()
            if "channel" in line:
                channel = int(line.split(",")[0].split(" ")[1])
                freq = int(line.split(",")[0].split(" ")[2].replace("(", ""))
                resp = _20MHZ_CHANNEL_LIST.get(freq, 0)
                if channel != resp:
                    self.log.warning(
                        "iw reported a different channel (%s) than our lookup (%s)", channel,
                        resp,
                    )
                if get_frequency:
                    self.log.debug("get_frequency is %s", freq)
                    return freq
                if get_channel:
                    self.log.debug("get_channel is %s", channel)
                    return channel
        #return _20MHZ_CHANNEL_LIST.get(self.frequency, 0)

    def get_operstate(self) -> str:
        """
        Get the current operating state of the interface.

        https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net
        What:       /sys/class/net/<iface>/operstate
        Date:       March 2006
        KernelVersion:  2.6.17
        Contact:    netdev@vger.kernel.org
        Description:
            Indicates the interface RFC2863 operational state as a string.
            Possible values are:
            "unknown", "notpresent", "down", "lowerlayerdown", "testing",
            "dormant", "up".
        """
        operstate = run_cli_cmd(["cat", f"/sys/class/net/{self.name}/operstate"])
        return operstate.strip()

    def build_iw_phy_list(self) -> List:
        iw_devs = run_cli_cmd(["iw", "dev", f"{self.name}", "info"])
        phy = namedtuple("phy", ["phy_id", "phy_name", "ifindex", "addr", "type"])
        phys = []
        first = True

        # init vars
        phy_id = ""
        phy_name = ""
        ifindex = ""
        addr = ""
        _type = ""
        for line, last_line in flag_last_object(iw_devs.splitlines()):
            # first phy
            line = line.strip().lower()
            if first:
                if line.startswith("phy#"):
                    first = False
                    phy_id = line.split("#")[1]
                    continue
            if line.startswith("interface "):
                phy_name = line.split(" ")[1]
                continue
            if line.startswith("ifindex "):
                ifindex = line.split(" ")[1]
                continue
            if line.startswith("addr "):
                addr = line.split(" ")[1]
                continue
            if line.startswith("type "):
                _type = line.split(" ")[1]
                continue
            if line.startswith("wiphy "):
                phy_id = line.split(" ")[1]
                continue
            if line.startswith("phy#"):
                phys.append(phy(phy_id, phy_name, ifindex, addr, _type))
                # reset vars
                phy_id = None
                phy_name = ""
                ifindex = None
                addr = ""
                _type = ""
                # new phy
                phy_id = line.split("#")[1].strip()

            # last phy
            if last_line:
                phys.append(phy(phy_id, phy_name, ifindex, addr, _type))
        return phys

    def get_phy_id(self) -> str:
        phys = self.build_iw_phy_list()
        phy_id = ""
        for phy in phys:
            if self.name in phy.phy_name:
                phy_id = phy.phy_id
        return phy_id

    def get_mode(self) -> str:
        """Get the current mode of the interface"""
        _interface_type: "str" = run_cli_cmd(
            ["cat", f"/sys/class/net/{self.name}/type"]
        )
        mode = "unknown"
        _type = int(_interface_type)
        if _type == 1:
            mode = "managed"
        elif _type == 801:
            mode = "monitor"
        elif _type == 802:
            mode = "monitor"
        elif (
            _type == 803
        ):  # https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_arp.h#L90
            mode = "monitor"
        return mode
