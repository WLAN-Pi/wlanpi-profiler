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

# standard library imports
import logging
import re

# app imports
from .constants import _20MHZ_CHANNEL_LIST
from .helpers import run_cli_cmd


class Interface:
    """WLAN Interface data class"""

    def __init__(self, interface, channel=None, no_interface_prep=False, initial=True):
        self.log = logging.getLogger(self.__class__.__name__.lower())
        self.name = interface.lower()
        self.mac = self.get_mac().lower()
        self.channel = channel
        self.no_interface_prep = no_interface_prep
        self.initial = initial
        if not self.channel:
            self.channel = self.get_channel()
            if not self.channel:
                self.log.warning("could not determine channel")
        self.mode = self.get_mode().lower()
        self.operstate = self.get_operstate().lower()
        self.driver = self.get_driver()
        self.driver_info = self.get_ethtool_info()
        self.driver_version = self.get_driver_version()
        self.firmware_version = self.get_firmware_version()
        self.checks()
        self.log_debug()

    def checks(self) -> None:
        """Perform self checks and warn as neccessary"""
        if self.no_interface_prep or not self.initial:
            if "monitor" not in self.mode:
                self.log.warning(
                    "%s mode is in %s mode when we expected monitor mode",
                    self.name,
                    self.mode,
                )

        if self.no_interface_prep or not self.initial:
            if "up" not in self.operstate:
                self.log.warning(
                    "%s operating state is %s when we expect up",
                    self.name,
                    self.operstate,
                )

    def log_debug(self) -> None:
        """Send debug information to logger"""
        self.log.debug(
            "mac: %s, channel: %s, driver: %s, version: %s",
            self.mac,
            self.channel,
            self.driver,
            self.driver_version,
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
            if "version:" in line:
                out = line.split(" ")[1]
        return out

    def get_firmware_version(self) -> str:
        """Gather driver firmware version for interface"""
        out = ""
        for line in self.driver_info.lower().splitlines():
            if "firmware-version:" in line:
                out = line.split(" ")[1]
        return out

    def get_mac(self) -> str:
        """Gather MAC address for a given interface"""
        mac = run_cli_cmd(["cat", f"/sys/class/net/{self.name}/address"])
        return mac.strip()

    def get_channel(self):
        """Determine what channel the interface is set to"""
        iwconfig = run_cli_cmd(["iwconfig"])
        for line in iwconfig.splitlines():
            line = line.lower()
            if self.name in line:
                if "freq" in line:
                    _result = re.search(r"frequency:\d+.\d+", line)
                    _freq = int(float(_result.group().split(":")[1]) * 1000)
                    return _20MHZ_CHANNEL_LIST[_freq]

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
