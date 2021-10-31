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
# standard library imports
import os
import re
import subprocess
import sys

# app imports
from .constants import _20MHZ_CHANNEL_LIST
from .helpers import run_cli_cmd

class InterfaceError(Exception):
    pass

class Interface:
    """WLAN Interface data class"""

    def __init__(self, interface, channel=None, no_interface_prep=False):
        self.log = logging.getLogger(self.__class__.__name__.lower())
        self.name = interface.lower()
        self.check_interface(self.name)
        self.channel = channel
        self.no_interface_prep = no_interface_prep
        if not self.channel:
            self.channel = self.get_channel()
            if not self.channel:
                self.log.warning("could not determine channel")
        self.mac = self.get_mac().lower()
        self.mode = self.get_mode().lower()
        self.operstate = self.get_operstate().lower()
        self.driver = self.get_driver()
        self.driver_info = self.get_ethtool_info()
        self.driver_version = self.get_driver_version()
        self.firmware_version = self.get_firmware_version()
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

    def stage_interface(self) -> None:
        """Prepare the interface for monitor mode and injection"""
        if self.mode in ("managed", "monitor"):
            iwlwifi_scan_commands = [
                ["ip", "link", "set", f"{self.name}", "down"],
                ["iw", "dev", f"{self.name}", "set", "managed"],
                ["ip", "link", "set", f"{self.name}", "up"],
                ["iw", f"{self.name}", "scan"],
            ]
            staging_commands = [
                ["wpa_cli", "-i", f"{self.name}", "terminate"],
                ["ip", "link", "set", f"{self.name}", "down"],
                ["iw", "dev", f"{self.name}", "set", "monitor", "none"],
                ["ip", "link", "set", f"{self.name}", "up"],
                ["iw", f"{self.name}", "set", "channel", f"{self.channel}", "HT20"],
            ]
            if "iwlwifi" in self.driver:
                commands = iwlwifi_scan_commands + staging_commands
            else:
                commands = staging_commands
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
                        if "wpa_cli" not in cmd:
                            raise OSError(
                                f"problem running '{' '.join(cmd)}'\n{cp.stderr}"
                            )
                return True
            except OSError:
                self.log.exception(
                    "error setting %s interface config: %s",
                    self.name,
                    "\n".join(
                        [line for line in cp.stderr.split("\n") if line.strip() != ""]
                    ),
                    exc_info=None,
                )

        self.log.error("failed to prepare the interface...")
        sys.exit(-1)

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
