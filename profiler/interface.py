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
import inspect
import logging
import os
from collections import namedtuple
from typing import Dict, List

# app imports
from .constants import _20MHZ_CHANNEL_LIST
from .helpers import flag_last_object, run_command


class InterfaceError(Exception):
    """Custom exception used when there are problems staging the interface for injection"""


class Interface:
    """WLAN Interface data class"""

    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__.lower())
        self.name = ""
        self.frequency = ""
        self.requires_monitor_interface = False
        self.phys = []
        self.no_interface_prep = False
        self.channel = None

    def setup(self):
        """Perform setup for the interface"""
        if not self.name:
            raise InterfaceError("interface name not set")
        self.driver = self.get_driver()
        self.driver_info = self.get_ethtool_info()
        self.driver_version = self.get_driver_version()
        self.firmware_version = self.get_firmware_version()
        self.check_interface_stack(self.name)
        self.phy_id = self.get_phy_id()
        self.phy = f"phy{self.phy_id}"
        self.mon = ""
        # if we're not managing interface prep, we need to get freq and channel from iw.
        if self.no_interface_prep:
            self.frequency = self.get_frequency()
            self.channel = self.get_channel()
        else:
            # we're using channel provided by user, we need to map it to a frequence for interface staging
            for freq, ch in _20MHZ_CHANNEL_LIST.items():
                if self.channel == ch:
                    self.frequency = freq
                    break
            # iwlwifi needs a different set of staging commands than mt76x2u or rtl88XXau
            if "iwlwifi" in self.driver:
                # if monX is not already created. we will create it.
                self.mon = f"mon{self.phy_id}"
                if self.mon == self.name:
                    self.log.warning(
                        "proposed %s interface matches provided %s and already maps to phy%s",
                        self.mon,
                        self.name,
                        self.phy_id,
                    )
                    raise InterfaceError(
                        "iwlwifi requires use of a separate monitor interface. did you already handle interface staging and mean to run with --noprep option?"
                    )
                else:
                    self.log.debug("new %s will map to phy%s", self.mon, self.phy_id)
                self.requires_monitor_interface = True
        if not self.channel:
            raise InterfaceError("could not determine channel for %s", self.name)
        self.log.debug(
            "frequency is set as %s and channel as %s", self.frequency, self.channel
        )
        self.mac = self.get_mac()
        self.mode = self.get_mode()
        if self.mode not in ("managed", "monitor"):
            raise InterfaceError("%s is mode is not managed or monitor", self.name)
        self.operstate = self.get_operstate()
        self.checks()
        self.log_debug()

    def check_reg_domain(self) -> None:
        """Check and report the set regulatory domain"""
        regdomain_result = run_command(["iw", "reg", "get"])
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

    def reset_interface(self) -> None:
        """Delete monitor interface and restore interface"""
        commands = [
            ["ip", "link", "set", f"{self.mon}", "down"],
            ["iw", "dev", f"{self.mon}", "del"],
            ["ip", "link", "set", f"{self.name}", "up"],
        ]
        for cmd in commands:
            self.log.info("run: %s", " ".join(cmd))
            run_command(cmd)

    def scan(self) -> None:
        """Perform scan in attempt to enable a disabled channel"""
        iwlwifi_scan_commands = [
            ["ip", "link", "set", f"{self.name}", "down"],
            ["iw", "dev", f"{self.name}", "set", "type", "managed"],
            ["ip", "link", "set", f"{self.name}", "up"],
            ["iw", f"{self.name}", "scan"],
        ]
        self.log.info("performing scan on %s", self.name)
        for cmd in iwlwifi_scan_commands:
            self.log.info("run: %s", " ".join(cmd))
            run_command(cmd, suppress_output=True)

    def get_generic_staging_commands(self) -> List:
        """Retrieve generic interface staging commands"""
        return [
            ["ip", "link", "set", f"{self.name}", "down"],
            ["iw", "dev", f"{self.name}", "set", "type", "monitor"],
            ["ip", "link", "set", f"{self.name}", "up"],
            ["iw", f"{self.name}", "set", "channel", f"{self.channel}", "HT20"],
        ]

    def get_iwlwifi_staging_commands(self) -> List:
        """Retrieve interface staging commands for iwlwifi cards"""
        cmds = [
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
            ["iw", f"{self.mon}", "set", "freq", f"{self.frequency}", "HT20"],
        ]
        return cmds

    def stage_interface(self) -> None:
        """Prepare the interface for monitor mode and injection"""
        # get and print debugs for versions of system utilities
        wpa_cli_version = run_command(["wpa_cli", "-v"])
        if wpa_cli_version:
            self.log.debug(
                "wpa_cli version is %s",
                wpa_cli_version.splitlines()[0].replace("wpa_cli ", ""),
            )
        ip_version = run_command(["ip", "-V"])
        if ip_version:
            self.log.debug("%s", ip_version.strip())
        iw_version = run_command(["iw", "--version"])
        if iw_version:
            self.log.debug("%s", iw_version.strip())

        # always run wpa_cli
        wpa_cli_cmd = ["wpa_cli", "-i", f"{self.name}", "terminate"]
        run_command(wpa_cli_cmd)

        cmds = []
        # if interface driver is iwlwifi we need to handle it differently
        if "iwlwifi" in self.driver:
            cmds = self.get_iwlwifi_staging_commands()
            # get channels from iw phy phyX channels
            channels_status = self.get_channels_status()
            # loop through channels and check if we need to do a scan before staging
            if channels_status:
                for _band, channels in channels_status.items():
                    for ch in channels:
                        if int(self.frequency) == int(ch.freq):
                            # if channel we want to use is disabled or No IR, scan to enable it
                            if ch.disabled or ch.no_ir:
                                self.scan()
                            break
        else:
            # if interface is not iwlwifi we can use more generic staging commands
            # this prevents failures for rtl88XXau on some WLAN Pi OS v2 NEO{1,2} deployments
            cmds = self.get_generic_staging_commands()

        # run the staging commands
        for cmd in cmds:
            self.log.info("run: %s", " ".join(cmd))
            if "monitor" in cmd:
                stdout = run_command(cmd)
                if "non-zero" not in stdout:
                    self.log.info(stdout)
            else:
                run_command(cmd)

        # check if the interface is in monitor mode and operstate up
        # self.operstate = self.get_operstate(iface=self.mon)
        self.mode = self.get_mode(iface=self.mon)
        if "monitor" not in self.mode:
            raise InterfaceError("interface is not in monitor mode")

    def get_channels_status(self) -> Dict:
        """Run `iw phy phyX channels` and analyze channel information"""
        cmd = ["iw", "phy", f"{self.phy}", "channels"]
        iw_phy_channels = run_command(cmd)
        if not iw_phy_channels or "command failed" in iw_phy_channels:
            self.log.warning("unable to detect valid channels from: %s", " ".join(cmd))
            return {}
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
            if line.startswith("no ir"):
                no_ir = True
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
            if line.startswith("band "):
                channels.append(channel(freq, ch, no_ir, disabled))
                bands[band] = channels
                # reset channels list
                channels = []
                # reset channel flag
                disabled = False
                first_channel_in_band = True
                band = line.split(" ")[1]
            if last_line:
                channels.append(channel(freq, ch, no_ir, disabled))
                bands[band] = channels
        return bands

    def checks(self, staged=False) -> None:
        """Perform self checks and warn as neccessary"""
        if self.no_interface_prep or staged:
            if "monitor" not in self.mode:
                self.log.warning(
                    "%s mode is in %s mode when we expected monitor mode",
                    self.name,
                    self.mode,
                )

        if self.no_interface_prep or staged:
            name = self.name
            if self.requires_monitor_interface:
                name = self.mon
            if "up" not in self.operstate:
                self.log.warning(
                    "%s operating state is %s when we expect up",
                    name,
                    self.operstate,
                )

        self.check_reg_domain()

    def check_interface_stack(self, interface: str) -> str:
        """Check that the interface we've been asked to run on actually exists and has an ieee80211 stack"""
        discovered_interfaces = []
        for iface in os.listdir("/sys/class/net"):
            iface_path = os.path.join("/sys/class/net", iface)
            device_path = os.path.join(iface_path, "device")
            if os.path.isdir(device_path):
                if "ieee80211" in os.listdir(device_path):
                    discovered_interfaces.append(iface)
        if interface not in discovered_interfaces:
            self.log.warning(
                "%s interface does not support the ieee80211 stack. here are some interfaces which do: %s",
                interface,
                ", ".join(discovered_interfaces),
            )
            raise InterfaceError(f"{interface} is not detected as a valid interface")
        else:
            self.log.debug("%s has ieee80211 stack", interface)
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
        ethtool = run_command(["ethtool", "-i", f"{self.name}"])
        return ethtool.strip()

    def get_driver(self) -> str:
        """Gather driver information for interface"""
        driver = run_command(
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
        mac = run_command(["cat", f"/sys/class/net/{self.name}/address"])
        return mac.strip().lower()

    def get_frequency(self):
        """Determine which frequency the interfac is set to"""
        return self.parse_iw_dev_iface_info(get_frequency=True)

    def get_channel(self):
        """Determine which channel the interface is set to"""
        return self.parse_iw_dev_iface_info(get_channel=True)

    def parse_iw_dev_iface_info(self, get_frequency=False, get_channel=False):
        """Determine what channel or frequency the interface is set to"""
        iw_dev_iface_info = run_command(["iw", "dev", f"{self.name}", "info"])
        for line in iw_dev_iface_info.splitlines():
            line = line.lower().strip()
            if "channel" in line:
                channel = int(line.split(",")[0].split(" ")[1])
                freq = int(line.split(",")[0].split(" ")[2].replace("(", ""))
                resp = _20MHZ_CHANNEL_LIST.get(freq, 0)
                if channel != resp:
                    self.log.warning(
                        "iw reported a different channel (%s) than our lookup (%s)",
                        channel,
                        resp,
                    )
                if get_frequency:
                    self.log.debug(
                        "get_frequency returns %s from `iw dev %s info`",
                        freq,
                        self.name,
                    )
                    return freq
                if get_channel:
                    self.log.debug(
                        "get_channel returns %s from `iw dev %s info`",
                        channel,
                        self.name,
                    )
                    return channel
        return None

    def get_operstate(self, iface="") -> str:
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
        if not iface:
            iface = self.name
        operstate = run_command(["cat", f"/sys/class/net/{iface}/operstate"])
        return operstate.strip().lower()

    @staticmethod
    def build_iw_phy_list(iw_devs) -> List:
        """Create map of phy to iface"""
        log = logging.getLogger(inspect.stack()[0][3])
        iface = namedtuple("iface", ["name", "ifindex", "addr", "type"])
        phy = namedtuple("phy", ["phy_id", "interfaces"])
        phys = []
        ifaces = []
        first_phy = True

        # init vars
        phy_id = ""
        iface_name = ""
        ifindex = ""
        addr = ""
        _type = ""
        for line, is_last_line in flag_last_object(iw_devs.splitlines()):
            # first phy
            line = line.strip().lower()
            if first_phy:
                # phy#0
                if line.startswith("phy#"):
                    first_phy = False
                    phy_id = line.split("#")[1]
                    continue
            # Interface mon0
            if line.startswith("interface "):
                if "unnamed" in line or "non-netdev" in line:
                    log.debug("skipping %s in phy%s detection", line, phy_id)
                    continue
                if iface_name:
                    ifaces.append(iface(iface_name, ifindex, addr, _type))
                iface_name = line.split(" ")[1]
                continue
            # ifindex 4
            if line.startswith("ifindex "):
                ifindex = line.split(" ")[1]
                continue
            # addr d8:f8:83:12:24:07
            if line.startswith("addr "):
                addr = line.split(" ")[1]
                continue
            # type managed
            if line.startswith("type "):
                _type = line.split(" ")[1]
                continue
            if line.startswith("phy#"):
                ifaces.append(iface(iface_name, ifindex, addr, _type))
                phys.append(phy(phy_id, ifaces))
                # reset vars
                phy_id = ""
                iface_name = ""
                ifaces = []
                ifindex = ""
                addr = ""
                _type = ""
                # new phy
                phy_id = line.split("#")[1].strip()

            # last phy
            if is_last_line:
                ifaces.append(iface(iface_name, ifindex, addr, _type))
                phys.append(phy(phy_id, ifaces))
        return phys

    def get_phy_id(self) -> str:
        """Check and determines the phy# for the interface name of this object"""
        self.phys = self.build_iw_phy_list(run_command(["iw", "dev"]))
        self.log.debug("phys: %s", self.phys)
        phy_id = ""
        for phy in self.phys:
            for iface in phy.interfaces:
                if self.name in iface.name:
                    self.log.debug("phy%s maps to provided %s", phy.phy_id, iface.name)
                    phy_id = phy.phy_id
        return phy_id

    def get_mode(self, iface="") -> str:
        """Get the current mode of the interface {unknown/managed/monitor}"""
        if not iface:
            iface = self.name
        _interface_type: "str" = run_command(["cat", f"/sys/class/net/{iface}/type"])
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
        ):  # https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_arp.h#L91
            mode = "monitor"
        # self.log.debug("%s mode is %s (%s)", iface, mode, _type)
        return mode.lower()
