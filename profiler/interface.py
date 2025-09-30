# -*- coding: utf-8 -*-
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024 Josh Schmelzle
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
from .constants import _20MHZ_FREQUENCY_CHANNEL_MAP
from .helpers import flag_last_object, run_command


class InterfaceError(Exception):
    """Custom exception used when there are problems staging the interface for injection"""


class InterfaceInformation:
    """Base class for Interface Information"""

    def __init__(
        self,
        phy,
        interface,
        mode,
        driver,
        driver_version,
        firmware_rev,
        chipset,
    ):
        self.phy = phy
        self.interface = interface
        self.mode = mode
        self.driver = driver
        self.driver_version = driver_version
        self.firmware_rev = firmware_rev
        self.chipset = chipset


class Interface:
    """WLAN Interface data class"""

    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__.lower())
        self.name = ""
        self.channel = None
        self.frequency = None
        self.requires_vif = False
        self.phys = []
        self.no_interface_prep = False
        self.removed = False

    def setup(self):
        """Perform setup for the interface"""
        if not self.name:
            raise InterfaceError("interface name not set")
        self.driver = self.get_driver(self.name)
        eth_tool_info = self.get_ethtool_info(self.name)
        self.driver_version = self.get_driver_version(eth_tool_info)
        self.firmware_revision = self.get_firmware_revision(eth_tool_info)
        self.chipset = self.get_chipset(self.name)
        self.check_interface_stack(self.name)
        self.phy_id = self.get_phy_id()
        self.phy = f"phy{self.phy_id}"
        self.mon = ""
        # if we're not managing interface prep, we need to get freq and channel from iw.
        if self.no_interface_prep:
            iw_dev_iface_info = run_command(["iw", "dev", f"{self.name}", "info"])
            self.frequency = self.get_frequency(iw_dev_iface_info, self.name)
            self.channel = self.get_channel(iw_dev_iface_info, self.name)
        else:
            # the rtl88XXau is crap and doesn't support vifs, otherwise lets create a mon interface for iwlwifi, mt76x2u, etc
            if "88XXau" not in self.driver:
                # if <iface>mon is not already created. we will create it.
                self.mon = f"{self.name}mon"
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
                self.requires_vif = True
        if not self.channel:
            raise InterfaceError("unknown channel setting for %s", self.name)
        if not self.frequency:
            raise InterfaceError("unknown frequency setting for %s", self.name)
        self.log.debug(
            "frequency is set to %s which maps to channel %s",
            self.frequency,
            self.channel,
        )
        self.mac = self.get_mac()
        self.mode = self.get_mode()
        if self.mode not in ("managed", "monitor"):
            raise InterfaceError("%s is mode is not managed or monitor", self.name)
        self.operstate = self.get_operstate()
        self.checks()
        self.log_debug()

    @staticmethod
    def get_attr_max_len(searchList, attr):
        """Find all matching attributes in a list and return max length"""
        _list = []
        for _obj in searchList:
            if isinstance(getattr(_obj, attr), str):
                _list.append(getattr(_obj, attr))
            else:
                _list.append(str(getattr(_obj, attr)))
        return max(len(x) for x in _list)

    def print_interface_information(self) -> None:
        """Print wiphys to the screen"""
        lsb_release = run_command(["lsb_release", "-a"])
        print(lsb_release)
        self.phys = self.build_iw_phy_list(run_command(["iw", "dev"]))
        self.log.debug("phys: %s", self.phys)

        ifaces = []
        for phy in self.phys:
            for iface in phy.interfaces:
                eth_tool_info = self.get_ethtool_info(iface.name)
                driver = self.get_driver(iface.name)
                driver_version = self.get_driver_version(eth_tool_info)
                firmware_rev = self.get_firmware_revision(eth_tool_info)
                chipset = self.get_chipset(iface.name)
                mode = self.get_mode(iface=iface.name)
                ifaces.append(
                    InterfaceInformation(
                        f"phy{phy.phy_id}",
                        iface.name,
                        mode,
                        driver,
                        driver_version,
                        firmware_rev,
                        chipset,
                    )
                )
        ifaces.reverse()

        ifaces.insert(
            0,
            InterfaceInformation(
                "PHY",
                "Interface",
                "Mode",
                "Driver",
                "DriverVersion",
                "FirmwareRev",
                "Chipset",
            ),
        )
        ifaces.insert(1, InterfaceInformation(" ", " ", " ", " ", " ", " ", " "))

        phy_len = Interface.get_attr_max_len(ifaces, "phy")
        interface_len = Interface.get_attr_max_len(ifaces, "interface")
        mode_len = Interface.get_attr_max_len(ifaces, "mode")
        driver_len = Interface.get_attr_max_len(ifaces, "driver")
        driverv_len = Interface.get_attr_max_len(ifaces, "driver_version")
        firmwarer_len = Interface.get_attr_max_len(ifaces, "firmware_rev")
        chipset_len = Interface.get_attr_max_len(ifaces, "chipset")

        uname = run_command(["uname", "-a"])
        print(uname)

        out = ""
        for iface in ifaces:
            out += "{0:<{phy_len}}  {1:<{interface_len}}  {2:<{mode_len}}  {3:<{driver_len}}  {4:<{driverv_len}}  {5:<{firmwarer_len}}  {6:<{chipset_len}}\n".format(
                iface.phy,
                iface.interface,
                iface.mode,
                iface.driver,
                iface.driver_version,
                iface.firmware_rev,
                iface.chipset,
                phy_len=phy_len,
                interface_len=interface_len,
                mode_len=mode_len,
                driver_len=driver_len,
                driverv_len=driverv_len,
                firmwarer_len=firmwarer_len,
                chipset_len=chipset_len,
            )
        print(out)

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
            self.log.debug("run: %s", " ".join(cmd))
            run_command(cmd)

    def check_for_disabled_or_noir_channels(
        self, freq: int, iw_phy_channels, verbose=False
    ) -> bool:
        """Check iw phy channels for disabled or No IR and return True if found"""
        channels_status = self.get_channels_status(iw_phy_channels)
        # on some cards, like iwlwifi, we may need to perform a scan to unlock channels because of LAR
        if channels_status:
            for _band, channels in channels_status.items():
                # loop through channels and check if we need to do a scan before staging
                for ch in channels:
                    if int(freq) == int(ch.freq):
                        # if channel we want to use is disabled or No IR, attempt scan to enable it
                        if ch.disabled or ch.no_ir:
                            if verbose:
                                if ch.disabled:
                                    self.log.warning(
                                        "Channel is disabled for %s (%s)",
                                        ch.ch,
                                        ch.freq,
                                    )
                                if ch.no_ir:
                                    self.log.warning(
                                        "No IR found in iw channel information for %s (%s) which _may_ cause packet injection to fail! Problem with discovery? Try a different channel / frequency. Confirm we're beaconing via OTA capture from a different interface or device.",
                                        ch.ch,
                                        ch.freq,
                                    )
                            return True
        return False

    def stage_interface(self) -> None:
        """Prepare the interface for monitor mode and injection"""
        # get and print debugs for versions of system utilities
        self.log.debug("start stage_interface")
        try:
            wpa_cli_version = run_command(["wpa_cli", "-v"])
            self.log.debug(
                "wpa_cli version is %s",
                wpa_cli_version.splitlines()[0].replace("wpa_cli ", ""),
            )
            wpa_cli_cmd = ["wpa_cli", "-i", f"{self.name}", "terminate"]
            self.log.debug("running '%s'", wpa_cli_cmd)
            run_command(wpa_cli_cmd)
            self.log.debug("finished with '%s'", wpa_cli_cmd)
        except FileNotFoundError:
            self.log.warning("wpa_cli not present")

        ip_version = run_command(["ip", "-V"])
        if ip_version:
            self.log.debug("%s", ip_version.strip())
        iw_version = run_command(["iw", "--version"])
        if iw_version:
            self.log.debug("%s", iw_version.strip())

        cmds = []
        # If the driver is crap, like 88XXau and does not support vif, we handle staging the old way:
        if "88XXau" in self.driver:
            # this prevents failures for rtl88XXau on some WLAN Pi OS v2 NEO{1,2} deployments
            cmds = [
                ["ip", "link", "set", f"{self.name}", "down"],
                ["iw", "dev", f"{self.name}", "set", "type", "monitor"],
                ["ip", "link", "set", f"{self.name}", "up"],
                ["iw", f"{self.name}", "set", "channel", f"{self.channel}", "HT20"],
            ]
        else:
            cmds = [
                ["ip", "link", "set", f"{self.name}", "down"],
                ["iw", "dev", f"{self.name}", "set", "type", "managed"],
                ["ip", "link", "set", f"{self.name}", "up"],
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
                ["iw", f"{self.name}", "scan"],
                ["ip", "link", "set", f"{self.name}", "down"],
                ["iw", f"{self.mon}", "set", "freq", f"{self.frequency}", "HT20"],
            ]

        # run the staging commands
        for cmd in cmds:
            self.log.debug("run: %s", " ".join(cmd))
            if "monitor" in cmd:
                stdout = run_command(cmd).strip()
                if "non-zero" not in stdout:
                    self.log.debug(stdout)
                    if "not supported" in stdout:
                        raise InterfaceError(
                            f"{self.name} does not appear to support monitor mode"
                        )
            elif "scan" in cmd:
                run_command(cmd, suppress_output=True)
            else:
                run_command(cmd)

        # check if the interface is in monitor mode and operstate up
        # self.operstate = self.get_operstate(iface=self.mon)
        self.mode = self.get_mode(iface=self.mon)
        if "monitor" not in self.mode:
            raise InterfaceError("interface is not in monitor mode")

        # check for No IR or disabled
        self.check_for_disabled_or_noir_channels(
            self.frequency,
            run_command(["iw", "phy", f"{self.phy}", "channels"]),
            verbose=True,
        )

        self.log.debug("finish stage_interface")

    @staticmethod
    def get_channels_status(iw_phy_channels) -> Dict:
        """Run `iw phy phyX channels` and analyze channel information"""
        log = logging.getLogger(inspect.stack()[0][3])
        if not iw_phy_channels or "command failed" in iw_phy_channels:
            log.warning("unable to detect valid channels from")
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
            if self.requires_vif:
                name = self.mon
            if "up" not in self.operstate:
                self.log.warning(
                    "%s operating state is %s when we expect up",
                    name,
                    self.operstate,
                )

        self.check_reg_domain()

    def check_interface_stack(self, interface: str) -> str:
        """Check that the interface we've been asked to run on actually exists and has an mac80211 stack"""
        discovered_interfaces = []
        for iface in os.listdir("/sys/class/net"):
            iface_path = os.path.join("/sys/class/net", iface)
            # ieee80211
            # device_path = os.path.join(iface_path, "device")
            if os.path.isdir(iface_path):
                if "phy80211" in os.listdir(iface_path):
                    discovered_interfaces.append(iface)
        if interface not in discovered_interfaces:
            self.log.warning(
                "%s interface does not support the mac80211 stack. here are some interfaces which do: %s",
                interface,
                ", ".join(discovered_interfaces),
            )
            raise InterfaceError(f"{interface} is not detected as a valid interface")
        else:
            self.log.debug("%s has a mac80211 stack", interface)
            return interface

    def log_debug(self) -> None:
        """Send debug information to logger"""
        self.log.debug(
            "mac: %s, channel: %s, driver: %s, driver-version: %s, chipset: %s",
            self.mac,
            self.channel,
            self.driver,
            self.driver_version,
            self.chipset,
        )

    def get_ethtool_info(self, iface) -> str:
        """Gather ethtool information for interface"""
        ethtool = run_command(["ethtool", "-i", f"{iface}"])
        return ethtool.strip()

    def get_driver(self, iface) -> str:
        """Gather driver information for interface"""
        driver = run_command(
            ["readlink", "-f", f"/sys/class/net/{iface}/device/driver"]
        )
        return driver.split("/")[-1].strip()

    def get_driver_version(self, eth_tool_info) -> str:
        """Gather driver version for interface"""
        out = ""
        for line in eth_tool_info.lower().splitlines():
            if line.startswith("version:"):
                out = line.replace("version:", "").strip()
        return out

    def get_firmware_revision(self, eth_tool_info) -> str:
        """Gather driver firmware version for interface"""
        out = ""
        for line in eth_tool_info.lower().splitlines():
            if line.startswith("firmware-version:"):
                out = line.replace("firmware-version:", "").strip()
        return out

    def cleanup_chipset(self, chipset) -> str:
        """Remove extraneous words"""
        words = [
            "Wireless LAN Controllers",
            "Network Connection",
            "Wireless Adapter",
            "WLAN Adapter",
            "(",
            ")",
            "Corporation.",
            "Corporation",
            "Corp.",
            "Corp",
            "Inc.",
            "Inc",
            "Technology,",
            "Technology",
            ",",
            '"',
            "  ",
        ]
        for word in words:
            if word in chipset:
                chipset = chipset.replace(word, " ")
        chipset = " ".join(chipset.split())
        return chipset

    def get_chipset(self, iface) -> str:
        """Gather chipset information for interface"""
        modalias = run_command(["cat", f"/sys/class/net/{iface}/device/modalias"])
        bus = modalias.split(":")[0]
        chipset = ""
        if bus == "usb":
            businfo = modalias.split(":")[1][1:10].replace("p", ":")
            chipset = run_command(["lsusb", "-d", f"{businfo}"])
            chipset = chipset.split(":")[2][5:].strip()
            chipset = self.cleanup_chipset(chipset)
            return chipset
        if bus == "pci":
            vendor = run_command(
                ["cat", f"/sys/class/net/{iface}/device/vendor"]
            ).strip()
            device = run_command(
                ["cat", f"/sys/class/net/{iface}/device/device"]
            ).strip()
            chipset = run_command(["lspci", "-d", f"{vendor}:{device}", "-q"])
            chipset = chipset.split(":")[2].strip().splitlines()[0]
            chipset = self.cleanup_chipset(chipset)
            return chipset
        if bus == "sdio":
            vendor = run_command(
                ["cat", f"/sys/class/net/{iface}/device/vendor"]
            ).strip()
            device = run_command(
                ["cat", f"/sys/class/net/{iface}/device/device"]
            ).strip()
            if f"{vendor}:{device}" == "0x02d0:0xa9a6":
                chipset = "Broadcom 43430"
        else:
            chipset = "Unknown"
        return chipset

    def get_mac(self) -> str:
        """Gather MAC address for a given interface"""
        mac = run_command(["cat", f"/sys/class/net/{self.name}/address"])
        return mac.strip().lower()

    @staticmethod
    def get_frequency(iw_dev_iface_info, iface):
        """Determine which frequency the interfac is set to"""
        return Interface.parse_iw_dev_iface_info(
            iw_dev_iface_info, iface, get_frequency=True
        )

    @staticmethod
    def get_channel(iw_dev_iface_info, iface):
        """Determine which channel the interface is set to"""
        return Interface.parse_iw_dev_iface_info(
            iw_dev_iface_info, iface, get_channel=True
        )

    @staticmethod
    def parse_iw_dev_iface_info(
        iw_dev_iface_info, iface, get_frequency=False, get_channel=False
    ):
        """Determine what channel or frequency the interface is set to"""
        log = logging.getLogger(inspect.stack()[0][3])
        for line in iw_dev_iface_info.splitlines():
            line = line.lower().strip()
            if "channel" in line:
                channel = int(line.split(",")[0].split(" ")[1])
                freq = int(line.split(",")[0].split(" ")[2].replace("(", ""))
                resp = _20MHZ_FREQUENCY_CHANNEL_MAP.get(freq, 0)
                if channel != resp:
                    log.warning(
                        "iw reported a different channel (%s) than our lookup (%s)",
                        channel,
                        resp,
                    )
                if get_frequency:
                    log.debug(
                        "get_frequency returns %s from `iw dev %s info`",
                        freq,
                        iface,
                    )
                    return freq
                if get_channel:
                    log.debug(
                        "get_channel returns %s from `iw dev %s info`",
                        channel,
                        iface,
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
                # if iw dev resp is empty return
                if is_last_line:
                    return []
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
        # self.log.debug("phys: %s", self.phys)
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
        try:
            _type = int(_interface_type)
        except ValueError:
            return mode
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
