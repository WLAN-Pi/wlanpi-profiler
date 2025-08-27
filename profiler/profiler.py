# -*- coding: utf-8 -*-
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.profiler
~~~~~~~~~~~~~~~~~

profiler code goes here, separate from fake ap code.
"""

import base64
import inspect
import json
import logging
import os
import platform
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from difflib import Differ
from functools import total_ordering
from logging.handlers import QueueHandler
from time import strftime
from typing import Dict, List, Union

from manuf2 import manuf  # type: ignore
from scapy.all import Dot11, RadioTap, wrpcap  # type: ignore

from .__version__ import __version__
from .constants import _20MHZ_FREQUENCY_CHANNEL_MAP
from .helpers import is_randomized

SSID_PARAMETER_SET_IE_TAG = 0
POWER_MIN_MAX_IE_TAG = 33  # power capability IE
SUPPORTED_CHANNELS_IE_TAG = 36  # client supported channels
HT_CAPABILITIES_IE_TAG = 45  # 802.11n
RSN_CAPABILITIES_IE_TAG = 48  # 802.11w
FT_CAPABILITIES_IE_TAG = 54  # 802.11r - mobility domain (MDE) IE
SUPPORTED_OPERATING_CLASSES_IE_TAG = 59  # Alternate Operating Classes IE
RM_CAPABILITIES_IE_TAG = 70  # 802.11k
EXT_CAPABILITIES_IE_TAG = 127  # 802.11v - Extended Capabilities
VHT_CAPABILITIES_IE_TAG = 191  # 802.11ac
VENDOR_SPECIFIC_IE_TAG = 221  # Vendor Specific IE
IE_EXT_TAG = 255  # Element ID Extension field
HE_CAPABILITIES_IE_EXT_TAG = 35  # 802.11ax HE Capabilities IE
HE_OPERATION_IE_EXT_TAG = 36  # 802.11ax HE Operation IE
HE_SPATIAL_REUSE_IE_EXT_TAG = 39  # 802.11ax Spatial Reuse Paramater IE
HE_6_GHZ_BAND_CAP_IE_EXT_TAG = 59  # 802.11ax 6 GHz capabilities IE
MLE_EXT_TAG = 107  # 802.11be Multi-Link Element
EHT_CAPABILITIES_IE_EXT_TAG = 108  # 802.11be EHT Capabilities IE
EHT_OPERATION_IE_EXT_TAG = 109  # 802.11be EHT Operation IE
RSNX_TAG = 244  # RSNX tag number


@total_ordering
@dataclass
class Capability:
    """Define custom fields for reporting"""

    name: str = ""
    value: Union[str, int] = ""
    db_key: str = ""
    db_value: Union[int, str, List[str]] = 0

    def __lt__(self, other):
        """Make capabilities sortable by name by default"""
        if not isinstance(other, Capability):
            return NotImplemented
        return self.name < other.name

    def __eq__(self, other):
        """Define equality based on name"""
        if not isinstance(other, Capability):
            return NotImplemented
        return self.name == other.name


class TsharkClientCapabilityParser:
    """Parse WiFi client capabilities from tshark JSON output"""

    def __init__(self, logger):
        self.capabilities = []
        self.lookup = manuf.MacParser(update=False)
        self.log = logger

    def parse_tshark_json(self, json_data: str) -> Dict:
        """Parse tshark JSON output and extract client capabilities"""
        data = json.loads(json_data)
        if not data or not isinstance(data, list) or len(data) == 0:
            return {"error": "No packet data found or invalid format"}

        try:
            # Extract the layers from the packet
            packet = data[0]["_source"]["layers"]

            client_mac = self._extract_client_mac(packet)
            client_manuf = self._extract_manufacturer(packet)

            capture_bssid = self._extract_bssid(packet)
            capture_manuf = self._extract_ap_manufacturer(packet)
            capture_freq_band = self._extract_frequency_band(packet)
            capture_channel = self._extract_channel(packet)
            capture_ssid = self._extract_ssid(packet)

            capabilities = []

            dot11_elt_dict = self._extract_information_elements(packet)
            # print(json.dumps(dot11_elt_dict, indent=2))
            if not dot11_elt_dict:
                return {
                    "client_mac": client_mac,
                    "bssid": capture_bssid,
                    "freq_band": capture_freq_band,
                    "manufacturer": client_manuf,
                    "ssid": capture_ssid,
                    "capabilities": {},
                    "warning": "No information elements found",
                }

            chipset = self._extract_chipset(dot11_elt_dict)

            capabilities += self._analyze_ht_capabilities(dot11_elt_dict)
            capabilities += self._analyze_vht_capabilities(dot11_elt_dict)
            capabilities += self._analyze_rm_capabilities(dot11_elt_dict)
            capabilities += self._analyze_ft_capabilities(dot11_elt_dict)
            capabilities += self._analyze_ext_capabilities(dot11_elt_dict)
            capabilities += self._analyze_rsn_capabilities(dot11_elt_dict)
            capabilities += self._analyze_he_capabilities(dot11_elt_dict)
            capabilities += self._analyze_power_capabilities(dot11_elt_dict)
            is_6ghz = False
            if "6" in str(capture_freq_band):
                is_6ghz = True
            capabilities += self._analyze_supported_channels(dot11_elt_dict, is_6ghz)
            capabilities += self._analyze_rsnx_capabilities(dot11_elt_dict)
            capabilities += self._analyze_6ghz_capabilities(dot11_elt_dict)
            capabilities += self._analyze_eht_capabilities(dot11_elt_dict)
            capabilities += self._analyze_multi_link_capabilities(dot11_elt_dict)

            result = {
                "mac": client_mac,
                "is_laa": is_randomized(client_mac),
                "manuf": client_manuf,
                "chipset": chipset,
                "capture_ssid": capture_ssid,
                "capture_bssid": capture_bssid,
                "capture_manuf": capture_manuf,
                "capture_band": capture_freq_band,
                "capture_channel": capture_channel,
                "capabilities": capabilities,
                "features": {},
                "pcapng": {},
                "schema_version": 2,
                "profiler_version": __version__,
            }

            # Add capabilities to result
            for cap in capabilities:
                if cap.db_key and cap.db_value is not None:
                    result["features"][cap.db_key] = cap.db_value
            result["features"] = dict(sorted(result["features"].items()))
            return result

        except KeyError as e:
            return {"error": f"Failed to parse packet data: {str(e)}"}

    def generate_text_report(self, profile: dict) -> str:
        """Generate a report for profile"""
        mac = profile.get("mac")
        manuf = profile.get("manuf", None)
        if is_randomized(mac):
            if manuf is None:
                manuf = "Randomized MAC"
            else:
                manuf = f"{manuf} (Randomized MAC)"

        text_report = "-" * 45
        text_report += f"\n - SSID: {profile.get('capture_ssid')}"
        text_report += f"\n - Client MAC: {mac}"
        text_report += f"\n - OUI manufacturer lookup: {manuf}"
        text_report += f"\n - Chipset lookup: {profile.get('chipset', 'Unknown')}"
        band_label = ""
        band = profile.get("capture_band")
        if band[0] == "2":
            band_label = "2.4 GHz"
        elif band[0] == "5":
            band_label = "5 GHz"
        elif band[0] == "6":
            band_label = "6 GHz"
        else:
            band_label = "Unknown"
        text_report += f"\n - Frequency band: {band_label}"
        text_report += f"\n - Capture channel: {profile.get('capture_channel')}\n"
        text_report += "-" * 45
        text_report += "\n"
        capabilities = profile.get("capabilities", [])
        if capabilities:
            capabilities.sort()
        for cap in capabilities:
            if cap:
                self.log.debug(cap)
                if cap.name and cap.value:
                    out = "{0:<40} {1}".format(cap.name, cap.value)
                    if out.strip():
                        text_report += out + "\n"
            else:
                self.log.warning("No capabilities found")

        text_report += "\nKey: [X]: Supported, [ ]: Not supported"
        text_report += "\n* Reported client capabilities are dependent on available features at the time of client association."
        text_report += "\n** Reported channels do not factor local regulatory domain. Detected channel sets are assumed contiguous."
        return text_report

    def _extract_client_mac(self, packet: Dict) -> str:
        """Extract client MAC address from packet"""
        return packet.get("wlan", {}).get("wlan.sa", "Unknown")

    def _extract_bssid(self, packet: Dict) -> str:
        """Extract BSSID from packet"""
        return packet.get("wlan", {}).get("wlan.bssid", "Unknown")

    def _extract_channel(self, packet: Dict) -> str:
        """Extract frequency band from packet"""
        freq = int(packet.get("radiotap", {}).get("radiotap.channel.freq", 0))
        channel = _20MHZ_FREQUENCY_CHANNEL_MAP.get(freq, 0)
        return channel

    def _extract_frequency_band(self, packet: Dict) -> str:
        """Extract frequency band from packet"""
        freq = int(packet.get("radiotap", {}).get("radiotap.channel.freq", 0))
        if 2401 <= freq <= 2495:
            return "2"
        elif 5150 <= freq <= 5895:
            return "5"
        elif 5925 <= freq <= 7125:
            return "6"
        else:
            self.log.warning("Unable to extract capture frequency band")
            return "Unknown"

    def _extract_ap_manufacturer(self, packet: Dict) -> str:
        """Extract manufacturer from packet"""
        try:
            manuf = self.lookup.get_manuf(packet["wlan"]["wlan.ra_tree"]["wlan.ra"])
            if not manuf:
                return packet["wlan"]["wlan.ra_tree"]["wlan.ra.oui_resolved"]
            return manuf
        except (KeyError, TypeError):
            self.log.warning("Unable to extract AP manufacturer")
            return "Unknown"

    def _extract_manufacturer(self, packet: Dict) -> str:
        """Extract manufacturer from packet"""
        try:
            manuf = self.lookup.get_manuf(packet["wlan"]["wlan.sa"])
            if not manuf:
                return packet["wlan"]["wlan.sa_tree"]["wlan.sa.oui_resolved"]
            return manuf
        except (KeyError, TypeError):
            self.log.warning("Unable to extract client manufacturer")
            return "Unknown"

    def _extract_chipset(self, dot11_elt_dict: Dict) -> str:
        try:
            if 221 in dot11_elt_dict:
                vendor_tags = dot11_elt_dict[221]
                chipset = self._resolve_chipset_from_vendor_tags(vendor_tags)
                return chipset if chipset else "Unknown"
            else:
                self.log.debug("No vendor specific IE (221) found")
                return "Unknown"
        except (KeyError, TypeError) as e:
            self.log.warning(f"Unable to extract chipset: {str(e)}")
            return "Unknown"

    def _resolve_chipset_from_vendor_tags(self, vendor_tags: list) -> str:
        """Resolve chipset from vendor specific tags"""
        manufs = []
        low_quality = ["muratama"]
        sanitize = {
            "intelwir": "Intel",
            "intelcor": "Intel",
            "samsunge": "Samsung",
            "samsungelect": "Samsung",
        }

        for tag in vendor_tags:
            try:
                if "wlan.tag.oui" in tag:
                    oui_value = tag["wlan.tag.oui"]

                    oui_int = int(oui_value)
                    oui_formatted = "{0:02X}:{1:02X}:{2:02X}:00:00:00".format(
                        (oui_int >> 16) & 0xFF, (oui_int >> 8) & 0xFF, oui_int & 0xFF
                    )
                    manuf = self.lookup.get_manuf(oui_formatted)
                    if manuf and manuf.lower() in sanitize:
                        manuf = sanitize[manuf.lower()]
                    if manuf and not any(
                        manuf.lower().startswith(lq) for lq in low_quality
                    ):
                        manufs.append(manuf)
                        self.log.debug(
                            f"Found manufacturer: {manuf} from OUI: {oui_formatted}"
                        )
            except (ValueError, KeyError) as e:
                self.log.debug(f"Error processing vendor tag: {str(e)}")

        matches = ["broadcom", "qualcomm", "mediatek", "intel", "infineon"]
        for manuf in manufs:
            for match in matches:
                if manuf and manuf.lower().startswith(match):
                    return match.title()
        return None

    def _extract_ssid(self, packet: Dict) -> str:
        """Extract SSID from packet"""
        try:
            for tag in packet["wlan.mgt"]["wlan.tagged.all"]["wlan.tag"]:
                if isinstance(tag, dict) and tag.get("wlan.tag.number") == "0":
                    ssid_hex = tag.get("wlan.ssid", "")
                    # SSID is stored as hex string, convert to ASCII
                    ssid = bytes.fromhex(ssid_hex.replace(":", "")).decode(
                        "utf-8", errors="replace"
                    )
                    return ssid
            self.log.warning("Unable to extract SSID")
            return "Unknown"
        except (KeyError, TypeError, ValueError):
            self.log.warning("Unable to extract SSID")
            return "Unknown"

    def _extract_information_elements(self, packet: Dict) -> Dict:
        """Extract information elements from the packet"""
        dot11_elt_dict = {}

        try:
            # Make sure wlan.mgt exists
            if "wlan.mgt" not in packet:
                self.log.warning("No wlan.mgt found in packet")
                return dot11_elt_dict

            # Make sure wlan.tagged.all exists
            if "wlan.tagged.all" not in packet["wlan.mgt"]:
                self.log.warning("No wlan.tagged.all found in packet")
                return dot11_elt_dict

            tagged = packet["wlan.mgt"]["wlan.tagged.all"]

            # Process standard tags
            if "wlan.tag" in tagged:
                tags = tagged["wlan.tag"]
                # Make sure tags is a list
                if not isinstance(tags, list):
                    tags = [tags]

                for tag in tags:
                    tag_number = int(tag["wlan.tag.number"])

                    # Initialize a list for this tag number if it doesn't exist yet
                    if tag_number not in dot11_elt_dict:
                        dot11_elt_dict[tag_number] = []

                    # Append the tag to the list
                    dot11_elt_dict[tag_number].append(tag)

            # Process extended tag if present
            if "wlan.ext_tag" in tagged:
                ext_tags = tagged["wlan.ext_tag"]

                if IE_EXT_TAG not in dot11_elt_dict:
                    dot11_elt_dict[IE_EXT_TAG] = []

                if isinstance(ext_tags, list):
                    for ext_tag in ext_tags:
                        ext_tag_number = int(ext_tag["wlan.ext_tag.number"])
                        dot11_elt_dict[IE_EXT_TAG].append(
                            {"number": ext_tag_number, "data": ext_tag}
                        )
                else:
                    ext_tag_number = int(ext_tags["wlan.ext_tag.number"])
                    dot11_elt_dict[IE_EXT_TAG].append(
                        {"number": ext_tag_number, "data": ext_tags}
                    )

        except (KeyError, TypeError, ValueError) as e:
            self.log.error(f"Error extracting IEs: {str(e)}")

        return dot11_elt_dict

    def _get_bit(self, value: int, bit_position: int) -> int:
        """Get a specific bit from an integer value"""
        return (value >> bit_position) & 1

    def _analyze_ht_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Check for 802.11n support"""
        dot11n = Capability(
            name="802.11n", value="Not reported*", db_key="dot11n", db_value=-1
        )

        dot11n_nss = Capability(
            name="802.11n/NSS", value="Not reported*", db_key="dot11n_nss", db_value=-1
        )

        if HT_CAPABILITIES_IE_TAG in dot11_elt_dict:
            dot11n.value = "Supported"
            dot11n.db_value = 1

            try:
                # Get MCS set data
                ht_tag = dot11_elt_dict[HT_CAPABILITIES_IE_TAG][0]

                if "wlan.ht.mcsset" in ht_tag:
                    mcs_set = ht_tag["wlan.ht.mcsset"]

                    # Count MCS set bitmask for number of spatial streams
                    spatial_streams = 0

                    if "wlan.ht.mcsset.rxbitmask" in mcs_set:
                        bitmasks = [
                            "wlan.ht.mcsset.rxbitmask.0to7",
                            "wlan.ht.mcsset.rxbitmask.8to15",
                            "wlan.ht.mcsset.rxbitmask.16to23",
                            "wlan.ht.mcsset.rxbitmask.24to31",
                        ]

                        for bitmask in bitmasks:
                            if bitmask in mcs_set["wlan.ht.mcsset.rxbitmask"]:
                                if int(mcs_set["wlan.ht.mcsset.rxbitmask"][bitmask], 0):
                                    spatial_streams += 1

                    dot11n_nss.db_value = spatial_streams
                    dot11n_nss.value = spatial_streams
            except (KeyError, TypeError, ValueError) as e:
                self.log.debug(f"Error parsing HT capabilities: {str(e)}")

        return [dot11n, dot11n_nss]

    def _analyze_vht_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Check for 802.11ac support"""
        dot11ac = Capability(
            name="802.11ac", value="Not reported*", db_key="dot11ac", db_value=-1
        )

        dot11ac_nss = Capability(
            name="802.11ac/VHT NSS",
            value="Not reported*",
            db_key="dot11ac_nss",
            db_value=-1,
        )

        dot11ac_mcs = Capability(
            name="802.11ac/VHT MCS",
            value="Not reported*",
            db_key="dot11ac_mcs",
            db_value=-1,
        )

        dot11ac_su_bf = Capability(
            name="802.11ac/SU BF",
            value="Not reported*",
            db_key="dot11ac_su_bf",
            db_value=-1,
        )

        dot11ac_mu_bf = Capability(
            name="802.11ac/MU BF",
            value="Not reported*",
            db_key="dot11ac_mu_bf",
            db_value=-1,
        )

        dot11ac_bf_sts = Capability(
            name="802.11ac/BF STS",
            value="Not reported*",
            db_key="dot11ac_bf_sts",
            db_value=-1,
        )

        dot11ac_160_mhz = Capability(
            name="802.11ac/160 MHz",
            value="Not reported*",
            db_key="dot11ac_160_mhz",
            db_value=-1,
        )

        if VHT_CAPABILITIES_IE_TAG in dot11_elt_dict:
            dot11ac.value = "Supported"
            dot11ac.db_value = 1

            try:
                vht_tag = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][0]

                # Check for VHT MCS set
                if "wlan.vht.mcsset" in vht_tag:
                    mcs_set = vht_tag["wlan.vht.mcsset"]

                    # Extract NSS information
                    if "wlan.vht.mcsset.rxmcsmap_tree" in mcs_set:
                        rx_map = mcs_set["wlan.vht.mcsset.rxmcsmap_tree"]
                        nss = 0
                        mcs_values = []

                        # Check each spatial stream
                        for i in range(1, 9):  # Check SS1-SS8
                            ss_key = f"wlan.vht.mcsset.rxmcsmap.ss{i}"
                            if ss_key in rx_map:
                                ss_value = int(rx_map[ss_key], 0)
                                if ss_value != 3:  # 3 means not supported
                                    nss += 1
                                    if ss_value == 0:
                                        mcs_values.append("0-7")
                                    elif ss_value == 1:
                                        mcs_values.append("0-8")
                                    elif ss_value == 2:
                                        mcs_values.append("0-9")

                        mcs_values = sorted(set(mcs_values))
                        mcs_list = (
                            ", ".join(mcs_values)
                            if len(mcs_values) > 1
                            else mcs_values[0] if mcs_values else "Unknown"
                        )

                        dot11ac_nss.db_value = nss
                        dot11ac_mcs.db_value = mcs_list
                        dot11ac_nss.value = nss
                        dot11ac_mcs.value = mcs_list
                        # dot11ac.value = f"Supported ({nss}ss), MCS {mcs_list}"

                # Check for 160 MHz support
                if "wlan.vht.capabilities_tree" in vht_tag:
                    caps = vht_tag["wlan.vht.capabilities_tree"]

                    # Check for 160 MHz support
                    if "wlan.vht.capabilities.supportedchanwidthset" in caps:
                        chan_width = int(
                            caps["wlan.vht.capabilities.supportedchanwidthset"], 0
                        )
                        if chan_width & 0x2:  # Bit 1 indicates 160 MHz support
                            dot11ac_160_mhz.db_value = 1
                            dot11ac_160_mhz.value = 1
                            # dot11ac.value += ", [X] 160 MHz"
                        else:
                            # dot11ac.value += ", [ ] 160 MHz"
                            dot11ac_160_mhz.db_value = 0
                            dot11ac_160_mhz.value = 0

                    # Check for beamforming capabilities
                    if "wlan.vht.capabilities.subeamformer" in caps:
                        su_bf = int(caps["wlan.vht.capabilities.subeamformer"], 0)
                        if su_bf:
                            dot11ac_su_bf.db_value = 1
                            dot11ac_su_bf.value = 1
                            # dot11ac.value += ", [X] SU BF"
                        else:
                            # dot11ac.value += ", [ ] SU BF"
                            dot11ac_su_bf.db_value = 0
                            dot11ac_su_bf.value = 0

                    if "wlan.vht.capabilities.mubeamformer" in caps:
                        mu_bf = int(caps["wlan.vht.capabilities.mubeamformer"], 0)
                        if mu_bf:
                            dot11ac_mu_bf.db_value = 1
                            dot11ac_mu_bf.value = 1
                            # dot11ac.value += ", [X] MU BF"
                        else:
                            # dot11ac.value += ", [ ] MU BF"
                            dot11ac_mu_bf.db_value = 0
                            dot11ac_mu_bf.value = 0

                    if "wlan.vht.capabilities.beamformee_sts_cap" in caps:

                        bf_sts = int(
                            caps["wlan.vht.capabilities.beamformee_sts_cap"], 0
                        )
                        dot11ac_bf_sts.db_value = bf_sts
                        dot11ac_bf_sts.value = bf_sts
                        # dot11ac.value += f", Beamformee STS={bf_sts}"

            except (KeyError, TypeError, ValueError) as e:
                self.log.debug(f"Error parsing VHT capabilities: {str(e)}")

        return [
            dot11ac,
            dot11ac_nss,
            dot11ac_mcs,
            dot11ac_su_bf,
            dot11ac_mu_bf,
            dot11ac_bf_sts,
            dot11ac_160_mhz,
        ]

    def _analyze_rm_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Check for 802.11k support"""
        dot11k = Capability(
            name="802.11k", value="Not reported*", db_key="dot11k", db_value=-1
        )

        if RM_CAPABILITIES_IE_TAG in dot11_elt_dict:
            dot11k.value = "Supported"
            dot11k.db_value = 1

        return [dot11k]

    def _analyze_ft_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Check for 802.11r support"""
        dot11r = Capability(
            name="802.11r", value="Not reported*", db_key="dot11r", db_value=-1
        )

        if FT_CAPABILITIES_IE_TAG in dot11_elt_dict:
            dot11r.value = "Supported"
            dot11r.db_value = 1

        return [dot11r]

    def _analyze_ext_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Check for 802.11v support"""
        dot11v = Capability(
            name="802.11v", value="Not reported*", db_key="dot11v", db_value=-1
        )

        if EXT_CAPABILITIES_IE_TAG in dot11_elt_dict:
            ext_cap_tag = dot11_elt_dict[EXT_CAPABILITIES_IE_TAG][0]

            try:
                if "wlan.extcap_tree" in ext_cap_tag:
                    ext_caps = ext_cap_tag["wlan.extcap_tree"]

                    # BSS Transition (11v) is bit 19 in octet 2 (0-indexed)
                    octet2 = ext_caps[2] if len(ext_caps) > 2 else None
                    if octet2 and "wlan.extcap.b19" in octet2:
                        if octet2["wlan.extcap.b19"] == "1":
                            dot11v.value = "Supported"
                            dot11v.db_value = 1
            except (KeyError, TypeError, IndexError) as e:
                self.log.debug(f"Error parsing extended capabilities: {str(e)}")

        return [dot11v]

    def _analyze_rsn_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Check for 802.11w support"""
        dot11w = Capability(
            name="802.11w", value="Not reported*", db_key="dot11w", db_value=-1
        )

        if RSN_CAPABILITIES_IE_TAG in dot11_elt_dict:
            rsn_tag = dot11_elt_dict[RSN_CAPABILITIES_IE_TAG][0]

            try:
                if "wlan.rsn.capabilities_tree" in rsn_tag:
                    rsn_caps = rsn_tag["wlan.rsn.capabilities_tree"]

                    if "wlan.rsn.capabilities.mfpc" in rsn_caps:
                        if rsn_caps["wlan.rsn.capabilities.mfpc"] == "1":
                            dot11w.value = "Supported"
                            dot11w.db_value = 1
            except (KeyError, TypeError) as e:
                self.log.debug(f"Error parsing RSN capabilities: {str(e)}")

        return [dot11w]

    def _analyze_power_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Check for power capabilities"""
        max_power = Capability(
            name="Max Power", value="Not reported*", db_key="max_power", db_value=-1
        )

        min_power = Capability(
            name="Min Power", value="Not reported*", db_key="min_power", db_value=-1
        )

        if POWER_MIN_MAX_IE_TAG in dot11_elt_dict:
            power_tag = dot11_elt_dict[POWER_MIN_MAX_IE_TAG][0]

            try:
                if (
                    "wlan.powercap.min" in power_tag
                    and "wlan.powercap.max" in power_tag
                ):
                    min_val = int(power_tag["wlan.powercap.min"])
                    max_val = int(power_tag["wlan.powercap.max"])

                    # Min power might be signed
                    if min_val > 127:
                        min_val = (256 - min_val) * (-1)

                    max_power.value = f"{max_val} dBm"
                    max_power.db_value = max_val
                    min_power.value = f"{min_val} dBm"
                    min_power.db_value = min_val
            except (KeyError, TypeError, ValueError) as e:
                self.log.debug(f"Error parsing power capabilities: {str(e)}")

        return [max_power, min_power]

    def _analyze_supported_channels(
        self, dot11_elt_dict: Dict, is_6ghz: bool
    ) -> List[Capability]:
        """Check supported channels"""
        supported_channels = Capability(
            name="Supported Channels",
            value="Not reported*",
            db_key="supported_channels",
            db_value=[],
        )

        num_channels = Capability(
            name="Number of Channels", value="0", db_key="num_channels", db_value=-1
        )

        if SUPPORTED_CHANNELS_IE_TAG in dot11_elt_dict:
            try:
                channel_tag = dot11_elt_dict[SUPPORTED_CHANNELS_IE_TAG][0]
                channel_list = []

                # Format 1: wlan.supchan format
                if "wlan.supchan" in channel_tag:
                    supchan = channel_tag["wlan.supchan"]

                    if not isinstance(supchan, list):
                        supchan = [supchan]

                    has_2ghz = False
                    has_5ghz = False

                    for chanset in supchan:
                        try:
                            start_channel = int(chanset["wlan.supchan.first"])
                            channel_range = int(chanset["wlan.supchan.range"])

                            if start_channel > 14 or is_6ghz:
                                channel_multiplier = 4
                                if start_channel <= 14 and is_6ghz:
                                    has_5ghz = True
                                else:
                                    has_5ghz = True
                            else:
                                has_2ghz = True
                                channel_multiplier = 1

                            for i in range(channel_range):
                                channel_list.append(
                                    start_channel + (i * channel_multiplier)
                                )
                        except (KeyError, TypeError, ValueError) as e:
                            self.log.debug(
                                f"Error processing channel set: {e}, chanset type: {type(chanset)}"
                            )

                # Format 2: ap_channel_report format
                if "wlan.ap_channel_report.channel_list" in channel_tag:
                    channel_list_raw = channel_tag[
                        "wlan.ap_channel_report.channel_list"
                    ]
                    # Handle both string and list formats
                    if isinstance(channel_list_raw, list):
                        for channel in channel_list_raw:
                            channel_list.append(int(channel))
                    else:
                        # Single channel
                        channel_list.append(int(channel_list_raw))

                if channel_list:
                    channel_list.sort()
                    num_channels.value = str(len(channel_list))
                    num_channels.db_value = len(channel_list)
                    if is_6ghz and len(channel_list) > 10:
                        min_channel = min(channel_list)
                        max_channel = max(channel_list)
                        supported_channels.value = f"{min_channel}-{max_channel}**"
                        supported_channels.db_value = channel_list
                    else:
                        has_2ghz = any(ch <= 14 for ch in channel_list)
                        has_5ghz = any(ch > 14 for ch in channel_list)
                        mixed_bands = has_2ghz and has_5ghz

                        ranges = []
                        placeholder = []

                        for index, channel in enumerate(channel_list):
                            if index == 0:
                                placeholder.append(channel)
                                continue

                            if mixed_bands:
                                if channel <= 14:
                                    current_multiplier = 1
                                else:
                                    current_multiplier = 4

                                prev_channel = placeholder[-1]
                                if prev_channel <= 14:
                                    prev_multiplier = 1
                                else:
                                    prev_multiplier = 4

                                if (prev_channel <= 14 and channel > 14) or (
                                    prev_channel > 14 and channel <= 14
                                ):
                                    expected_gap = None
                                else:
                                    expected_gap = prev_multiplier
                            else:
                                if channel > 14 or is_6ghz:
                                    current_multiplier = 4
                                else:
                                    current_multiplier = 1
                                expected_gap = current_multiplier

                            if (
                                expected_gap
                                and channel - placeholder[-1] == expected_gap
                            ):
                                placeholder.append(channel)
                            else:
                                if placeholder:
                                    ranges.append(placeholder)
                                placeholder = [channel]

                        if placeholder and placeholder not in ranges:
                            ranges.append(placeholder)

                        channel_ranges = []
                        for _range in ranges:
                            if len(_range) > 1:
                                channel_ranges.append(f"{_range[0]}-{_range[-1]}")
                            else:
                                channel_ranges.append(str(_range[0]))

                        supported_channels.value = f"{', '.join(channel_ranges)}**"
                        supported_channels.db_value = channel_list

            except (KeyError, TypeError, ValueError, IndexError) as e:
                self.log.debug(f"Error parsing supported channels: {str(e)}")
                supported_channels.value = "Error parsing supported channels"
                num_channels.value = "Error"

        return [supported_channels, num_channels]

    def _analyze_he_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Check for 802.11ax support and capabilities"""
        dot11ax = Capability(
            name="802.11ax", value="Not supported", db_key="dot11ax", db_value=-1
        )

        dot11ax_nss = Capability(
            name="802.11ax/HE NSS",
            value="Not reported*",
            db_key="dot11ax_nss",
            db_value=-1,
        )

        dot11ax_mcs = Capability(
            name="802.11ax/HE MCS",
            value="Not reported*",
            db_key="dot11ax_mcs",
            db_value=-1,
        )

        # Additional 802.11ax capabilities
        dot11ax_punctured_preamble = Capability(
            name="802.11ax/Punctured Preamble",
            value="Not reported*",
            db_key="dot11ax_punctured_preamble",
            db_value=-1,
        )
        dot11ax_he_su_beamformee = Capability(
            name="802.11ax/SU BF",
            value="Not reported*",
            db_key="dot11ax_he_su_beamformee",
            db_value=-1,
        )
        dot11ax_he_beamformee_sts = Capability(
            name="802.11ax/BF STS",
            value="Not reported*",
            db_key="dot11ax_he_beamformee_sts",
            db_value=-1,
        )
        dot11ax_twt = Capability(
            name="802.11ax/TWT",
            value="Not reported*",
            db_key="dot11ax_twt",
            db_value=-1,
        )
        dot11ax_bsr = Capability(
            name="802.11ax/BSR",
            value="Not reported*",
            db_key="dot11ax_bsr",
            db_value=-1,
        )
        dot11ax_he_er_su_ppdu = Capability(
            name="802.11ax/ER SU PPDU",
            value="Not reported*",
            db_key="dot11ax_he_er_su_ppdu",
            db_value=-1,
        )
        dot11ax_spatial_reuse = Capability(
            name="802.11ax/Spatial Reuse",
            value="Not reported*",
            db_key="dot11ax_spatial_reuse",
            db_value=-1,
        )
        dot11ax_160_mhz = Capability(
            name="802.11ax/160 MHz",
            value="Not reported*",
            db_key="dot11ax_160_mhz",
            db_value=-1,
        )
        dot11ax_six_ghz = Capability(
            name="802.11ax/6 GHz",
            value="Not reported*",
            db_key="dot11ax_six_ghz",
            db_value=-1,
        )

        # Check for HE capabilities in extended tags
        if IE_EXT_TAG in dot11_elt_dict:
            for ext_tag in dot11_elt_dict[IE_EXT_TAG]:
                if ext_tag["number"] == HE_CAPABILITIES_IE_EXT_TAG:
                    dot11ax.value = "Supported"
                    dot11ax.db_value = 1

                    try:
                        tag_data = ext_tag["data"]

                        # Process HE MAC capabilities
                        if "wlan.ext_tag.he_mac_caps_tree" in tag_data:
                            mac_caps = tag_data["wlan.ext_tag.he_mac_caps_tree"]

                            # Check for TWT support
                            if "wlan.ext_tag.he_mac_cap.twt_req_support" in mac_caps:
                                if (
                                    mac_caps["wlan.ext_tag.he_mac_cap.twt_req_support"]
                                    == "1"
                                ):
                                    dot11ax_twt.db_value = 1
                                    dot11ax_twt.value = "Yes"
                                    # dot11ax.value += ", [X] TWT"
                                else:
                                    # dot11ax.value += ", [ ] TWT"
                                    dot11ax_twt.db_value = 0
                                    dot11ax_twt.value = "No"

                            # Check for BSR support
                            if "wlan.ext_tag.he_mac_cap.bsr_support" in mac_caps:
                                if (
                                    mac_caps["wlan.ext_tag.he_mac_cap.bsr_support"]
                                    == "1"
                                ):
                                    dot11ax_bsr.db_value = 1
                                    dot11ax_bsr.value = "Yes"
                                    # dot11ax.value += ", [X] BSR"
                                else:
                                    # dot11ax.value += ", [ ] BSR"
                                    dot11ax_bsr.db_value = 0
                                    dot11ax_bsr.value = "No"

                        # Process HE PHY capabilities
                        if "HE PHY Capabilities Information" in tag_data:
                            phy_caps = tag_data["HE PHY Capabilities Information"]

                            # wlan.ext_tag.he_phy_cap.chan_width_set.160_in_5ghz

                            # Check for 160 MHz support
                            if "wlan.ext_tag.he_phy_cap.fbytes_tree" in phy_caps:
                                chan_width = phy_caps[
                                    "wlan.ext_tag.he_phy_cap.fbytes_tree"
                                ]
                                if (
                                    "wlan.ext_tag.he_phy_cap.chan_width_set.160_in_5ghz"
                                    in chan_width
                                ):
                                    if (
                                        chan_width[
                                            "wlan.ext_tag.he_phy_cap.chan_width_set.160_in_5ghz"
                                        ]
                                        == "1"
                                    ):
                                        dot11ax_160_mhz.db_value = 1
                                        dot11ax_160_mhz.value = "Yes"
                                        # dot11ax.value += ", [X] 160 MHz"
                                    else:
                                        # dot11ax.value += ", [ ] 160 MHz"
                                        dot11ax_160_mhz.db_value = 0
                                        dot11ax_160_mhz.value = "No"

                            # Check for punctured preamble support
                            if "wlan.ext_tag.he_phy_cap.bits_8_to_23_tree" in phy_caps:
                                punc_bits = phy_caps[
                                    "wlan.ext_tag.he_phy_cap.bits_8_to_23_tree"
                                ]
                                if (
                                    "wlan.ext_tag.he_phy_cap.punc_preamble_rx"
                                    in punc_bits
                                ):
                                    punc_val = int(
                                        punc_bits[
                                            "wlan.ext_tag.he_phy_cap.punc_preamble_rx"
                                        ],
                                        0,
                                    )
                                    if punc_val > 0:
                                        dot11ax_punctured_preamble.db_value = 1
                                        dot11ax_punctured_preamble.value = "Yes"
                                        # dot11ax.value += ", [X] Punctured Preamble"
                                    else:
                                        # dot11ax.value += ", [ ] Punctured Preamble"
                                        dot11ax_punctured_preamble.db_value = 0
                                        dot11ax_punctured_preamble.value = "No"

                            # Check for beamforming capabilities
                            if "wlan.ext_tag.he_phy_cap.bits_24_to_39_tree" in phy_caps:
                                bf_bits = phy_caps[
                                    "wlan.ext_tag.he_phy_cap.bits_24_to_39_tree"
                                ]

                                if "wlan.ext_tag.he_phy_cap.su_beamformee" in bf_bits:
                                    if (
                                        bf_bits["wlan.ext_tag.he_phy_cap.su_beamformee"]
                                        == "1"
                                    ):
                                        dot11ax_he_su_beamformee.db_value = 1
                                        dot11ax_he_su_beamformee.value = "Yes"
                                        # dot11ax.value += ", [X] SU Beamformee"
                                    else:
                                        # dot11ax.value += ", [ ] SU Beamformee"
                                        dot11ax_he_su_beamformee.db_value = 0
                                        dot11ax_he_su_beamformee.value = "No"

                                # Beamformee STS (for ≤ 80 MHz)
                                bf_sts = 0
                                if (
                                    "wlan.ext_tag.he_phy_cap.beamformee_sts_lte_80mhz"
                                    in bf_bits
                                ):
                                    bf_sts = int(
                                        bf_bits[
                                            "wlan.ext_tag.he_phy_cap.beamformee_sts_lte_80mhz"
                                        ],
                                        0,
                                    )
                                dot11ax_he_beamformee_sts.db_value = bf_sts
                                dot11ax_he_beamformee_sts.value = bf_sts
                                # dot11ax.value += f", Beamformee STS={bf_sts}"

                        # Process HE MCS capabilities
                        if "Supported HE-MCS and NSS Set" in tag_data:
                            mcs_caps = tag_data["Supported HE-MCS and NSS Set"]

                            # Process 80 MHz MCS capabilities
                            if "Rx and Tx MCS Maps <= 80 MHz" in mcs_caps:
                                mcs_80 = mcs_caps["Rx and Tx MCS Maps <= 80 MHz"]

                                if (
                                    "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_lte_80_tree"
                                    in mcs_80
                                ):
                                    rx_map = mcs_80[
                                        "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_lte_80_tree"
                                    ]
                                    nss = 0
                                    mcs_values = []

                                    # Check each spatial stream
                                    for i in range(1, 9):  # Check SS1-SS8
                                        ss_key = f"wlan.ext_tag.he_mcs_map.max_he_mcs_80_rx_{i}_ss"
                                        if ss_key in rx_map:
                                            ss_value = int(rx_map[ss_key], 0)
                                            if ss_value != 3:  # 3 means not supported
                                                nss += 1
                                                if ss_value == 0:
                                                    mcs_values.append("0-7")
                                                elif ss_value == 1:
                                                    mcs_values.append("0-9")
                                                elif ss_value == 2:
                                                    mcs_values.append("0-11")

                                    mcs_values = sorted(set(mcs_values))
                                    mcs_list = (
                                        ", ".join(mcs_values)
                                        if len(mcs_values) > 1
                                        else mcs_values[0] if mcs_values else "Unknown"
                                    )

                                    dot11ax_nss.db_value = nss
                                    dot11ax_nss.value = nss
                                    dot11ax_mcs.db_value = mcs_list
                                    dot11ax_mcs.value = mcs_list
                                    # if not dot11ax.value.startswith("Supported ("):
                                    #     dot11ax.value = (
                                    #         f"Supported ({nss}ss), MCS {mcs_list}"
                                    #         + dot11ax.value[9:]
                                    #     )

                    except (KeyError, TypeError, ValueError) as e:
                        self.log.debug(f"Error parsing HE capabilities: {str(e)}")
                        dot11ax_nss.db_value = -2
                        dot11ax_mcs.db_value = -2
                        if not "ss" in dot11ax.value:
                            dot11ax.value = f"Supported ({dot11ax_nss.db_value}ss), MCS {dot11ax_mcs.db_value}"

                # Check for spatial reuse parameter set
                elif ext_tag["number"] == HE_SPATIAL_REUSE_IE_EXT_TAG:
                    dot11ax_spatial_reuse.db_value = 1

                # Check for 6 GHz band capabilities
                elif ext_tag["number"] == HE_6_GHZ_BAND_CAP_IE_EXT_TAG:
                    dot11ax_six_ghz.db_value = 1
                    dot11ax_six_ghz.name = "6 GHz Capability"
                    dot11ax_six_ghz.value = "Supported"

        return [
            dot11ax,
            dot11ax_nss,
            dot11ax_mcs,
            dot11ax_twt,
            dot11ax_bsr,
            dot11ax_punctured_preamble,
            dot11ax_he_su_beamformee,
            dot11ax_he_beamformee_sts,
            dot11ax_he_er_su_ppdu,
            dot11ax_six_ghz,
            dot11ax_160_mhz,
            dot11ax_spatial_reuse,
        ]

    def _analyze_rsnx_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Check for RSNX capabilities, including SAE Hash-to-Element"""
        sae_h2e = Capability(
            name="RSNX H2E", value="No", db_key="rsnx_sae_h2e", db_value=-1
        )

        if RSNX_TAG in dot11_elt_dict:
            rsnx_tag = dot11_elt_dict[RSNX_TAG][0]
            try:
                if "wlan.rsnx_tree" in rsnx_tag:
                    rsnx_tree = rsnx_tag["wlan.rsnx_tree"]
                    if (
                        "wlan.rsnx.sae_hash_to_element" in rsnx_tree
                        and rsnx_tree["wlan.rsnx.sae_hash_to_element"] == "1"
                    ):
                        sae_h2e.value = "Yes"
                        sae_h2e.db_value = 1
            except (KeyError, TypeError) as e:
                self.log.debug(f"Error parsing RSNX capabilities: {str(e)}")

        return [sae_h2e]

    def _analyze_6ghz_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Parse 6 GHz specific capabilities"""
        sm_power_save = Capability(
            name="802.11ax/HE 6 GHz SM Power Save",
            value="No",
            db_key="dot11ax_6ghz_sm_power_save",
            db_value=-1,
        )

        # Extended tags - look for HE 6 GHz band capabilities
        if IE_EXT_TAG in dot11_elt_dict:
            for ext_tag in dot11_elt_dict[IE_EXT_TAG]:
                if ext_tag["number"] == HE_6_GHZ_BAND_CAP_IE_EXT_TAG:
                    try:
                        tag_data = ext_tag["data"]
                        if "wlan.tag.he_6ghz.cap_inf_tree" in tag_data:
                            cap_inf = tag_data["wlan.tag.he_6ghz.cap_inf_tree"]
                            if "wlan.tag.he_6ghz.cap_inf.b9b_b10" in cap_inf:
                                sm_ps_value = int(
                                    cap_inf["wlan.tag.he_6ghz.cap_inf.b9b_b10"], 0
                                )
                                if sm_ps_value > 0:
                                    sm_power_save.value = "Yes"
                                    sm_power_save.db_value = sm_ps_value
                    except (KeyError, TypeError, ValueError) as e:
                        self.log.debug(f"Error parsing 6 GHz capabilities: {str(e)}")

        return [sm_power_save]

    def _analyze_multi_link_capabilities(
        self, dot11_elt_dict: Dict
    ) -> List[Capability]:
        """Parse Multi-Link Control (MLC) capabilities"""
        capabilities = []

        # MLE
        mle = Capability(
            name="802.11be/MLE (Multi-Link Element)",
            value="Not reported*",
            db_key="dot11be_mle",
            db_value=-1,
        )

        # MLC Type
        mlc_type = Capability(
            name="802.11be/MLE/MLC Type",
            value="Not reported*",
            db_key="dot11be_mle_mlc_type",
            db_value=-1,
        )

        # EMLSR Support
        emlsr_support = Capability(
            name="802.11be/MLE/EMLSR",
            value="Not reported*",
            db_key="dot11be_mle_emlsr_support",
            db_value=-1,
        )

        # EMLSR Padding Delay
        emlsr_padding_delay = Capability(
            name="802.11be/MLE/EMLSR Padding Delay",
            value="Not reported*",
            db_key="dot11be_mle_emlsr_padding_delay",
            db_value=-1,
        )

        # EMLSR Transition Delay
        emlsr_transition_delay = Capability(
            name="802.11be/MLE/EMLSR Transition Delay",
            value="Not reported*",
            db_key="dot11be_mle_emlsr_transition_delay",
            db_value=-1,
        )

        # EMLMR Support
        emlmr_support = Capability(
            name="802.11be/MLE/EMLMR",
            value="Not reported*",
            db_key="dot11be_mle_emlmr_support",
            db_value=-1,
        )

        # Max Simultaneous Links
        max_simultaneous_links = Capability(
            name="802.11be/MLE/Max Sim. Links",
            value="Not reported*",
            db_key="dot11be_mle_max_simultaneous_links",
            db_value=-1,
        )

        # T2LM Negotiation Support
        t2lm_negotiation_support = Capability(
            name="802.11be/MLE/T2LM Negot. Spt.",
            value="Not reported*",
            db_key="dot11be_mle_t2lm_negotiation_support",
            db_value=-1,
        )

        # Link Reconfiguration Operation Support
        link_reconfig_support = Capability(
            name="802.11be/MLE/Link Reconf Oper. Spt.",
            value="Not reported*",
            db_key="dot11be_mle_link_reconfig_support",
            db_value=-1,
        )

        # Extended tags - look for Multi-Link Element
        if IE_EXT_TAG in dot11_elt_dict:
            for ext_tag in dot11_elt_dict[IE_EXT_TAG]:
                if ext_tag["number"] == MLE_EXT_TAG:
                    mle.value = "Present"
                    mle.db_value = 1
                    try:
                        tag_data = ext_tag["data"]

                        # Parse MLC Type
                        if "wlan.eht.multi_link.control_tree" in tag_data:
                            mlc_control = tag_data["wlan.eht.multi_link.control_tree"]
                            type_value = 0
                            if "wlan.eht.multi_link.control.type" in mlc_control:
                                type_value = int(
                                    mlc_control["wlan.eht.multi_link.control.type"], 0
                                )
                            mlc_type.value = str(type_value)
                            mlc_type.db_value = type_value

                        # Parse Common Info section
                        if "Common Info" in tag_data:
                            common_info = tag_data["Common Info"]

                            # Parse EML Capabilities
                            if (
                                "wlan.eht.multi_link.common_info.eml_capabilities_tree"
                                in common_info
                            ):
                                eml_caps = common_info[
                                    "wlan.eht.multi_link.common_info.eml_capabilities_tree"
                                ]

                                # EMLSR Support
                                if (
                                    "wlan.eht.multi_link.common_info.eml_capabilities.emlsr_support"
                                    in eml_caps
                                ):
                                    if (
                                        eml_caps[
                                            "wlan.eht.multi_link.common_info.eml_capabilities.emlsr_support"
                                        ]
                                        == "1"
                                    ):
                                        emlsr_support.value = "Yes"
                                        emlsr_support.db_value = 1
                                    else:
                                        emlsr_support.value = "No"
                                        emlsr_support.db_value = 0

                                # EMLSR Padding Delay
                                padding_value = 0
                                if (
                                    "wlan.eht.multi_link.common_info.eml_capabilities.emlsr_padding_delay"
                                    in eml_caps
                                ):
                                    padding_value = int(
                                        eml_caps[
                                            "wlan.eht.multi_link.common_info.eml_capabilities.emlsr_padding_delay"
                                        ],
                                        0,
                                    )
                                emlsr_padding_delay.value = str(padding_value)
                                emlsr_padding_delay.db_value = padding_value

                                # EMLSR Transition Delay
                                transition_value = 0
                                if (
                                    "wlan.eht.multi_link.common_info.eml_capabilities.emlsr_transition_delay"
                                    in eml_caps
                                ):
                                    transition_value = int(
                                        eml_caps[
                                            "wlan.eht.multi_link.common_info.eml_capabilities.emlsr_transition_delay"
                                        ],
                                        0,
                                    )
                                emlsr_transition_delay.value = str(transition_value)
                                emlsr_transition_delay.db_value = transition_value

                                # EMLMR Support
                                if (
                                    "wlan.eht.multi_link.common_info.eml_capabilities.emlmr_support"
                                    in eml_caps
                                ):
                                    if (
                                        eml_caps[
                                            "wlan.eht.multi_link.common_info.eml_capabilities.emlmr_support"
                                        ]
                                        == "1"
                                    ):
                                        emlmr_support.value = "Yes"
                                        emlmr_support.db_value = 1
                                    else:
                                        emlmr_support.value = "No"
                                        emlmr_support.db_value = 0

                            # Parse MLD Capabilities
                            if (
                                "wlan.eht.multi_link.common_info.mld_capabilities_tree"
                                in common_info
                            ):
                                mld_caps = common_info[
                                    "wlan.eht.multi_link.common_info.mld_capabilities_tree"
                                ]

                                # Max Simultaneous Links
                                links_value = 0
                                if (
                                    "wlan.eht.multi_link.common_info.mld_capabilities.max_simultaneous_links"
                                    in mld_caps
                                ):
                                    links_value = int(
                                        mld_caps[
                                            "wlan.eht.multi_link.common_info.mld_capabilities.max_simultaneous_links"
                                        ],
                                        0,
                                    )
                                max_simultaneous_links.value = str(links_value)
                                max_simultaneous_links.db_value = links_value

                                # T2LM Negotiation Support
                                t2lm_value = 0
                                if (
                                    "wlan.eht.multi_link.common_info.mld_capabilities.tid_to_link_neg_sup"
                                    in mld_caps
                                ):
                                    t2lm_value = int(
                                        mld_caps[
                                            "wlan.eht.multi_link.common_info.mld_capabilities.tid_to_link_neg_sup"
                                        ],
                                        0,
                                    )
                                t2lm_negotiation_support.value = str(t2lm_value)
                                t2lm_negotiation_support.db_value = t2lm_value

                                # Link Reconfiguration Operation Support
                                if (
                                    "wlan.eht.multi_link.common_info.mld_capabilities.link_reconfig_op_support"
                                    in mld_caps
                                ):
                                    if (
                                        mld_caps[
                                            "wlan.eht.multi_link.common_info.mld_capabilities.link_reconfig_op_support"
                                        ]
                                        == "1"
                                    ):
                                        link_reconfig_support.value = "Yes"
                                        link_reconfig_support.db_value = 1
                                    else:
                                        link_reconfig_support.value = "No"
                                        link_reconfig_support.db_value = 0

                    except (KeyError, TypeError, ValueError) as e:
                        self.log.debug(
                            f"Error parsing Multi-Link capabilities: {str(e)}"
                        )

        capabilities.extend(
            [
                mle,
                mlc_type,
                emlsr_support,
                emlsr_padding_delay,
                emlsr_transition_delay,
                emlmr_support,
                max_simultaneous_links,
                t2lm_negotiation_support,
                link_reconfig_support,
            ]
        )

        return capabilities

    def _analyze_eht_capabilities(self, dot11_elt_dict: Dict) -> List[Capability]:
        """Check for 802.11be/EHT support and capabilities"""
        capabilities = []

        # Basic EHT support
        eht_support = Capability(
            name="802.11be", value="Not supported", db_key="dot11be", db_value=-1
        )

        # EPCS Support
        epcs_support = Capability(
            name="802.11be/EPCS Support",
            value="No",
            db_key="dot11be_epcs_support",
            db_value=-1,
        )

        # EHT OM Control Support
        eht_om_support = Capability(
            name="802.11be/EHT OM Ctrl. Spt.",
            value="No",
            db_key="dot11be_om_support",
            db_value=-1,
        )

        # R-TWT Support
        rtwt_support = Capability(
            name="802.11be/R-TWT Support",
            value="No",
            db_key="dot11be_rtwt_support",
            db_value=-1,
        )

        # SCS Traffic Description Support
        scs_support = Capability(
            name="802.11be/SCS Traffic Desc.",
            value="No",
            db_key="dot11be_scs_support",
            db_value=-1,
        )

        # 320 MHz Support
        support_320mhz = Capability(
            name="802.11be/320 MHz support (6G)",
            value="No",
            db_key="dot11be_320mhz",
            db_value=-1,
        )

        # MCS 14 Support (EHT Duplicate 6 GHz)
        mcs14_support = Capability(
            name="802.11be/MCS 14",
            value="No",
            db_key="dot11be_mcs14_support",
            db_value=-1,
        )

        # MCS 15 Support
        mcs15_support = Capability(
            name="802.11be/MCS 15",
            value="No",
            db_key="dot11be_mcs15_support",
            db_value=-1,
        )

        eht_nss = Capability(
            name="802.11be/EHT SS",
            value="Not reported*",
            db_key="dot11be_nss",
            db_value=-1,
        )

        eht_mcs = Capability(
            name="802.11be/EHT MCS",
            value="Not reported*",
            db_key="dot11be_mcs",
            db_value=-1,
        )

        # Check for EHT capabilities in extended tags
        if IE_EXT_TAG in dot11_elt_dict:
            for ext_tag in dot11_elt_dict[IE_EXT_TAG]:
                if ext_tag["number"] == EHT_CAPABILITIES_IE_EXT_TAG:
                    eht_support.value = "Supported"
                    eht_support.db_value = 1

                    try:
                        tag_data = ext_tag["data"]

                        # Parse MAC capabilities
                        if "wlan.eht.mac_capabilities_info_tree" in tag_data:
                            mac_caps = tag_data["wlan.eht.mac_capabilities_info_tree"]

                            # EPCS Support
                            if (
                                "wlan.eht.mac_capabilities.epcs_priority_access_support"
                                in mac_caps
                            ):
                                if (
                                    mac_caps[
                                        "wlan.eht.mac_capabilities.epcs_priority_access_support"
                                    ]
                                    == "1"
                                ):
                                    epcs_support.value = "Yes"
                                    epcs_support.db_value = 1
                                else:
                                    epcs_support.value = "No"
                                    epcs_support.db_value = 0

                            # EHT OM Control Support
                            if (
                                "wlan.eht.mac_capabilities.eht_om_control_support"
                                in mac_caps
                            ):
                                if (
                                    mac_caps[
                                        "wlan.eht.mac_capabilities.eht_om_control_support"
                                    ]
                                    == "1"
                                ):
                                    eht_om_support.value = "Yes"
                                    eht_om_support.db_value = 1
                                else:
                                    eht_om_support.value = "No"
                                    eht_om_support.db_value = 0

                            # R-TWT Support
                            if (
                                "wlan.eht.mac_capabilities.restricted_twt_support"
                                in mac_caps
                            ):
                                if (
                                    mac_caps[
                                        "wlan.eht.mac_capabilities.restricted_twt_support"
                                    ]
                                    == "1"
                                ):
                                    rtwt_support.value = "Yes"
                                    rtwt_support.db_value = 1
                                else:
                                    rtwt_support.value = "No"
                                    rtwt_support.db_value = 0

                            # SCS Traffic Description Support
                            if (
                                "wlan.eht.mac_capabilities.scs_traffic_description_support"
                                in mac_caps
                            ):
                                if (
                                    mac_caps[
                                        "wlan.eht.mac_capabilities.scs_traffic_description_support"
                                    ]
                                    == "1"
                                ):
                                    scs_support.value = "Yes"
                                    scs_support.db_value = 1
                                else:
                                    scs_support.value = "No"
                                    scs_support.db_value = 0

                        # Parse PHY capabilities
                        if "EHT PHY Capabilities Information" in tag_data:
                            phy_caps = tag_data["EHT PHY Capabilities Information"]

                            # 320 MHz Support
                            if "wlan.eht.phy_capabilities.bits_0_15_tree" in phy_caps:
                                bits_0_15 = phy_caps[
                                    "wlan.eht.phy_capabilities.bits_0_15_tree"
                                ]
                                if (
                                    "wlan.eht.phy_capabilities.bits_0_15.support_for_320mhz_in_6ghz"
                                    in bits_0_15
                                ):
                                    if (
                                        bits_0_15[
                                            "wlan.eht.phy_capabilities.bits_0_15.support_for_320mhz_in_6ghz"
                                        ]
                                        == "1"
                                    ):
                                        support_320mhz.value = "Yes"
                                        support_320mhz.db_value = 1
                                    else:
                                        support_320mhz.value = "No"
                                        support_320mhz.db_value = 0

                            # MCS 14/15 Support
                            if "wlan.eht.phy_capabilities.bits_40_63_tree" in phy_caps:
                                bits_40_63 = phy_caps[
                                    "wlan.eht.phy_capabilities.bits_40_63_tree"
                                ]

                                # MCS 15 Support
                                if (
                                    "wlan.eht.phy_capabilities.bits_40_63.support_of_mcs_15"
                                    in bits_40_63
                                ):
                                    if (
                                        bits_40_63[
                                            "wlan.eht.phy_capabilities.bits_40_63.support_of_mcs_15"
                                        ]
                                        == "1"
                                    ):
                                        mcs15_support.value = "Yes"
                                        mcs15_support.db_value = 1
                                    else:
                                        mcs15_support.value = "No"
                                        mcs15_support.db_value = 0

                                # MCS 14 Support (EHT Duplicate 6 GHz)
                                if (
                                    "wlan.eht.phy_capabilities.bits_40_63.support_eht_dup_6_ghz"
                                    in bits_40_63
                                ):
                                    if (
                                        bits_40_63[
                                            "wlan.eht.phy_capabilities.bits_40_63.support_eht_dup_6_ghz"
                                        ]
                                        == "1"
                                    ):
                                        mcs14_support.value = "Yes"
                                        mcs14_support.db_value = 1
                                    else:
                                        mcs14_support.value = "No"
                                        mcs14_support.db_value = 0

                        # Parse MCS and NSS sets
                        if "Supported EHT-MCS and NSS Set" in tag_data:
                            mcs_sets = tag_data["Supported EHT-MCS and NSS Set"]

                            nss_80 = 0
                            nss_160 = 0
                            nss_320 = 0
                            if (
                                "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_le_80_mhz_tree"
                                in mcs_sets
                            ):
                                mcs_80 = mcs_sets[
                                    "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_le_80_mhz_tree"
                                ]
                                nss_80 = 0
                                mcs_ranges_80 = []

                                # MCS 0-9
                                rx_mcs_0_9 = int(
                                    mcs_80.get(
                                        "wlan.eht.supported_eht_mcs_bss_set.le_80.rx_max_nss_supports_eht_mcs_0_9",
                                        "0",
                                    ),
                                    0,
                                )
                                if rx_mcs_0_9 > 0:
                                    nss_80 += rx_mcs_0_9
                                    mcs_ranges_80.extend(["0-9"] * rx_mcs_0_9)

                                # MCS 10-11
                                rx_mcs_10_11 = int(
                                    mcs_80.get(
                                        "wlan.eht.supported_eht_mcs_bss_set.le_80.rx_max_nss_supports_eht_mcs_10_11",
                                        "0",
                                    ),
                                    0,
                                )
                                if rx_mcs_10_11 > 0:
                                    nss_80 = max(nss_80, rx_mcs_10_11)
                                    mcs_ranges_80.extend(["10-11"] * rx_mcs_10_11)

                                # MCS 12-13
                                rx_mcs_12_13 = int(
                                    mcs_80.get(
                                        "wlan.eht.supported_eht_mcs_bss_set.le_80.rx_max_nss_supports_eht_mcs_12_13",
                                        "0",
                                    ),
                                    0,
                                )
                                if rx_mcs_12_13 > 0:
                                    nss_80 = max(nss_80, rx_mcs_12_13)
                                    mcs_ranges_80.extend(["12-13"] * rx_mcs_12_13)

                                mcs_ranges_80 = sorted(set(mcs_ranges_80))
                                mcs_list_80 = (
                                    ", ".join(mcs_ranges_80)
                                    if len(mcs_ranges_80) > 1
                                    else (
                                        mcs_ranges_80[0] if mcs_ranges_80 else "Unknown"
                                    )
                                )

                                eht_mcs.value = f"MCS {mcs_list_80}"
                                eht_nss.value = f"{nss_80}ss"

                            # 160 MHz MCS/NSS - following same pattern
                            if (
                                "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_eq_160_mhz_tree"
                                in mcs_sets
                            ):
                                mcs_160 = mcs_sets[
                                    "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_eq_160_mhz_tree"
                                ]
                                mcs_ranges_160 = []

                                # MCS 0-9
                                rx_mcs_0_9 = int(
                                    mcs_160.get(
                                        "wlan.eht.supported_eht_mcs_bss_set.160.rx_max_nss_supports_eht_mcs_0_9",
                                        "0",
                                    ),
                                    0,
                                )
                                if rx_mcs_0_9 > 0:
                                    nss_160 = max(nss_160, rx_mcs_0_9)
                                    mcs_ranges_160.extend(["0-9"] * rx_mcs_0_9)

                                # MCS 10-11
                                rx_mcs_10_11 = int(
                                    mcs_160.get(
                                        "wlan.eht.supported_eht_mcs_bss_set.160.rx_max_nss_supports_eht_mcs_10_11",
                                        "0",
                                    ),
                                    0,
                                )
                                if rx_mcs_10_11 > 0:
                                    nss_160 = max(nss_160, rx_mcs_10_11)
                                    mcs_ranges_160.extend(["10-11"] * rx_mcs_10_11)

                                # MCS 12-13
                                rx_mcs_12_13 = int(
                                    mcs_160.get(
                                        "wlan.eht.supported_eht_mcs_bss_set.160.rx_max_nss_supports_eht_mcs_12_13",
                                        "0",
                                    ),
                                    0,
                                )
                                if rx_mcs_12_13 > 0:
                                    nss_160 = max(nss_160, rx_mcs_12_13)
                                    mcs_ranges_160.extend(["12-13"] * rx_mcs_12_13)

                                mcs_ranges_160 = sorted(set(mcs_ranges_160))
                                mcs_list_160 = (
                                    ", ".join(mcs_ranges_160)
                                    if len(mcs_ranges_160) > 1
                                    else (
                                        mcs_ranges_160[0]
                                        if mcs_ranges_160
                                        else "Unknown"
                                    )
                                )

                                eht_mcs.value = f"MCS {mcs_list_160}"
                                eht_nss.value = f"{nss_160}ss"

                            max_nss = max(nss_80, nss_160, nss_320)
                            eht_nss.db_value = max_nss

                            highest_mcs = ""
                            if "12-13" in mcs_ranges_80 or "12-13" in mcs_ranges_160:
                                highest_mcs = "0-13"
                            elif "10-11" in mcs_ranges_80 or "10-11" in mcs_ranges_160:
                                highest_mcs = "0-11"
                            else:
                                highest_mcs = "0-9"

                            eht_mcs.db_value = highest_mcs
                    except (KeyError, TypeError, ValueError) as e:
                        self.log.debug(f"Error parsing EHT capabilities: {str(e)}")

        capabilities.extend(
            [
                eht_support,
                epcs_support,
                eht_om_support,
                rtwt_support,
                scs_support,
                support_320mhz,
                eht_nss,
                eht_mcs,
                mcs14_support,
                mcs15_support,
            ]
        )

        return capabilities


class Profiler:
    """Code handling analysis of client capablities"""

    def __init__(self, config=None, queue=None, log_queue=None):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.config = config
        debug = config.get("GENERAL", {}).get("debug", False)
        if debug:
            self.log.setLevel(logging.DEBUG)
        else:
            self.log.setLevel(logging.INFO)
        if log_queue:
            for handler in self.log.handlers:
                self.log.removeHandler(handler)
            queue_handler = QueueHandler(log_queue)
            self.log.addHandler(queue_handler)
        self.parent_pid = os.getppid()
        self.log.debug("profiler pid: %s; parent pid: %s", os.getpid(), self.parent_pid)
        self.analyzed_hash = {}
        if config:
            channel = config.get("GENERAL").get("channel")
            if channel:
                self.channel = int(channel)
            else:
                self.log.warning("profiler cannot determine channel from config")
            self.listen_only = config.get("GENERAL").get("listen_only")
            self.files_path = config.get("GENERAL").get("files_path")
            self.ft_disabled = config.get("GENERAL").get("ft_disabled")
            self.he_disabled = config.get("GENERAL").get("he_disabled")
            self.be_disabled = config.get("GENERAL").get("be_disabled")
            # self.reports_dir = os.path.join(self.files_path, "reports")
            # self.clients_dir = os.path.join(self.files_path, "clients")
            # self.csv_file = os.path.join(
            #     self.reports_dir, f"profiler-{time.strftime('%Y-%m-%d')}.csv"
            # )
            self.pcap_analysis = config.get("GENERAL").get("pcap_analysis")
        self.client_profiled_count = 0
        self.lookup = manuf.MacParser(update=False)
        self.last_manuf = "N/A"
        self.running = True
        self.tshark = self.get_tshark_path()
        self.log.debug(self.get_tshark_version(self.tshark))
        self.run(queue)

    def write_tshark_json_and_text(self, results, ascii_report) -> None:
        actual_user = os.environ.get('SUDO_USER', pwd.getpwuid(os.getuid()).pw_name)
        user_info = pwd.getpwnam(actual_user)

        client_mac = results.get("mac")
        client_mac = client_mac.replace(":", "-", 5)
        band = results.get("capture_band")
        features = results.get("features")
        
        for path in self.files_path:
            client_dir_path = os.path.join(os.path.join(path, "clients"), client_mac)

            if not os.path.isdir(client_dir_path):
                try:
                    os.mkdir(client_dir_path)
                except OSError:
                    self.log.exception("problem creating %s directory", client_dir_path)
                    sys.exit(signal.SIGHUP)

            if not band:
                band = ""
            else:
                band = f"_{band}GHz"

            text_filename = os.path.join(client_dir_path, f"{client_mac}{band}.txt")

            json_filename = os.path.join(client_dir_path, f"{client_mac}{band}.json")

            try:
                same = False
                write_time = strftime("%Y%m%dt%H%M%S")
                if os.path.exists(json_filename):
                    with open(json_filename, "r") as _file:
                        existing_json = json.load(_file)

                    if hash(str(json.dumps(existing_json.get("features")))) == hash(
                        str(json.dumps(features))
                    ):
                        # previously profiled client has the same features
                        same = True

                    if not same:
                        json_filename = json_filename.replace(
                            ".json", f"_diff.{write_time}.json"
                        )

                self.log.debug("writing json report to %s", json_filename)
                with open(json_filename, "w") as write_json_file:
                    json.dump(results, write_json_file)

                if os.path.exists(text_filename):
                    with open(text_filename, "r") as read_file:
                        existing_text = read_file.readlines()
                        temp = []
                        for line in existing_text:
                            temp.append(line.replace("\n", ""))
                        existing_text = temp

                    if not same:
                        ascii_report = list(
                            Differ().compare(existing_text, ascii_report.split("\n"))
                        )
                        text_filename = text_filename.replace(
                            ".txt", f"_diff.{write_time}.txt"
                        )
                        ascii_report = "\n".join(ascii_report)

                self.log.debug("writing to %s", text_filename)
                with open(text_filename, "w") as file_writer:
                    file_writer.write(ascii_report)

                os.chown(client_dir_path, user_info.pw_uid, user_info.pw_gid)
                for file in [text_filename, json_filename]:
                    os.chown(os.path.join(path, file), user_info.pw_uid, user_info.pw_gid)
            except OSError:
                self.log.exception(
                    "error creating flat files to dump client info (%s)", text_filename
                )
                sys.exit(signal.SIGHUP)

    def get_tshark_path(self) -> str:
        """Get the tshark executable path for the current platform."""
        system = platform.system().lower()

        if system == "darwin":  # macOS
            path = "/Applications/Wireshark.app/Contents/MacOS/tshark"
        elif system == "windows":
            path = r"C:\Program Files\Wireshark\tshark.exe"
        else:
            system_tshark = shutil.which("tshark")
            if system_tshark:
                return system_tshark

            path = "/usr/bin/tshark"

        if os.path.isfile(path):
            return path

        path_from_which = shutil.which("tshark")
        if path_from_which:
            return path_from_which

        raise FileNotFoundError(
            f"Could not find tshark executable on this {system} system"
        )

    def get_tshark_version(self, tshark_path):
        cmd = [self.tshark, "-v"]
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout

    def get_tshark_raw(self, pcap_file) -> str:
        cmd = [
            self.tshark,
            "-r",
            pcap_file,
            "-Y",
            "wlan.fc.type_subtype == 0",
            "-c",
            "1",
            "-F",
            "pcapng",
            "-w",
            "-",
        ]
        self.log.debug(" ".join(cmd))
        out = ""
        try:
            result = subprocess.run(cmd, capture_output=True, text=False, check=True)
            if result.stdout:
                packet_data = result.stdout
                encoded = base64.b64encode(packet_data).decode("ascii")
                out = json.dumps(encoded)
        except subprocess.CalledProcessError as e:
            self.log.error(
                "tshark command failed with exit code %d: %s", e.returncode, e
            )
        except Exception as e:
            self.log.error("Error in get_tshark_raw: %s", e)
        return out

    def get_tshark_raw_from_scapy(self, scapy_packet) -> str:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            wrpcap(tmp.name, scapy_packet)
            cmd = [
                self.tshark,
                "-r",
                tmp.name,
                "-Y",
                "wlan.fc.type_subtype == 0",
                "-c",
                "1",
                "-F",
                "pcapng",
                "-w",
                "-",
            ]
            self.log.debug(" ".join(cmd))
            out = ""
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=False, check=True
                )
                if result.stdout:
                    packet_data = result.stdout
                    encoded = base64.b64encode(packet_data).decode("ascii")
                    out = json.dumps(encoded)
            except subprocess.CalledProcessError as e:
                self.log.error(
                    "tshark command failed with exit code %d: %s", e.returncode, e
                )
            except Exception:
                self.log.exception("Error in get_tshark_raw_from_scapy")
            return out

    def scapy_to_tshark(self, scapy_packet, display_filter=None):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            wrpcap(tmp.name, scapy_packet)
            cmd = [
                self.tshark,
                "-r",
                tmp.name,
                "-T",
                "json",
                "-V",
                "--no-duplicate-keys",
                "-c",
                "1",
            ]
            if display_filter:
                cmd.extend(["-Y", display_filter])
            self.log.debug(" ".join(cmd))

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout

    def run_tshark_json(self, pcap_file, display_filter=None):
        """
        Run tshark on a pcap file and return the output as parsed JSON.

        Args:
            pcap_file (str): Path to the pcap file
            display_filter (str, optional): Wireshark display filter

        Returns:
            dict: The parsed JSON output from tshark
        """
        cmd = [
            self.tshark,
            "-r",
            pcap_file,
            "-T",
            "json",
            "-V",
            "--no-duplicate-keys",
            "-c",
            "1",
        ]
        if display_filter:
            cmd.extend(["-Y", display_filter])
        self.log.debug(" ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout

    def run(self, queue) -> None:
        """Runner which performs checks prior to profiling an association request"""
        tsharkparser = TsharkClientCapabilityParser(self.log)
        self.log.debug("tshark path at %s", self.tshark)
        if queue:
            buffer: "Dict" = {}
            buffer_squelch_timer = 3

            message_printed = False
            while self.running:
                frame = queue.get()
                if frame:
                    if isinstance(frame, RadioTap) or isinstance(frame, Dot11):
                        if frame.addr2 in buffer:
                            elapsed = time.time() - buffer[frame.addr2]
                            if elapsed < buffer_squelch_timer:
                                self.log.debug(
                                    "already seen %s %s seconds ago; not sending to profiler process",
                                    frame.addr2,
                                    f"{elapsed:.2f}",
                                )
                                continue
                            else:
                                buffer[frame.addr2] = time.time()
                        else:
                            buffer[frame.addr2] = time.time()

                        # if self.pcap_analysis:
                        #     tshark_output = self.run_tshark_json(self.pcap_analysis)
                        # self.tshark_single_frame_raw_output = self.get_tshark_raw(
                        #     self.pcap_analysis
                        # )
                        # else:
                        tshark_output = self.scapy_to_tshark(frame)
                        raw_tshark_output = self.get_tshark_raw_from_scapy(frame)
                        try:
                            parsed = json.loads(tshark_output)
                            compact_json = json.dumps(parsed, separators=(", ", ": "))
                            self.log.debug("TSHARK OUTPUT: %s", compact_json)
                        except json.JSONDecodeError:
                            self.log.debug("TSHARK OUTPUT: %s", tshark_output)
                        filepath = os.path.join(
                            os.path.dirname(os.path.abspath(__file__)), "tshark.json"
                        )
                        with open(filepath, "w") as f:
                            json.dump(json.loads(tshark_output), f, indent=2)
                        results = tsharkparser.parse_tshark_json(tshark_output)
                        results["pcapng"] = raw_tshark_output
                        ascii_report = tsharkparser.generate_text_report(results)
                        client = results.get("mac")
                        self.log.info(
                            "generating text report for %s\n%s\n", client, ascii_report
                        )
                        del results["capabilities"]
                        self.log.info(
                            "JSON results:\n%s", json.dumps(results, indent=2)
                        )
                        self.write_tshark_json_and_text(results, ascii_report)

                if self.pcap_analysis:
                    self.log.info(
                        "exiting after completing analysis of %s ...",
                        self.pcap_analysis,
                    )
                    sys.exit(0)

                if queue.empty():
                    if not message_printed:
                        print("Queue is empty, waiting for data ...")
