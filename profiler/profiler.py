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
import csv
from functools import total_ordering
import inspect
import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from difflib import Differ
from logging.handlers import QueueHandler
from time import strftime
from typing import Dict, List, Tuple, Union

from manuf2 import manuf  # type: ignore
from scapy.all import Dot11, RadioTap, wrpcap  # type: ignore

from .__version__ import __version__
from .constants import (
    _20MHZ_FREQUENCY_CHANNEL_MAP,
)
from .helpers import (
    Base64Encoder,
    flag_last_object,
    get_bit,
    is_randomized,
    update_last_profile_record,
)

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
            capabilities += self._analyze_supported_channels(
                dot11_elt_dict,
                is_6ghz
            )
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


    def generate_text_report(
        self,
        profile: dict
    ) -> str:
        """Generate a report for profile"""
        mac = profile.get('mac')
        manuf = profile.get('manuf', None)
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
        band = profile.get('capture_band')
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
        capabilities = profile.get('capabilities', [])
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
            manuf = self.lookup.get_manuf(packet["wlan"]["wlan.sa_tree"]["wlan.sa_resolved"])
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
                if 'wlan.tag.oui' in tag:
                    oui_value = tag['wlan.tag.oui']
                    
                    oui_int = int(oui_value)
                    oui_formatted = "{0:02X}:{1:02X}:{2:02X}:00:00:00".format(
                        (oui_int >> 16) & 0xFF,
                        (oui_int >> 8) & 0xFF,
                        oui_int & 0xFF
                    )
                    manuf = self.lookup.get_manuf(oui_formatted)
                    if manuf and manuf.lower() in sanitize:
                        manuf = sanitize[manuf.lower()]
                    if manuf and not any(manuf.lower().startswith(lq) for lq in low_quality):
                        manufs.append(manuf)
                        self.log.debug(f"Found manufacturer: {manuf} from OUI: {oui_formatted}")
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

        dot11n_nss = Capability(name="802.11n/NSS", value="Not reported*", db_key="dot11n_nss", db_value=-1)

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

        dot11ac_nss = Capability(name="802.11ac/VHT NSS", value="Not reported*", db_key="dot11ac_nss", db_value=-1)

        dot11ac_mcs = Capability(name="802.11ac/VHT MCS", value="Not reported*", db_key="dot11ac_mcs", db_value=-1)

        dot11ac_su_bf = Capability(name="802.11ac/SU BF", value="Not reported*", db_key="dot11ac_su_bf", db_value=-1)

        dot11ac_mu_bf = Capability(name="802.11ac/MU BF", value="Not reported*", db_key="dot11ac_mu_bf", db_value=-1)

        dot11ac_bf_sts = Capability(name="802.11ac/BF STS", value="Not reported*", db_key="dot11ac_bf_sts", db_value=-1)

        dot11ac_160_mhz = Capability(name="802.11ac/160 MHz", value="Not reported*", db_key="dot11ac_160_mhz", db_value=-1)

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

        min_power = Capability(name="Min Power", value="Not reported*", db_key="min_power", db_value=-1)

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
                    
                    has_2ghz = False
                    has_5ghz = False
                    
                    for chanset in supchan:
                        start_channel = int(chanset["wlan.supchan.first"])
                        if start_channel <= 14 and not is_6ghz:
                            has_2ghz = True
                        elif start_channel > 14 or is_6ghz:
                            has_5ghz = True
                    
                    for chanset in supchan:
                        
                        start_channel = int(chanset["wlan.supchan.first"])
                        channel_range = int(chanset["wlan.supchan.range"])

                        if start_channel > 14 or is_6ghz:
                            channel_multiplier = 4  # 5 GHz or 6 GHz
                        else:
                            channel_multiplier = 1  # 2.4 GHz

                        for i in range(channel_range):
                            channel_list.append(start_channel + (i * channel_multiplier))

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
                                
                            if (prev_channel <= 14 and channel > 14) or (prev_channel > 14 and channel <= 14):
                                expected_gap = None 
                            else:
                                expected_gap = prev_multiplier
                        else:
                            if channel > 14 or is_6ghz:
                                current_multiplier = 4
                            else:
                                current_multiplier = 1
                            expected_gap = current_multiplier

                        if expected_gap and channel - placeholder[-1] == expected_gap:
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

        dot11ax_nss = Capability(name="802.11ax/HE NSS", value="Not reported*", db_key="dot11ax_nss", db_value=-1)

        dot11ax_mcs = Capability(name="802.11ax/HE MCS", value="Not reported*", db_key="dot11ax_mcs", db_value=-1)

        # Additional 802.11ax capabilities
        dot11ax_punctured_preamble = Capability(
            name="802.11ax/Punctured Preamble", value="Not reported*", db_key="dot11ax_punctured_preamble", db_value=-1
        )
        dot11ax_he_su_beamformee = Capability(
            name="802.11ax/SU BF", value="Not reported*", db_key="dot11ax_he_su_beamformee", db_value=-1
        )
        dot11ax_he_beamformee_sts = Capability(
            name="802.11ax/BF STS", value="Not reported*", db_key="dot11ax_he_beamformee_sts", db_value=-1
        )
        dot11ax_twt = Capability(name="802.11ax/TWT", value="Not reported*", db_key="dot11ax_twt", db_value=-1)
        dot11ax_bsr = Capability(name="802.11ax/BSR", value="Not reported*", db_key="dot11ax_bsr", db_value=-1)
        dot11ax_he_er_su_ppdu = Capability(name="802.11ax/ER SU PPDU", value="Not reported*", db_key="dot11ax_he_er_su_ppdu", db_value=-1)
        dot11ax_spatial_reuse = Capability(name="802.11ax/Spatial Reuse", value="Not reported*", db_key="dot11ax_spatial_reuse", db_value=-1)
        dot11ax_160_mhz = Capability(name="802.11ax/160 MHz", value="Not reported*", db_key="dot11ax_160_mhz", db_value=-1)
        dot11ax_six_ghz = Capability(name="802.11ax/6 GHz", value="Not reported*", db_key="dot11ax_six_ghz", db_value=-1)

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
            name="802.11be/MLE (Multi-Link Element)", value="Not reported*", db_key="dot11be_mle", db_value=-1
        )
        
        # MLC Type
        mlc_type = Capability(
            name="802.11be/MLE/MLC Type", value="Not reported*", db_key="dot11be_mle_mlc_type", db_value=-1
        )

        # EMLSR Support
        emlsr_support = Capability(
            name="802.11be/MLE/EMLSR", value="Not reported*", db_key="dot11be_mle_emlsr_support", db_value=-1
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
            name="802.11be/MLE/EMLMR", value="Not reported*", db_key="dot11be_mle_emlmr_support", db_value=-1
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
                        self.log.debug(f"Error parsing Multi-Link capabilities: {str(e)}")

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
            name="802.11be/EPCS Support", value="No", db_key="dot11be_epcs_support", db_value=-1
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
            name="802.11be/R-TWT Support", value="No", db_key="dot11be_rtwt_support", db_value=-1
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
            name="802.11be/320 MHz support (6G)", value="No", db_key="dot11be_320mhz", db_value=-1
        )

        # MCS 14 Support (EHT Duplicate 6 GHz)
        mcs14_support = Capability(
            name="802.11be/MCS 14", value="No", db_key="dot11be_mcs14_support", db_value=-1
        )

        # MCS 15 Support
        mcs15_support = Capability(
            name="802.11be/MCS 15", value="No", db_key="dot11be_mcs15_support", db_value=-1
        )

        eht_nss = Capability(
            name="802.11be/EHT SS", value="Not reported*", db_key="dot11be_nss", db_value=-1
        )

        eht_mcs = Capability(
            name="802.11be/EHT MCS", value="Not reported*", db_key="dot11be_mcs", db_value=-1
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
        if config:
            debug = config.get("GENERAL").get("debug")
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
            self.pcap_analysis = config.get("GENERAL").get("pcap_analysis")
            self.ft_disabled = config.get("GENERAL").get("ft_disabled")
            self.he_disabled = config.get("GENERAL").get("he_disabled")
            self.be_disabled = config.get("GENERAL").get("be_disabled")
            self.reports_dir = os.path.join(self.files_path, "reports")
            self.clients_dir = os.path.join(self.files_path, "clients")
            self.pcap_analysis = config.get("GENERAL").get("pcap_analysis")
            self.csv_file = os.path.join(
                self.reports_dir, f"profiler-{time.strftime('%Y-%m-%d')}.csv"
            )
        self.client_profiled_count = 0
        self.lookup = manuf.MacParser(update=False)
        self.last_manuf = "N/A"
        self.running = True
        if self.pcap_analysis:
            self.tshark = self.get_tshark_path()
            self.log.debug(self.get_tshark_version(self.tshark))
            self.tshark_single_frame_raw_output = self.get_tshark_raw(self.pcap_analysis)
            self.tshark_output = self.run_tshark_json(self.pcap_analysis)
            # self.log.debug(json.dumps(self.tshark_output, indent=2))

            filepath = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "tshark.json"
            )
            with open(filepath, "w") as f:
                json.dump(json.loads(self.tshark_output), f, indent=2)

            tsharkparser = TsharkClientCapabilityParser(self.log)
            self.log.debug("tshark path at %s", self.tshark)
            results = tsharkparser.parse_tshark_json(self.tshark_output)
            results["pcapng"] = self.tshark_single_frame_raw_output
            ascii_report = tsharkparser.generate_text_report(results)
            client = results.get('mac')
            self.log.info("generating text report for %s\n%s\n", client, ascii_report)
            del results['capabilities']
            self.log.info(json.dumps(results, indent=2))
            self.write_tshark_json_and_text(results, ascii_report)

        # self.run(queue)  # TODO MAKE COMPAT WITH TSHARK

    def write_tshark_json_and_text(self, results, ascii_report) -> None:
        client_mac = results.get('mac')
        client_mac = client_mac.replace(":", "-", 5)
        band = results.get('capture_band')
        features = results.get('features')
        dest = os.path.join(self.clients_dir, client_mac)
        
        if not band:
            band = ""
        else:
            band = f"_{band}GHz"
    
        text_filename = os.path.join(dest, f"{client_mac}{band}.txt")

        json_filename = os.path.join(dest, f"{client_mac}{band}.json")

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
                encoded = base64.b64encode(packet_data).decode('ascii')
                out = json.dumps(encoded)
        except subprocess.CalledProcessError as e:
            self.log.error("tshark command failed with exit code %d: %s", e.returncode, e)
        except Exception as e:
            self.log.error("Error in get_tshark_raw: %s", e)
        return out

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
        self.log.debug(" ".join(cmd))
        if display_filter:
            cmd.extend(["-Y", display_filter])
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout

    def run(self, queue) -> None:
        """Runner which performs checks prior to profiling an association request"""
        if queue:
            buffer: "Dict" = {}
            buffer_squelch = 3

            while self.running:
                frame = queue.get()

                if frame:
                    if isinstance(frame, RadioTap) or isinstance(frame, Dot11):
                        if frame.addr2 in buffer:
                            toc = time.time() - buffer[frame.addr2]
                            if toc < buffer_squelch:
                                self.log.debug(
                                    "already seen %s %s seconds ago; not sending to profiler process",
                                    frame.addr2,
                                    f"{toc:.2f}",
                                )
                                continue
                            else:
                                buffer[frame.addr2] = time.time()
                        else:
                            buffer[frame.addr2] = time.time()

                        self.profile(frame)

                if queue.empty():
                    if self.pcap_analysis:
                        # if nothing is left in the queue and we're only analyzing a pcap file
                        self.log.info(
                            "exiting after completing analysis of %s",
                            self.pcap_analysis,
                        )
                        sys.exit(signal.SIGTERM)

    def profile(self, frame) -> None:
        """Handle profiling clients as they come into the queue"""
        # we should determine the channel from frame itself, not from the profiler config
        freq = frame.ChannelFrequency
        self.log.debug("detected freq from assoc is %s", freq)

        # update /var/run/wlanpi-profiler.last_profile
        update_last_profile_record(frame.addr2.replace(":", ""))

        channel = _20MHZ_FREQUENCY_CHANNEL_MAP.get(freq, 0)
        """
        All radio tap headers are malformed from some adapters on certain kernels.
        This has been observed in 5.15rc2 up to 5.15.1 with MediaTek adapters for example.
        If that is the case, we are unable to detect the frequency/channel from the association.
        ---------------------------------------------
        - Client MAC: 6e:1d:8a:28:32:51
        - OUI manufacturer lookup: Apple (Randomized MAC)
        - Chipset lookup: Broadcom
        - Frequency band: Unknown
        - Capture channel: 0
        ---------------------------------------------
        """
        if channel == 0:
            self.log.warning(
                "COULD NOT MAP FREQUENCY FROM RADIO TAP HEADER FOUND IN ASSOCIATION FRAME"
            )
        else:
            self.log.debug("detected freq from assoc maps to channel %s", channel)

        is_6ghz = False
        if freq > 2411 and freq < 2485:
            band = "2.4GHz"
        elif freq > 5100 and freq < 5900:
            band = "5.0GHz"
        elif freq > 5900 and freq < 7120:
            band = "6.0GHz"
            is_6ghz = True
        else:
            band = "unknown"

        ssid, oui_manuf, chipset, capabilities = self.analyze_assoc_req(frame, is_6ghz)
        analysis_hash = hash(f"{frame.addr2}: {capabilities}")
        if analysis_hash in self.analyzed_hash.keys():
            self.log.info(
                "already seen %s (capabilities hash=%s) this session, ignoring...",
                frame.addr2,
                analysis_hash,
            )
        else:
            randomized = is_randomized(frame.addr2)
            text_report_oui_manuf = oui_manuf
            if randomized:
                if oui_manuf is None:
                    text_report_oui_manuf = "Randomized MAC"
                else:
                    text_report_oui_manuf = "{0} (Randomized MAC)".format(oui_manuf)

            self.last_manuf = oui_manuf
            self.analyzed_hash[analysis_hash] = frame

            if self.listen_only:
                self.log.info(
                    "discovered association request for %s to %s",
                    frame.addr2,
                    ssid,
                )

            # generate text report
            text_report = self.generate_text_report(
                text_report_oui_manuf,
                chipset,
                capabilities,
                frame.addr2,
                channel,
                band,
                ssid,
                self.listen_only,
            )

            self.log.info("generating text report for %s\n%s", frame.addr2, text_report)

            self.log.debug(
                "writing textual reports for %s (capabilities hash=%s) to %s",
                frame.addr2,
                analysis_hash,
                os.path.join(self.clients_dir, frame.addr2.replace(":", "-")),
            )
            self.write_analysis_to_file_system(
                text_report,
                capabilities,
                frame,
                oui_manuf,
                chipset,
                randomized,
                band,
                channel,
                self.listen_only,
            )

            self.client_profiled_count += 1

            self.log.debug(
                "%s clients profiled this session", self.client_profiled_count
            )

    @staticmethod
    def generate_text_report(
        oui_manuf: str,
        chipset: str,
        capabilities: list,
        client_mac: str,
        channel: int,
        band: str,
        ssid: str,
        listen_only: bool,
    ) -> str:
        """Generate a report for output"""
        # start report
        text_report = "-" * 45
        if listen_only:
            text_report += f"\n - SSID: {ssid}"
        text_report += f"\n - Client MAC: {client_mac}"
        text_report += f"\n - OUI manufacturer lookup: {oui_manuf or 'Unknown'}"
        text_report += f"\n - Chipset lookup: {chipset or 'Unknown'}"
        band_label = ""
        if band[0] == "2":
            band_label = "2.4 GHz"
        elif band[0] == "5":
            band_label = "5 GHz"
        elif band[0] == "6":
            band_label = "6 GHz"
        else:
            band_label = "Unknown"
        text_report += f"\n - Frequency band: {band_label}"
        text_report += f"\n - Capture channel: {channel}\n"
        text_report += "-" * 45
        text_report += "\n"
        for capability in capabilities:
            if capability.name and capability.value:
                out = "{0:<22} {1:<22}".format(capability.name, capability.value)
                if out.strip():
                    text_report += out + "\n"

        text_report += "\nKey: [X]: Supported, [ ]: Not supported"
        text_report += "\n* Reported client capabilities are dependent on available features at the time of client association."
        text_report += "\n** Reported channels do not factor local regulatory domain. Detected channel sets are assumed contiguous."
        return text_report

    def write_analysis_to_file_system(
        self,
        text_report,
        capabilities,
        frame,
        oui_manuf,
        chipset,
        randomized: bool,
        band,
        channel,
        listen_only,
    ):
        """Write report files out to a directory on the WLAN Pi"""
        log = logging.getLogger(inspect.stack()[0][3])
        # dump out the text to a file
        client_mac = frame.addr2.replace(":", "-", 5)
        dest = os.path.join(self.clients_dir, client_mac)

        if not os.path.isdir(dest):
            try:
                os.mkdir(dest)
            except OSError:
                log.exception("problem creating %s directory", dest)
                sys.exit(signal.SIGHUP)

        data = {}

        data["mac"] = client_mac
        data["is_laa"] = randomized
        data["manuf"] = oui_manuf
        data["chipset"] = chipset
        if band[0] == "2":
            band_db = 2
        elif band[0] == "5":
            band_db = 5
        elif band[0] == "6":
            band_db = 6
        else:
            band_db = 0
        data["band"] = band_db
        data["capture_channel"] = channel
        data["listen_only"] = listen_only
        features = {}
        for capability in capabilities:
            if capability.db_key:
                features[capability.db_key] = capability.db_value
        data["features"] = features
        data["pcap"] = json.dumps(bytes(frame), cls=Base64Encoder)
        data["schema_version"] = 1
        data["profiler_version"] = __version__

        # if there is a malformed radiotap header
        if band == "unknown":
            band = ""
        else:
            band = f"_{band}"

        text_filename = os.path.join(dest, f"{client_mac}{band}.txt")

        json_filename = os.path.join(dest, f"{client_mac}{band}.json")

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

            log.debug("writing json report to %s", json_filename)
            with open(json_filename, "w") as write_json_file:
                json.dump(data, write_json_file)

            if os.path.exists(text_filename):
                with open(text_filename, "r") as read_file:
                    existing_text = read_file.readlines()
                    temp = []
                    for line in existing_text:
                        temp.append(line.replace("\n", ""))
                    existing_text = temp

                if not same:
                    text_report = list(
                        Differ().compare(existing_text, text_report.split("\n"))
                    )
                    text_filename = text_filename.replace(
                        ".txt", f"_diff.{write_time}.txt"
                    )
                    text_report = "\n".join(text_report)

            log.debug("writing to %s", text_filename)
            with open(text_filename, "w") as file_writer:
                file_writer.write(text_report)

        except OSError:
            log.exception(
                "error creating flat files to dump client info (%s)", text_filename
            )
            sys.exit(signal.SIGHUP)

        out_row = {"Client_Mac": client_mac, "OUI_Manuf": oui_manuf}

        out_fieldnames = ["Client_Mac", "OUI_Manuf"]

        for capability in capabilities:
            if capability.db_key:
                features[capability.db_key] = capability.db_value

        for capability in capabilities:
            if capability.db_key is not None and capability.db_value is not None:
                out_fieldnames.append(capability.db_key)
                out_row[capability.db_key] = capability.db_value

        # dump out the frame to a file
        pcap_filename = os.path.splitext(text_filename)[0] + ".pcap"
        log.debug("writing to %s", pcap_filename)
        wrpcap(pcap_filename, [frame])

        # check if csv file exists
        if not os.path.exists(self.csv_file):
            # create file with csv headers
            with open(self.csv_file, mode="w") as file_obj:
                csv_writer = csv.DictWriter(file_obj, fieldnames=out_fieldnames)
                csv_writer.writeheader()

        # append data to csv file
        with open(self.csv_file, mode="a") as file_obj:
            csv_writer = csv.DictWriter(file_obj, fieldnames=out_fieldnames)
            csv_writer.writerow(out_row)

    @staticmethod
    def process_information_elements(buffer: bytes) -> dict:
        """
        Parse a 802.11 payload and returns a dict of IEs

        Does not handle headers or FCS.

        You must strip those before passing the payload in.
        """
        # init element vars
        information_elements: "Dict" = {}
        element_id = 0
        element_length = 0
        element_data = []
        # loop tracking vars
        is_index_byte = True
        is_length_byte = True
        index = 0
        for byte, last in flag_last_object(buffer):
            if is_index_byte:
                element_id = byte
                is_index_byte = False
                continue
            if is_length_byte:
                element_length = byte
                is_length_byte = False
                continue
            if index < element_length:
                index += 1
                element_data.append(byte)
            else:
                if element_id in [VENDOR_SPECIFIC_IE_TAG, IE_EXT_TAG]:
                    # map a list of data items to the key
                    if element_id in information_elements:
                        information_elements[element_id].append(element_data)
                    else:
                        information_elements[element_id] = [element_data]
                else:
                    # map the data to the key
                    information_elements[element_id] = element_data

                # reset vars to decode next information element
                index = 0
                is_index_byte = True
                is_length_byte = True
                element_data = []
                element_id = 0
                element_length = 0
                # current byte should be next index byte
                element_id = byte
                is_index_byte = False
                continue
            if last:
                if element_id in [VENDOR_SPECIFIC_IE_TAG, IE_EXT_TAG]:
                    # map a list of data items to the key
                    if element_id in information_elements:
                        information_elements[element_id].append(element_data)
                    else:
                        information_elements[element_id] = [element_data]
                else:
                    # map the data to the key
                    information_elements[element_id] = element_data

        return information_elements

    def resolve_oui_manuf(self, mac: str, dot11_elt_dict) -> str:
        """Resolve client's manuf using manuf database and other heuristics"""
        log = logging.getLogger(inspect.stack()[0][3])

        # log.debug("starting oui lookup for %s", mac)
        oui_manuf = self.lookup.get_manuf(mac)

        # vendor OUI that we possibly want to check for a more clear OUI match
        low_quality = "muratama"

        sanitize = {
            "intelwir": "Intel",
            "intelcor": "Intel",
            "samsunge": "Samsung",
            "samsungelect": "Samsung",
        }

        if (
            oui_manuf is None
            or oui_manuf.lower().startswith(low_quality)
            or oui_manuf.lower() in sanitize.keys()
        ):
            # inspect vendor specific IEs and see if there's an IE with
            # an OUI that we know can only be included if the manuf
            # of the client is the vendor that maps to that OUI
            if VENDOR_SPECIFIC_IE_TAG in dot11_elt_dict.keys():
                for element_data in dot11_elt_dict[VENDOR_SPECIFIC_IE_TAG]:
                    try:
                        vendor_mac = "{0:02X}:{1:02X}:{2:02X}:00:00:00".format(
                            element_data[0], element_data[1], element_data[2]
                        )
                        oui_manuf_vendor = self.lookup.get_manuf(vendor_mac)
                        if oui_manuf_vendor is not None:
                            # Matches are vendor specific IEs we know are client specific
                            # e.g. Apple vendor specific IEs can only be found in Apple devices
                            # Samsung may follow similar logic based on S10 5G testing and S21 5G Ultra but unsure of consistency
                            matches = ("apple", "samsung", "intel")
                            if oui_manuf_vendor.lower().startswith(matches):
                                if oui_manuf_vendor.lower() in sanitize:
                                    oui_manuf = sanitize.get(
                                        oui_manuf_vendor.lower(), oui_manuf_vendor
                                    )
                                else:
                                    oui_manuf = oui_manuf_vendor
                    except IndexError:
                        log.debug("IndexError in %s" % VENDOR_SPECIFIC_IE_TAG)

        log.debug("finished oui lookup for %s: %s", mac, oui_manuf)
        return oui_manuf

    def resolve_vendor_specific_tag_chipset(self, dot11_elt_dict) -> str:
        """Resolve client's chipset via heuristics of vendor specific tags"""
        # Broadcom
        # MediaTek
        # Qualcomm
        # Infineon AG
        # Intel Wireless Network Group
        log = logging.getLogger(inspect.stack()[0][3])
        chipset = None
        manufs = []

        if VENDOR_SPECIFIC_IE_TAG in dot11_elt_dict.keys():
            for element_data in dot11_elt_dict[VENDOR_SPECIFIC_IE_TAG]:
                try:
                    oui = "{0:02X}:{1:02X}:{2:02X}:00:00:00".format(
                        element_data[0], element_data[1], element_data[2]
                    )
                    manufs.append(self.lookup.get_manuf(oui))
                except IndexError:
                    log.debug("IndexError for %s" % VENDOR_SPECIFIC_IE_TAG)

        matches = ["broadcom", "qualcomm", "mediatek", "intel", "infineon"]
        _break = False
        for manuf in manufs:
            for match in matches:
                if manuf.lower().startswith(match):
                    chipset = match.title()
                    _break = True
                    break
            if _break:
                break

        return chipset

    @staticmethod
    def analyze_ssid_ie(dot11_elt_dict) -> str:
        """Check the SSID parameter to determine network name"""
        out = ""
        if SSID_PARAMETER_SET_IE_TAG in dot11_elt_dict.keys():
            try:
                ssid = bytes(dot11_elt_dict[SSID_PARAMETER_SET_IE_TAG]).decode("utf-8")
            except UnicodeDecodeError:
                ssid = bytes(dot11_elt_dict[SSID_PARAMETER_SET_IE_TAG]).decode(
                    "latin-1"
                )
            out = f"{ssid}"
        return out

    @staticmethod
    def analyze_ht_capabilities_ie(dot11_elt_dict) -> List:
        """Check for 802.11n support"""
        dot11n = Capability(
            name="802.11n", value="Not reported*", db_key="dot11n", db_value=0
        )
        dot11n_nss = Capability(db_key="dot11n_nss", db_value=0)

        if HT_CAPABILITIES_IE_TAG in dot11_elt_dict.keys():
            spatial_streams = 0

            # mcs octets 1 - 4 indicate # streams supported (up to 4 streams only)
            for mcs_octet in range(3, 7):
                mcs_octet_value = dot11_elt_dict[HT_CAPABILITIES_IE_TAG][mcs_octet]

                if mcs_octet_value & 255:
                    spatial_streams += 1

            dot11n.value = f"Supported ({spatial_streams}ss)"
            dot11n.db_value = 1
            dot11n_nss.db_value = spatial_streams

        return [dot11n, dot11n_nss]

    @staticmethod
    def analyze_vht_capabilities_ie(dot11_elt_dict) -> List:
        """Check for 802.11ac support"""
        dot11ac = Capability(
            name="802.11ac", value="Not reported*", db_key="dot11ac", db_value=0
        )
        dot11ac_nss = Capability(db_key="dot11ac_nss", db_value=0)
        dot11ac_mcs = Capability(db_key="dot11ac_mcs", db_value="")
        dot11ac_su_bf = Capability(db_key="dot11ac_su_bf", db_value=0)
        dot11ac_mu_bf = Capability(db_key="dot11ac_mu_bf", db_value=0)
        dot11ac_bf_sts = Capability(db_key="dot11ac_bf_sts", db_value=0)
        dot11ac_160_mhz = Capability(db_key="dot11ac_160_mhz", db_value=0)

        if VHT_CAPABILITIES_IE_TAG in dot11_elt_dict.keys():
            # determine number of spatial streams (NSS) supported
            mcs_upper_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][5]
            mcs_lower_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][4]
            nss = 0
            mcs = []
            for octet in [mcs_lower_octet, mcs_upper_octet]:
                for bit_position in [0, 2, 4, 6]:
                    bit1 = get_bit(octet, bit_position)
                    bit2 = get_bit(octet, bit_position + 1)
                    if (bit1 == 1) and (bit2 == 1):  # (0x3) Not supported
                        continue
                    if (bit1 == 0) and (bit2 == 0):  # (0x0) MCS 0-7
                        nss += 1
                        mcs.append("0-7")
                        continue
                    if (bit1 == 1) and (bit2 == 0):  # (0x1) MCS 0-8
                        nss += 1
                        mcs.append("0-8")
                        continue
                    if (bit1 == 0) and (bit2 == 1):  # (0x2) MCS 0-9
                        nss += 1
                        mcs.append("0-9")
                        continue

            mcs = sorted(set(mcs))
            mcs_list = ", ".join(mcs) if len(mcs) > 1 else mcs[0]
            dot11ac.value = f"Supported ({nss}ss), MCS {mcs_list}"
            dot11ac_nss.db_value = nss
            dot11ac_mcs.db_value = mcs_list

            # check for SU & MU beam formee support
            mu_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][2]
            su_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][1]
            bf_sts_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][1]
            onesixty = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][0]

            # 160 MHz
            if get_bit(onesixty, 2):
                dot11ac_160_mhz.db_value = 1
                dot11ac.value += ", [X] 160 MHz"
            else:
                dot11ac.value += ", [ ] 160 MHz"

            # bit 4 indicates support for both octets (1 = supported, 0 = not supported)
            beam_form_mask = 16

            # SU BF
            if su_octet & beam_form_mask:
                dot11ac.value += ", [X] SU BF"
                dot11ac_su_bf.db_value = 1
            else:
                dot11ac.value += ", [ ] SU BF"

            # MU BF
            if mu_octet & beam_form_mask:
                dot11ac.value += ", [X] MU BF"
                dot11ac_mu_bf.db_value = 1
            else:
                dot11ac.value += ", [ ] MU BF"

            # BF STS
            vht_bf_sts_binary_string = "{0}{1}{2}".format(
                int(get_bit(bf_sts_octet, 5)),
                int(get_bit(bf_sts_octet, 6)),
                int(get_bit(bf_sts_octet, 7)),
            )
            vht_bf_sts_value = int(vht_bf_sts_binary_string, base=2)
            dot11ac_bf_sts.db_value = vht_bf_sts_value
            dot11ac.value += f", Beamformee STS={vht_bf_sts_value}"

        return [
            dot11ac,
            dot11ac_nss,
            dot11ac_160_mhz,
            dot11ac_mcs,
            dot11ac_su_bf,
            dot11ac_mu_bf,
            dot11ac_bf_sts,
        ]

    @staticmethod
    def analyze_rm_capabilities_ie(dot11_elt_dict) -> List:
        """Check for 802.11k support"""
        dot11k = Capability(
            name="802.11k",
            value="Not reported* - treat with caution, many clients lie about this",
            db_key="dot11k",
            db_value=0,
        )
        if RM_CAPABILITIES_IE_TAG in dot11_elt_dict.keys():
            dot11k.value = "Supported"
            dot11k.db_value = 1

        return [dot11k]

    @staticmethod
    def analyze_ft_capabilities_ie(dot11_elt_dict, ft_disabled: bool) -> List:
        """Check for 802.11r support"""
        dot11r = Capability(
            name="802.11r", value="Not reported*", db_key="dot11r", db_value=0
        )
        if ft_disabled:
            dot11r.value = "Reporting disabled (--no11r option used)"
        elif FT_CAPABILITIES_IE_TAG in dot11_elt_dict.keys():
            dot11r.value = "Supported"
            dot11r.db_value = 1
        else:
            pass

        return [dot11r]

    @staticmethod
    def analyze_ext_capabilities_ie(dot11_elt_dict) -> List:
        """Check for 802.11v support"""
        dot11v = Capability(
            name="802.11v", value="Not reported*", db_key="dot11v", db_value=0
        )

        if EXT_CAPABILITIES_IE_TAG in dot11_elt_dict.keys():
            ext_cap_list = dot11_elt_dict[EXT_CAPABILITIES_IE_TAG]

            # check octet 3 exists
            if 3 <= len(ext_cap_list):
                # bit 4 of octet 3 in the extended capabilites field
                octet3 = ext_cap_list[2]
                bss_trans_support = int("00001000", 2)

                # 'And' octet 3 to test for bss transition support
                if octet3 & bss_trans_support:
                    dot11v.value = "Supported"
                    dot11v.db_value = 1

        return [dot11v]

    @staticmethod
    def analyze_rsn_capabilities_ie(dot11_elt_dict) -> List:
        """Check for 802.11w support"""
        dot11w = Capability(
            name="802.11w", value="Not reported*", db_key="dot11w", db_value=0
        )

        if RSN_CAPABILITIES_IE_TAG in dot11_elt_dict.keys():
            rsn_cap_list = dot11_elt_dict[RSN_CAPABILITIES_IE_TAG]
            rsn_len = len(rsn_cap_list) - 2
            pmf_oct = rsn_cap_list[rsn_len]

            # bit 8 of 2nd last octet in the rsn capabilites field
            if 127 <= pmf_oct:
                dot11w.value = "Supported"
                dot11w.db_value = 1

        return [dot11w]

    @staticmethod
    def analyze_power_capability_ie(dot11_elt_dict) -> List:
        """Check for supported power capabilities"""
        max_power_cap = Capability(
            name="Max Power",
            value="Not reported*",
            db_key="max_power",
            db_value=0,
        )
        min_power_cap = Capability(
            name="Min Power",
            value="Not reported*",
            db_key="min_power",
            db_value=0,
        )

        if POWER_MIN_MAX_IE_TAG in dot11_elt_dict.keys():
            # octet 3 of power capabilites
            max_power = dot11_elt_dict[POWER_MIN_MAX_IE_TAG][1]
            min_power = dot11_elt_dict[POWER_MIN_MAX_IE_TAG][0]

            # check if signed
            if min_power > 127:
                signed_min_power = (256 - min_power) * (-1)
            else:
                signed_min_power = min_power

            max_power_cap.value = f"{max_power} dBm"
            max_power_cap.db_value = max_power
            min_power_cap.value = f"{signed_min_power} dBm"
            min_power_cap.db_value = signed_min_power

        return [max_power_cap, min_power_cap]

    @staticmethod
    def analyze_supported_channels_ie(dot11_elt_dict, is_6ghz: bool) -> List:
        """Check supported channels"""
        supported_channels = Capability(
            name="Supported Channels",
            value="Not reported*",
            db_key="supported_channels",
            db_value=[],
        )
        number_of_supported_channels = Capability(
            name="Number of Channels",
            value=0,
        )
        if SUPPORTED_CHANNELS_IE_TAG in dot11_elt_dict.keys():
            channel_sets_list = dot11_elt_dict[SUPPORTED_CHANNELS_IE_TAG]
            channel_list = []

            is_2ghz = False
            is_5ghz = False

            while channel_sets_list:
                start_channel = channel_sets_list.pop(0)
                channel_range = channel_sets_list.pop(0)

                if start_channel > 14 or is_6ghz:
                    if not is_6ghz:
                        is_5ghz = True
                    channel_multiplier = 4
                else:
                    is_2ghz = True
                    channel_multiplier = 1

                number_of_supported_channels.value += channel_range
                for i in range(channel_range):
                    channel_list.append(start_channel + (i * channel_multiplier))

            ranges = []
            placeholder = []
            for index, channel in enumerate(channel_list):
                if index == 0:
                    placeholder.append(channel)
                    continue
                if is_2ghz and is_5ghz:
                    if channel < 15:
                        channel_multiplier = 1
                    else:
                        channel_multiplier = 4
                if channel - placeholder[-1] == channel_multiplier:
                    placeholder.append(channel)
                    # are we at last index? add last list to ranges
                    if channel == channel_list[-1]:
                        ranges.append(placeholder)
                else:
                    ranges.append(placeholder)
                    placeholder = []
                    placeholder.append(channel)

            channel_ranges = []
            for _range in ranges:
                channel_ranges.append(f"{_range[0]}-{_range[-1]}")

            supported_channels.value = f"{', '.join(channel_ranges)}**"
            supported_channels.db_value = channel_list

        return [supported_channels, number_of_supported_channels]

    @staticmethod
    def analyze_operating_classes(dot11_elt_dict) -> List:
        """Check if 6 GHz is a supported alternative operating class"""
        six_ghz_operating_class_cap = Capability(
            db_key="six_ghz_operating_class_supported",
            db_value=0,
        )

        supported_6ghz_alternative_operating_classes = []
        six_ghz_alternative_operating_classes = [131, 132, 133, 134, 135]
        if SUPPORTED_OPERATING_CLASSES_IE_TAG in dot11_elt_dict.keys():
            supported_operating_classes = dot11_elt_dict[
                SUPPORTED_OPERATING_CLASSES_IE_TAG
            ]
            # pop current operating class from list
            supported_operating_classes.pop()
            for alternative_operating_class in supported_operating_classes:
                if alternative_operating_class in six_ghz_alternative_operating_classes:
                    supported_6ghz_alternative_operating_classes.append(
                        alternative_operating_class
                    )

        if supported_6ghz_alternative_operating_classes:
            six_ghz_operating_class_cap.name = "6 GHz Operating Class"
            six_ghz_operating_class_cap.value = "Supported"
            six_ghz_operating_class_cap.db_value = 1

        return [six_ghz_operating_class_cap]

    @staticmethod
    def analyze_extension_ies(
        dot11_elt_dict, he_disabled: bool, be_disabled: bool
    ) -> List:
        """Check for 802.11ax and 802.11be support"""
        dot11ax = Capability(
            name="802.11ax",
            value="Not supported",
            db_key="dot11ax",
            db_value=0,
        )
        dot11ax_six_ghz = Capability(
            db_key="dot11ax_six_ghz",
            db_value=0,
        )
        dot11ax_punctured_preamble = Capability(
            db_key="dot11ax_punctured_preamble", db_value=0
        )
        dot11ax_he_su_beamformer = Capability(
            db_key="dot11ax_he_su_beamformer", db_value=0
        )
        dot11ax_he_su_beamformee = Capability(
            db_key="dot11ax_he_su_beamformee", db_value=0
        )
        dot11ax_he_beamformee_sts = Capability(
            db_key="dot11ax_he_beamformee_sts", db_value=0
        )
        dot11ax_nss = Capability(db_key="dot11ax_nss", db_value=0)
        dot11ax_mcs = Capability(db_key="dot11ax_mcs", db_value="")
        dot11ax_twt = Capability(db_key="dot11ax_twt", db_value=0)
        dot11ax_bsr = Capability(db_key="dot11ax_bsr", db_value=0)
        dot11ax_he_er_su_ppdu = Capability(db_key="dot11ax_he_er_su_ppdu", db_value=0)
        dot11ax_spatial_reuse = Capability(db_key="dot11ax_spatial_reuse", db_value=0)
        dot11ax_160_mhz = Capability(db_key="dot11ax_160_mhz", db_value=0)

        if he_disabled:
            dot11ax.value = "Reporting disabled (--no11ax option used)"
        else:
            if IE_EXT_TAG in dot11_elt_dict.keys():
                for element_data in dot11_elt_dict[IE_EXT_TAG]:
                    ext_ie_id = int(str(element_data[0]))

                    if ext_ie_id == HE_CAPABILITIES_IE_EXT_TAG:
                        # dot11ax is supported
                        dot11ax.value = "Supported"
                        dot11ax.db_value = 1

                        # determine number of spatial streams (NSS) supported
                        mcs_upper_octet = element_data[19]
                        mcs_lower_octet = element_data[18]
                        nss = 0
                        mcs = []
                        for octet in [mcs_lower_octet, mcs_upper_octet]:
                            for bit_position in [0, 2, 4, 6]:
                                bit1 = get_bit(octet, bit_position)
                                bit2 = get_bit(octet, bit_position + 1)
                                if (bit1 == 1) and (bit2 == 1):  # (0x3) Not supported
                                    continue
                                if (bit1 == 0) and (bit2 == 0):  # (0x0) MCS 0-7
                                    nss += 1
                                    mcs.append("0-7")
                                    continue
                                if (bit1 == 1) and (bit2 == 0):  # (0x1) MCS 0-9
                                    nss += 1
                                    mcs.append("0-9")
                                    continue
                                if (bit1 == 0) and (bit2 == 1):  # (0x2) MCS 0-11
                                    nss += 1
                                    mcs.append("0-11")
                                    continue

                        mcs = sorted(set(mcs))
                        mcs = ", ".join(mcs) if len(mcs) > 1 else mcs[0]  # type: ignore
                        dot11ax.value = f"Supported ({nss}ss), MCS {mcs}"
                        dot11ax_mcs.db_value = mcs
                        dot11ax_nss.db_value = nss

                        onesixty_octet = element_data[7]
                        if get_bit(onesixty_octet, 3):
                            dot11ax.value += ", [X] 160 MHz"
                            dot11ax_160_mhz.db_value = 1
                        else:
                            dot11ax.value += ", [ ] 160 MHz"

                        twt_octet = element_data[1]
                        if get_bit(twt_octet, 1):
                            dot11ax_twt.db_value = 1
                            dot11ax.value += ", [X] TWT"
                        else:
                            dot11ax.value += ", [ ] TWT"

                        punctured_preamble_octet = element_data[8]
                        punctured_preamble_octet_binary_string = ""
                        for bit_position in range(8):
                            punctured_preamble_octet_binary_string += f"{int(get_bit(punctured_preamble_octet, bit_position))}"
                        punctured_bit_booleans = [
                            bool(int(bit))
                            for bit in punctured_preamble_octet_binary_string[0:4]
                        ]
                        puncture_preamble_support = any(punctured_bit_booleans)

                        if puncture_preamble_support:
                            dot11ax_punctured_preamble.db_value = 1
                            dot11ax.value += ", [X] Punctured Preamble"
                        else:
                            dot11ax_punctured_preamble.db_value = 0
                            dot11ax.value += ", [ ] Punctured Preamble"

                        su_beamformer_octet = element_data[10]
                        su_beamformer_octet_binary_string = ""
                        for bit_position in range(8):
                            su_beamformer_octet_binary_string += (
                                f"{int(get_bit(su_beamformer_octet, bit_position))}"
                            )
                        if int(su_beamformer_octet_binary_string[7]):
                            su_beamformer_support = True
                        else:
                            su_beamformer_support = False
                        if su_beamformer_support:
                            dot11ax_he_su_beamformer.db_value = 1
                            dot11ax.value += ", [X] SU Beamformer"
                        else:
                            dot11ax_he_su_beamformer.db_value = 0
                            dot11ax.value += ", [ ] SU Beamformer"

                        su_beamformee_octet = element_data[11]
                        su_beamformee_octet_binary_string = ""
                        for bit_position in range(8):
                            su_beamformee_octet_binary_string += (
                                f"{int(get_bit(su_beamformee_octet, bit_position))}"
                            )
                        if int(su_beamformee_octet_binary_string[0]):
                            su_beamformee_support = True
                        else:
                            su_beamformee_support = False
                        if su_beamformee_support:
                            dot11ax_he_su_beamformee.db_value = 1
                            dot11ax.value += ", [X] SU Beamformee"
                        else:
                            dot11ax_he_su_beamformee.db_value = 0
                            dot11ax.value += ", [ ] SU Beamformee"

                        # BF STS
                        he_bf_sts_octet = element_data[11]

                        he_bf_sts_binary_string = "{0}{1}{2}".format(
                            int(get_bit(he_bf_sts_octet, 2)),
                            int(get_bit(he_bf_sts_octet, 3)),
                            int(get_bit(he_bf_sts_octet, 4)),
                        )
                        he_bf_sts_value = int(he_bf_sts_binary_string, base=2)
                        dot11ax_he_beamformee_sts.db_value = he_bf_sts_value
                        dot11ax.value += f", Beamformee STS={he_bf_sts_value}"

                        he_er_su_ppdu_octet = element_data[15]
                        he_er_su_ppdu_octet_binary_string = ""
                        for bit_position in range(8):
                            he_er_su_ppdu_octet_binary_string += (
                                f"{int(get_bit(he_er_su_ppdu_octet, bit_position))}"
                            )
                        if int(he_er_su_ppdu_octet_binary_string[0]):
                            he_er_su_ppdu_support = True
                        else:
                            he_er_su_ppdu_support = False
                        if he_er_su_ppdu_support:
                            dot11ax_he_er_su_ppdu.db_value = 1
                            dot11ax.value += ", [X] HE ER SU PPDU"
                        else:
                            dot11ax_he_er_su_ppdu.db_value = 0
                            dot11ax.value += ", [ ] HE ER SU PPDU"

                        uora_octet = element_data[4]
                        uora_octet_binary_string = ""
                        for bit_position in range(8):
                            uora_octet_binary_string += (
                                f"{int(get_bit(uora_octet, bit_position))}"
                            )

                        bsr_octet = element_data[3]
                        bsr_octet_binary_string = ""
                        for bit_position in range(8):
                            bsr_octet_binary_string += (
                                f"{int(get_bit(bsr_octet, bit_position))}"
                            )

                        if int(bsr_octet_binary_string[3]):
                            bsr_support = True
                        else:
                            bsr_support = False
                        if bsr_support:
                            dot11ax_bsr.db_value = 1
                            dot11ax.value += ", [X] BSR"
                        else:
                            dot11ax_bsr.db_value = 0
                            dot11ax.value += ", [ ] BSR"
                        continue

                    if ext_ie_id == HE_SPATIAL_REUSE_IE_EXT_TAG:
                        dot11ax_spatial_reuse.db_value = 1

                    if ext_ie_id == HE_6_GHZ_BAND_CAP_IE_EXT_TAG:
                        dot11ax_six_ghz.name = "6 GHz Capability"
                        dot11ax_six_ghz.value = "Supported"
                        dot11ax_six_ghz.db_value = 1

                    if ext_ie_id == HE_CAPABILITIES_IE_EXT_TAG:
                        # dot11ax is supported
                        dot11ax.value = "Supported"
                        dot11ax.db_value = 1

        dot11be = Capability(
            name="802.11be",
            value="Not supported",
            db_key="dot11be",
            db_value=0,
        )
        dot11be_nss = Capability(
            db_key="dot11be_nss",
            db_value=0,
        )
        dot11be_mcs = Capability(
            db_key="dot11be_mcs",
            db_value="",
        )
        dot11be_320_mhz = Capability(db_key="dot11be_320_mhz", db_value=0)

        if be_disabled:
            dot11be.value = "Reporting disabled (--no11be option used)"
        else:
            if IE_EXT_TAG in dot11_elt_dict.keys():
                for element_data in dot11_elt_dict[IE_EXT_TAG]:
                    ext_ie_id = int(str(element_data[0]))

                    if ext_ie_id == EHT_CAPABILITIES_IE_EXT_TAG:
                        # dot11be is supported
                        dot11be.value = "Supported"
                        dot11be.db_value = 1

                        element_data[1]
                        element_data[2]
                        eht_phy_cap_1 = element_data[3]
                        element_data[4]
                        element_data[5]
                        element_data[6]
                        element_data[7]
                        element_data[8]
                        element_data[9]
                        element_data[10]
                        element_data[11]
                        element_data[12]
                        element_data[13]
                        element_data[14]
                        # element_data[15]  IndexError: list index out of range
                        # element_data[16]
                        # element_data[17]

                        if get_bit(eht_phy_cap_1, 2):
                            dot11be.value += ", [X] 320 MHz"
                            dot11be_320_mhz.db_value = 1
                        else:
                            dot11be.value += ", [ ] 320 MHz"

        return [
            dot11ax,
            dot11ax_nss,
            dot11ax_mcs,
            dot11ax_twt,
            dot11ax_bsr,
            dot11ax_punctured_preamble,
            dot11ax_he_su_beamformer,
            dot11ax_he_su_beamformee,
            dot11ax_he_beamformee_sts,
            dot11ax_he_er_su_ppdu,
            dot11ax_six_ghz,
            dot11ax_160_mhz,
            dot11be,
            dot11be_nss,
            dot11be_mcs,
            dot11be_320_mhz,
        ]

    def analyze_assoc_req(self, frame, is_6ghz: bool) -> Tuple[str, str, list]:
        """Tear apart the association request for analysis"""
        log = logging.getLogger(inspect.stack()[0][3])

        # log.debug("processing information elements for client MAC %s", frame.addr2)

        # strip radiotap
        ie_buffer = bytes(frame.payload)

        # strip dot11
        ie_buffer = ie_buffer[24:]

        # strip params
        ie_buffer = ie_buffer[4:]

        # strip fcs
        ie_buffer = ie_buffer[:-4]

        # convert buffer to ie dict
        dot11_elt_dict = self.process_information_elements(ie_buffer)

        log.debug(
            "%s IEs detected in assoc req from %s: %s",
            len(dot11_elt_dict),
            frame.addr2,
            dot11_elt_dict.keys(),
        )

        #  resolve manufacturer
        oui_manuf = self.resolve_oui_manuf(frame.addr2, dot11_elt_dict)

        # parse chipset
        chipset = self.resolve_vendor_specific_tag_chipset(dot11_elt_dict)

        ssid = self.analyze_ssid_ie(dot11_elt_dict)

        # dictionary to store capabilities as we decode them
        capabilities = []

        # check if 11k supported
        capabilities += self.analyze_rm_capabilities_ie(dot11_elt_dict)

        # check if 11r supported
        capabilities += self.analyze_ft_capabilities_ie(
            dot11_elt_dict, self.ft_disabled
        )

        # check if 11v supported
        capabilities += self.analyze_ext_capabilities_ie(dot11_elt_dict)

        # check if 11w supported
        capabilities += self.analyze_rsn_capabilities_ie(dot11_elt_dict)

        # check for 11n support
        capabilities += self.analyze_ht_capabilities_ie(dot11_elt_dict)

        # check for 11ac support
        capabilities += self.analyze_vht_capabilities_ie(dot11_elt_dict)

        # check for ext tags (e.g. 802.11ax support, 802.11be draft support)
        capabilities += self.analyze_extension_ies(
            dot11_elt_dict, self.he_disabled, self.be_disabled
        )

        # check supported operating classes for 6 GHz
        capabilities += self.analyze_operating_classes(dot11_elt_dict)

        # check supported power capabilities
        capabilities += self.analyze_power_capability_ie(dot11_elt_dict)

        # check supported channels
        capabilities += self.analyze_supported_channels_ie(dot11_elt_dict, is_6ghz)

        return ssid, oui_manuf, chipset, capabilities
