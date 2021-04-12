# -*- coding: utf-8 -*-
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2020-2021 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.profiler
~~~~~~~~~~~~~~~~~

profiler code goes here, separate from fake ap code.
"""

# standard library imports
import csv
import inspect
import json
import logging
import os
import signal
import sys
import time
from difflib import Differ
from time import strftime
from typing import List, Tuple

# third party imports
from manuf import manuf
from scapy.all import Dot11, RadioTap, wrpcap

# app imports
from .__version__ import __version__
from .constants import (_20MHZ_CHANNEL_LIST, EXT_CAPABILITIES_IE_TAG,
                        FT_CAPABILITIES_IE_TAG, HE_6_GHZ_BAND_CAP_IE_EXT_TAG,
                        HE_CAPABILITIES_IE_EXT_TAG,
                        HE_SPATIAL_REUSE_IE_EXT_TAG, HT_CAPABILITIES_IE_TAG,
                        IE_EXT_TAG, POWER_MIN_MAX_IE_TAG,
                        RM_CAPABILITIES_IE_TAG, RSN_CAPABILITIES_IE_TAG,
                        SSID_PARAMETER_SET_IE_TAG, SUPPORTED_CHANNELS_IE_TAG,
                        VENDOR_SPECIFIC_IE_TAG, VHT_CAPABILITIES_IE_TAG)
from .helpers import (Base64Encoder, Capability, flag_last_object, get_bit,
                      is_randomized)


class Profiler(object):
    """ Code handling analysis of client capablities """

    def __init__(self, config=None, queue=None):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.parent_pid = os.getppid()
        self.log.debug("profiler pid: %s; parent pid: %s", os.getpid(), self.parent_pid)
        self.analyzed_hash = {}
        self.config = config
        if config:

            channel = config.get("GENERAL").get("channel")
            if channel:
                self.channel = int(channel)
            else:
                self.log.warn("profiler cannot determine channel from config")

            self.listen_only = config.get("GENERAL").get("listen_only")
            self.files_path = config.get("GENERAL").get("files_path")
            self.pcap_analysis = config.get("GENERAL").get("pcap_analysis")
            self.ft_disabled = config.get("GENERAL").get("ft_disabled")
            self.he_disabled = config.get("GENERAL").get("he_disabled")
            self.reports_dir = os.path.join(self.files_path, "reports")
            self.clients_dir = os.path.join(self.files_path, "clients")
            self.csv_file = os.path.join(
                self.reports_dir, f"profiler-{time.strftime('%Y-%m-%d')}.csv"
            )
        self.client_profiled_count = 0
        self.lookup = manuf.MacParser(update=False)
        self.last_manuf = "N/A"
        self.running = True
        self.run(queue)

    def run(self, queue) -> None:
        """ Runner which performs checks prior to profiling an association request """
        if queue:
            buffer = {}
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
                            "exit because we were told to only analyze %s",
                            self.pcap_analysis,
                        )
                        sys.exit(signal.SIGTERM)

    def profile(self, frame) -> None:
        """ Handle profiling clients as they come into the queue """
        ssid, oui_manuf, capabilities = self.analyze_assoc_req(frame)
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

            # we want channel from frame, not from profiler.
            channel = _20MHZ_CHANNEL_LIST[frame.ChannelFrequency]
            if channel < 15:
                band = "2.4GHz"
            elif channel > 30 and channel < 170:
                band = "5.8GHz"
            else:
                band = "unknown"

            if self.listen_only:
                self.log.info(
                    "discovered association request for %s to %s",
                    frame.addr2,
                    ssid,
                )

            # generate text report
            text_report = self.generate_text_report(
                text_report_oui_manuf,
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
        capabilities: list,
        client_mac: str,
        channel: int,
        band: str,
        ssid: str,
        listen_only: bool,
    ) -> str:
        """ Generate a report for output """
        # start report
        text_report = "-" * 45
        if listen_only:
            text_report += f"\n - SSID: {ssid}"
        text_report += f"\n - Client MAC: {client_mac}"
        text_report += f"\n - OUI manufacturer lookup: {oui_manuf or 'Unknown'}"
        band_label = ""
        if band[0] == "2":
            band_label = "2.4 GHz"
        if band[0] == "5":
            band_label = "5 GHz"
        if band[0] == "6":
            band_label = "6 GHz"
        text_report += f"\n - Frequency band: {band_label}"
        text_report += f"\n - Capture channel: {channel}\n"
        text_report += "-" * 45
        text_report += "\n"
        for capability in capabilities:
            if capability.name is not None and capability.value is not None:
                text_report += (
                    "{0:<20} {1:<20}".format(capability.name, capability.value) + "\n"
                )

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
        randomized: bool,
        band,
        channel,
        listen_only,
    ):
        """ Write report files out to a directory on the WLAN Pi """
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
        if band[0] == "2":
            band_db = 2
        elif band[0] == "5":
            band_db = 5
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

        text_filename = os.path.join(dest, f"{client_mac}_{band}.txt")

        json_filename = os.path.join(dest, f"{client_mac}_{band}.json")

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

            with open(json_filename, "w") as writer:
                json.dump(data, writer)

            if os.path.exists(text_filename):
                with open(text_filename, "r") as _file:
                    existing_text = _file.readlines()
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

            with open(text_filename, "w") as writer:
                writer.write(text_report)

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
        wrpcap(pcap_filename, [frame])

        # check if csv file exists
        if not os.path.exists(self.csv_file):

            # create file with csv headers
            with open(self.csv_file, mode="w") as file_obj:
                writer = csv.DictWriter(file_obj, fieldnames=out_fieldnames)
                writer.writeheader()

        # append data to csv file
        with open(self.csv_file, mode="a") as file_obj:
            writer = csv.DictWriter(file_obj, fieldnames=out_fieldnames)
            writer.writerow(out_row)

    @staticmethod
    def process_information_elements(buffer: bytes) -> dict:
        """
        Parse a 802.11 payload and returns a dict of IEs

        Does not handle headers or FCS.

        You must strip those before passing the payload in.
        """
        # init element vars
        information_elements = {}
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

    def resolve_oui_manuf(self, mac: str, dot11_elt_dict: dict) -> str:
        """ Resolve client's manuf using manuf database and other heuristics """
        log = logging.getLogger(inspect.stack()[0][3])

        # log.debug("starting oui lookup for %s", mac)
        oui_manuf = self.lookup.get_manuf(mac)

        # vendor OUI that we possibly want to check for a more clear OUI match
        low_quality = "muratama"

        if oui_manuf is None or oui_manuf.lower().startswith(low_quality):
            # inspect vendor specific IEs and see if there's an IE with
            # an OUI that we know can only be included if the manuf
            # of the client is the vendor that maps to that OUI
            if VENDOR_SPECIFIC_IE_TAG in dot11_elt_dict.keys():
                for element_data in dot11_elt_dict[VENDOR_SPECIFIC_IE_TAG]:
                    vendor_mac = "{0:02X}:{1:02X}:{2:02X}:00:00:00".format(
                        element_data[0], element_data[1], element_data[2]
                    )
                    oui_manuf_vendor = self.lookup.get_manuf(vendor_mac)
                    if oui_manuf_vendor is not None:
                        # Matches are vendor specific IEs we know are client specific
                        # e.g. Apple vendor specific IEs can only be found in Apple devices
                        # Samsung may follow similar logic based on S10 5G testing, but unsure
                        matches = ("apple", "samsung")
                        if oui_manuf_vendor.lower().startswith(matches):
                            oui_manuf = oui_manuf_vendor

        log.debug("finished oui lookup for %s: %s", mac, oui_manuf)
        return oui_manuf

    @staticmethod
    def analyze_ssid_ie(dot11_elt_dict: dict) -> str:
        if SSID_PARAMETER_SET_IE_TAG in dot11_elt_dict.keys():
            ssid = bytes(dot11_elt_dict[SSID_PARAMETER_SET_IE_TAG]).decode("utf-8")
            return f"{ssid}"

    @staticmethod
    def analyze_ht_capabilities_ie(dot11_elt_dict: dict) -> List:
        """ Check for 802.11n support """
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
    def analyze_vht_capabilities_ie(dot11_elt_dict: dict) -> List:
        """ Check for 802.11ac support """
        dot11ac = Capability(
            name="802.11ac", value="Not reported*", db_key="dot11ac", db_value=0
        )
        dot11ac_nss = Capability(db_key="dot11ac_nss", db_value=0)
        dot11ac_mcs = Capability(db_key="dot11ac_mcs", db_value=0)
        dot11ac_su_bf = Capability(db_key="dot11ac_su_bf", db_value=0)
        dot11ac_mu_bf = Capability(db_key="dot11ac_mu_bf", db_value=0)
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
            mcs = ", ".join(mcs) if len(mcs) > 1 else mcs[0]
            dot11ac.value = f"Supported ({nss}ss), MCS {mcs}"
            dot11ac_nss.db_value = nss
            dot11ac_mcs.db_value = mcs

            # check for SU & MU beam formee support
            mu_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][2]
            su_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][1]
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

        return [
            dot11ac,
            dot11ac_nss,
            dot11ac_160_mhz,
            dot11ac_mcs,
            dot11ac_su_bf,
            dot11ac_mu_bf,
        ]

    @staticmethod
    def analyze_rm_capabilities_ie(dot11_elt_dict: dict) -> []:
        """ Check for 802.11k support """
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
    def analyze_ft_capabilities_ie(dot11_elt_dict: dict, ft_disabled: bool) -> List:
        """ Check for 802.11r support """
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
    def analyze_ext_capabilities_ie(dot11_elt_dict: dict) -> List:
        """ Check for 802.11v support """
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
    def analyze_rsn_capabilities_ie(dot11_elt_dict: dict) -> List:
        """ Check for 802.11w support """
        dot11w = Capability(
            name="802.11w", value="Not reported", db_key="dot11w", db_value=0
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
    def analyze_power_capability_ie(dot11_elt_dict: dict) -> List:
        """ Check for supported power capabilities """
        max_power_cap = Capability(
            name="Max Power",
            value="Not reported",
            db_key="max_power",
            db_value=0,
        )
        min_power_cap = Capability(
            # name="Min Power",
            # value="Not reported",
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
    def analyze_supported_channels_ie(dot11_elt_dict: dict) -> List:
        """ Check supported channels """
        supported_channels = Capability(
            name="Supported Channels",
            value="Not reported",
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

            while channel_sets_list:

                start_channel = channel_sets_list.pop(0)
                channel_range = channel_sets_list.pop(0)

                # check for if 2.4Ghz or 5GHz
                if start_channel > 14:
                    channel_multiplier = 4
                else:
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
    def analyze_extension_ies(dot11_elt_dict: dict, he_disabled: bool) -> List:
        """ Check for 802.11ax support """
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
        dot11ax_nss = Capability(db_key="dot11ax_nss", db_value=0)
        dot11ax_mcs = Capability(db_key="dot11ax_mcs", db_value="")
        dot11ax_twt = Capability(db_key="dot11ax_twt", db_value=0)
        dot11ax_uora = Capability(db_key="dot11ax_uora", db_value=0)
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
                        mcs = ", ".join(mcs) if len(mcs) > 1 else mcs[0]
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

                        if int(uora_octet_binary_string[2]):
                            uora_support = True
                        else:
                            uora_support = False
                        if uora_support:
                            dot11ax_uora.db_value = 1
                            dot11ax.value += ", [X] UORA"
                        else:
                            dot11ax_uora.db_value = 0
                            dot11ax.value += ", [ ] UORA"

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
                        # dot11ax_six_ghz.value = "Supported"
                        dot11ax_six_ghz.db_value = 1

        return [
            dot11ax,
            dot11ax_nss,
            dot11ax_mcs,
            dot11ax_twt,
            dot11ax_uora,
            dot11ax_bsr,
            dot11ax_punctured_preamble,
            dot11ax_he_er_su_ppdu,
            dot11ax_six_ghz,
            dot11ax_160_mhz,
        ]

    def analyze_assoc_req(self, frame) -> Tuple[str, list]:
        """ Tear apart the association request for analysis """
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

        # check for Ext tags (e.g. 802.11ax draft support)
        capabilities += self.analyze_extension_ies(dot11_elt_dict, self.he_disabled)

        # check supported power capabilities
        capabilities += self.analyze_power_capability_ie(dot11_elt_dict)

        # check supported channels
        capabilities += self.analyze_supported_channels_ie(dot11_elt_dict)

        return ssid, oui_manuf, capabilities
