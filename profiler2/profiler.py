# -*- coding: utf-8 -*-
#
# profiler2: a Wi-Fi client capability analyzer
# Copyright 2020 Josh Schmelzle
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
profiler2.profiler
~~~~~~~~~~~~~~~~~~

profiler code goes here, separate from fake ap code.
"""

# standard library imports
import csv
import inspect
import logging
import os
import sys
import time
from difflib import Differ
from multiprocessing.queues import Queue
from typing import Tuple

# third party imports
from manuf import manuf
from scapy.all import wrpcap

# app imports
from .constants import (
    EXT_CAPABILITIES_IE_TAG,
    FT_CAPABILITIES_IE_TAG,
    HT_CAPABILITIES_IE_TAG,
    POWER_MIN_MAX_IE_TAG,
    RM_CAPABILITIES_IE_TAG,
    RSN_CAPABILITIES_IE_TAG,
    SUPPORTED_CHANNELS_IE_TAG,
    VENDOR_SPECIFIC_IE_TAG,
    VHT_CAPABILITIES_IE_TAG,
    IE_EXT_TAG,
    HE_CAPABILITIES_IE_EXT_TAG,
    HE_6_GHZ_BAND_CAP_IE_EXT_TAG,
)
from .helpers import Capability, flag_last_object


class Profiler(object):
    """ Code handling analysis of client capablities """

    def __init__(self, config=None, queue=None):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.debug("profiler pid: %s; parent pid: %s", os.getpid(), os.getppid())
        self.analyzed_hash = {}
        self.config = config
        if config:
            self.channel = int(config.get("GENERAL").get("channel"))
            self.ssid = config.get("GENERAL").get("ssid")
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

        if queue:
            while True:
                self.profile(queue)

    def __del__(self):
        """ Clean up while we shut down """

    def is_randomized(self, mac) -> bool:
        """ Check if MAC Address <format>:'00:00:00:00:00:00' is locally assigned """
        return any(local == mac[1] for local in ["2", "6", "a", "e"])

    def profile(self, queue: Queue) -> None:
        """ Handle profiling clients as they come into the queue """
        frame = queue.get()
        oui_manuf, capabilities = self.analyze_assoc_req(frame)
        analysis_hash = hash(f"{frame.addr2}: {capabilities}")
        if analysis_hash in self.analyzed_hash.keys():
            self.log.debug(
                "already seen %s (capabilities hash=%s) this session, ignoring...",
                frame.addr2,
                analysis_hash,
            )
        else:

            if self.is_randomized(frame.addr2):
                if oui_manuf is None:
                    oui_manuf = "Randomized MAC"
                else:
                    oui_manuf = "{0} (Randomized MAC)".format(oui_manuf)

            self.last_manuf = oui_manuf
            self.log.debug("%s oui lookup matched to %s", frame.addr2, oui_manuf)
            self.analyzed_hash[analysis_hash] = frame
            text_report = self.generate_text_report(
                oui_manuf, capabilities, frame.addr2, self.channel
            )

            self.log.info("text report\n%s", text_report)

            if self.channel < 15:
                band = "2.4GHz"
            elif self.channel > 30 and self.channel < 170:
                band = "5.8GHz"
            else:
                band = "unknown"

            self.log.debug(
                "writing text and csv report for %s (capabilities hash=%s)",
                frame.addr2,
                analysis_hash,
            )
            self.write_analysis_to_file_system(
                text_report, capabilities, frame, oui_manuf, band
            )

            self.client_profiled_count += 1
            self.log.debug("%s clients profiled", self.client_profiled_count)

            # if we end up sending multiple frames from pcap for profiling - this will need changed
            if self.pcap_analysis:
                self.log.info(
                    "exiting because we were told to only analyze %s",
                    self.pcap_analysis,
                )
                sys.exit()

    @staticmethod
    def generate_text_report(
        oui_manuf: str, capabilities: list, client_mac: str, channel: int
    ) -> str:
        """ Generate a report for output """
        # start report
        text_report = "-" * 45
        text_report += f"\n - Client MAC: {client_mac}"
        text_report += f"\n - OUI manufacturer lookup: {oui_manuf or 'Unknown'}"
        text_report += f"\n - Capture channel: {channel}\n"
        text_report += "-" * 45
        text_report += "\n"
        for capability in capabilities:
            if capability.name is not None and capability.value is not None:
                text_report += (
                    "{0:<20} {1:<20}".format(capability.name, capability.value) + "\n"
                )

        text_report += "\n* Reported client capabilities are dependent on available features at time of client association."
        text_report += "\n** Reported channels do not factor local regulatory domain."
        return text_report

    def write_analysis_to_file_system(
        self, text_report, capabilities, frame, oui_manuf, band
    ):
        """ Write report files out to a directory on the WLAN Pi """
        log = logging.getLogger(inspect.stack()[0][3])
        # dump out the text to a file
        client_mac = frame.addr2.replace(":", "-", 5)
        dest = os.path.join(self.clients_dir, client_mac)

        if not os.path.isdir(dest):
            try:
                os.mkdir(dest)
            except Exception:
                log.error("problem creating %s directory", dest)
                sys.exit(-1)

        filename = os.path.join(dest, f"{client_mac}_{band}.txt")

        try:
            if os.path.exists(filename):

                existing = open(filename, "r").readlines()
                temp = []
                for line in existing:
                    temp.append(line.replace("\n", ""))
                existing = temp
                new = text_report.split("\n")
                # strip header when comparing existing file from newly profiled
                if existing[5:] == new[5:]:
                    pass
                else:
                    text_report = list(
                        Differ().compare(existing, text_report.split("\n"))
                    )
                    filename = filename.replace(".txt", "_changed.txt")
                    text_report = "\n".join(text_report)
            with open(filename, "w") as writer:
                writer.write(text_report)
        except Exception:
            log.exception("error creating flat file to dump client info (%s)", filename)
            sys.exit(-1)

        out_row = {"Client_Mac": client_mac, "OUI_Manuf": oui_manuf}

        out_fieldnames = ["Client_Mac", "OUI_Manuf"]

        for capability in capabilities:
            if capability.name is not None and capability.value is not None:
                out_fieldnames.append(capability.name)
                out_row[capability.name] = capability.value

        # dump out the frame to a file
        filename = os.path.splitext(filename)[0] + ".pcap"
        wrpcap(filename, [frame])

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
    def analyze_ht_capabilities_ie(dot11_elt_dict: dict) -> []:
        """ Check for 802.11n support """
        dot11n = Capability(
            name="802.11n", value="Not reported*", db_key="802.11n", db_value=0
        )
        dot11n_ss = Capability(db_key="802.11n_ss", db_value=0)

        if HT_CAPABILITIES_IE_TAG in dot11_elt_dict.keys():

            spatial_streams = 0

            # mcs octets 1 - 4 indicate # streams supported (up to 4 streams only)
            for mcs_octet in range(3, 7):

                mcs_octet_value = dot11_elt_dict[HT_CAPABILITIES_IE_TAG][mcs_octet]

                if mcs_octet_value & 255:
                    spatial_streams += 1

            dot11n.value = f"Supported ({spatial_streams}ss)"
            dot11n.db_value = 1
            dot11n_ss.db_value = spatial_streams

        return [dot11n, dot11n_ss]

    @staticmethod
    def analyze_vht_capabilities_ie(dot11_elt_dict: dict) -> []:
        """ Check for 802.11ac support """
        dot11ac = Capability(
            name="802.11ac", value="Not reported*", db_key="802.11ac", db_value=0
        )
        dot11ac_ss = Capability(db_key="802.11ac_ss", db_value=0)
        dot11ac_su_bf = Capability(db_key="802.11ac_su_bf", db_value=0)
        dot11ac_mu_bf = Capability(db_key="802.11ac_mu_bf", db_value=0)

        if VHT_CAPABILITIES_IE_TAG in dot11_elt_dict.keys():
            # Check for number streams supported
            mcs_upper_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][5]
            mcs_lower_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][4]
            mcs_rx_map = (mcs_upper_octet * 256) + mcs_lower_octet

            # define the bit pair we need to look at
            spatial_streams = 0
            stream_mask = 3

            # move through each bit pair & test for '10' (stream supported)
            for _mcs_bits in range(1, 9):

                if (mcs_rx_map & stream_mask) != stream_mask:

                    # stream mask bits both '1' when mcs map range not supported
                    spatial_streams += 1

                # shift to next mcs range bit pair (stream)
                stream_mask = stream_mask * 4

            dot11ac.value = f"Supported ({spatial_streams}ss)"
            dot11ac.db_value = 1
            dot11ac_ss.db_value = spatial_streams

            # check for SU & MU beam formee support
            mu_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][2]
            su_octet = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG][1]

            beam_form_mask = 16

            # bit 4 indicates support for both octets (1 = supported, 0 = not supported)
            if su_octet & beam_form_mask:
                dot11ac.value += ", SU BF supported"
                dot11ac_su_bf.db_value = 1
            else:
                dot11ac.value += ", SU BF not supported"

            if mu_octet & beam_form_mask:
                dot11ac.value += ", MU BF supported"
                dot11ac_mu_bf.db_value = 1
            else:
                dot11ac.value += ", MU BF not supported"

        return [dot11ac, dot11ac_ss, dot11ac_su_bf, dot11ac_mu_bf]

    @staticmethod
    def analyze_rm_capabilities_ie(dot11_elt_dict: dict) -> []:
        """ Check for 802.11k support """
        dot11k = Capability(
            name="802.11k",
            value="Not reported* - treat with caution, many clients lie about this",
            db_key="802.11k",
            db_value=0,
        )
        if RM_CAPABILITIES_IE_TAG in dot11_elt_dict.keys():
            dot11k.value = "Supported"
            dot11k.db_value = 1

        return [dot11k]

    @staticmethod
    def analyze_ft_capabilities_ie(dot11_elt_dict: dict, ft_disabled: bool) -> []:
        """ Check for 802.11r support """
        dot11r = Capability(
            name="802.11r", value="Not reported*", db_key="802.11r", db_value=0
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
    def analyze_ext_capabilities_ie(dot11_elt_dict: dict) -> []:
        """ Check for 802.11v support """
        dot11v = Capability(
            name="802.11v", value="Not reported*", db_key="802.11v", db_value=0
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
    def analyze_rsn_capabilities_ie(dot11_elt_dict: dict) -> []:
        """ Check for 802.11w support """
        dot11w = Capability(
            name="802.11w", value="Not reported", db_key="802.11w", db_value=0
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
    def analyze_power_capability_ie(dot11_elt_dict: dict) -> []:
        """ Check for supported power capabilities """
        max_power_cap = Capability(
            name="Max_Power",
            value="Not reported",
            db_key="max_power",
            db_value="Not reported",
        )
        min_power_cap = Capability(
            name="Min_Power",
            value="Not reported",
            db_key="min_power",
            db_value="Not reported",
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
    def analyze_supported_channels_ie(dot11_elt_dict: dict) -> []:
        """ Check supported channels """
        supported_channels = Capability(
            name="Supported_Channels",
            value="Not reported",
            db_key="SupportedChannels",
            db_value=None,
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

                for i in range(channel_range):
                    channel_list.append(start_channel + (i * channel_multiplier))

            supported_channels.value = ",".join(map(str, channel_list))
            supported_channels.db_value = channel_list

        return [supported_channels]

    @staticmethod
    def analyze_extension_ies(dot11_elt_dict: dict, he_disabled: bool) -> []:
        """ Check for 802.11ax support """
        dot11ax = Capability(
            name="802.11ax",
            value="Not supported",
            db_key="802.11ax",
            db_value="0",
        )
        six_ghz = Capability(
            name="6 GHz",
            value="Not supported",
            db_key="six_ghz",
            db_value="0",
        )

        if he_disabled:
            dot11ax.value = "Reporting disabled (--no11ax option used)"
        else:
            if IE_EXT_TAG in dot11_elt_dict.keys():
                for element_data in dot11_elt_dict[IE_EXT_TAG]:

                    ext_ie_id = int(str(element_data[0]))

                    if ext_ie_id == HE_CAPABILITIES_IE_EXT_TAG:
                        dot11ax.value = "Supported"
                        dot11ax.db_value = 1
                        continue
                    if ext_ie_id == HE_6_GHZ_BAND_CAP_IE_EXT_TAG:
                        six_ghz.value = "Supported"
                        six_ghz.db_value = 1

        return [dot11ax]  # , six_ghz]

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

        return oui_manuf, capabilities
