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
import csv, inspect, logging
import os, sys
import time

# third party imports
from manuf import manuf

from scapy.all import wrpcap

# app imports
from .constants import (
    CLIENTS_DIR,
    EXT_CAPABILITIES_TAG,
    EXT_IE_TAG,
    FT_CAPABILITIES_TAG,
    HT_CAPABILITIES_TAG,
    POWER_MIN_MAX_TAG,
    REPORTS_DIR,
    RM_CAPABILITIES_TAG,
    ROOT_DIR,
    RSN_CAPABILITIES_TAG,
    SUPPORTED_CHANNELS_TAG,
    VHT_CAPABILITIES_TAG,
)
from .helpers import Capability, flag_last_object, generate_menu_report


class Profiler(object):
    """ Code handling analysis of client capablities """

    def __init__(self, config, queue):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.debug("profiler pid: %s; parent pid: %s", os.getpid(), os.getppid())
        self.analyzed_hash = {}
        self.config = config
        self.channel = int(config.get("GENERAL").get("channel"))
        self.ssid = config.get("GENERAL").get("ssid")
        self.menu_mode = config.get("GENERAL").get("menu_mode")
        self.files_root = config.get("GENERAL").get("files_root")
        self.pcap_analysis = config.get("GENERAL").get("pcap_analysis")
        self.ft_disabled = config.get("GENERAL").get("ft_disabled")
        self.he_disabled = config.get("GENERAL").get("he_disabled")
        self.reports_dir = os.path.join(self.files_root, ROOT_DIR, REPORTS_DIR)
        self.clients_dir = os.path.join(self.files_root, ROOT_DIR, CLIENTS_DIR)
        self.client_profiled_count = 0
        self.last_manuf = "N/A"
        if self.menu_mode:
            generate_menu_report(
                self.config, self.client_profiled_count, self.last_manuf, "running"
            )
        self.csv_file = os.path.join(
            self.reports_dir, f"db-{time.strftime('%Y-%m-%dt%H-%M-%S')}.csv"
        )

        while True:
            self.profile(queue)

    def __del__(self):
        if self.menu_mode:
            generate_menu_report(self.config, 0, "N/A", "stopped")

    def profile(self, queue):
        """ Handle profiling clients as they come into the queue """
        frame = queue.get()
        if frame.addr2 in self.analyzed_hash.keys():
            self.log("already seen %s, ignoring...", frame.addr2)
        else:
            # self.log.debug(
            #    f"addr1 (TA): {frame.addr1} addr2 (RA): {frame.addr2} addr3 (SA): {frame.addr3} addr4 (DA): {frame.addr4}"
            # )
            self.analyzed_hash[frame.addr2] = frame

            self.log.debug("starting oui lookup for %s", frame.addr2)
            lookup = manuf.MacParser(update=False)
            oui_manuf = lookup.get_manuf(frame.addr2)
            self.last_manuf = oui_manuf
            self.log.debug("%s oui lookup matched to %s", frame.addr2, oui_manuf)

            capabilities = self.analyze_assoc_req(frame)

            text_report = self.generate_text_report(
                oui_manuf, capabilities, frame.addr2, self.channel
            )

            self.log.info(text_report)

            if self.channel < 15:
                band = "2.4GHz"
            elif self.channel > 30 and self.channel < 170:
                band = "5.8GHz"
            else:
                band = "unknown"

            self.log.debug("writing assoc req from %s to file", frame.addr2)
            self.write_assoc_req_pcap(frame, band)

            self.log.debug("writing text and csv report for %s", frame.addr2)
            self.write_analysis_to_file_system(
                text_report, capabilities, frame.addr2, oui_manuf, band
            )

            self.client_profiled_count += 1
            self.log.debug("%s clients profiled", self.client_profiled_count)
            if self.menu_mode:
                generate_menu_report(
                    self.config, self.client_profiled_count, self.last_manuf, "running"
                )
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
        return text_report

    def write_analysis_to_file_system(
        self, text_report, capabilities, client_mac, oui_manuf, band
    ):
        """ Write report files out to a directory on the WLAN Pi """
        log = logging.getLogger(inspect.stack()[0][3])
        # dump out the text to a file
        client_mac = client_mac.replace(":", "-", 5)
        dest = os.path.join(self.clients_dir, client_mac)

        if not os.path.isdir(dest):
            try:
                os.mkdir(dest)
            except Exception:
                log.error("problem creating %s directory", dest)
                sys.exit(-1)

        filename = os.path.join(dest, f"{client_mac}_{band}.txt")
        try:
            with open(filename, "w") as writer:
                writer.write(text_report)
        except Exception:
            log.error("error creating flat file to dump client info (%s)", filename)
            sys.exit(-1)

        out_row = {"Client_Mac": client_mac, "OUI_Manuf": oui_manuf}

        out_fieldnames = ["Client_Mac", "OUI_Manuf"]

        for capability in capabilities:
            if capability.name is not None and capability.value is not None:
                out_fieldnames.append(capability.name)
                out_row[capability.name] = capability.value

        # Check if csv file exists
        if not os.path.exists(self.csv_file):

            # create file with csv headers
            with open(self.csv_file, mode="w") as file_obj:
                writer = csv.DictWriter(file_obj, fieldnames=out_fieldnames)
                writer.writeheader()

        # append data to csv file
        with open(self.csv_file, mode="a") as file_obj:
            writer = csv.DictWriter(file_obj, fieldnames=out_fieldnames)
            writer.writerow(out_row)

    def write_assoc_req_pcap(self, frame, band):
        """ Write client association request to pcap file on WLAN Pi """
        log = logging.getLogger(inspect.stack()[0][3])
        mac = frame.addr2.replace(":", "-", 5)
        dest = os.path.join(self.clients_dir, mac)

        if not os.path.isdir(dest):
            try:
                os.mkdir(dest)
            except Exception:
                log.error("problem creating %s directory", dest)
                sys.exit(-1)

        # dump out the frame to a file
        filename = os.path.join(dest, f"{mac}_{band}.pcap")
        wrpcap(filename, [frame])

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
                information_elements[element_id] = element_data
        return information_elements

    @staticmethod
    def analyze_ht_capabilities_ie(dot11_elt_dict: dict) -> []:
        """ Check for 802.11n support """
        dot11n = Capability(
            name="802.11n", value="Not reported*", db_key="802.11n", db_value=0
        )
        dot11n_ss = Capability(db_key="802.11n_ss", db_value=0)

        if HT_CAPABILITIES_TAG in dot11_elt_dict.keys():

            spatial_streams = 0

            # mcs octets 1 - 4 indicate # streams supported (up to 4 streams only)
            for mcs_octet in range(3, 7):

                mcs_octet_value = dot11_elt_dict[HT_CAPABILITIES_TAG][mcs_octet]

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

        if VHT_CAPABILITIES_TAG in dot11_elt_dict.keys():
            # Check for number streams supported
            mcs_upper_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][5]
            mcs_lower_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][4]
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
            mu_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][2]
            su_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][1]

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
        if RM_CAPABILITIES_TAG in dot11_elt_dict.keys():
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
        elif FT_CAPABILITIES_TAG in dot11_elt_dict.keys():
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

        if EXT_CAPABILITIES_TAG in dot11_elt_dict.keys():

            ext_cap_list = dot11_elt_dict[EXT_CAPABILITIES_TAG]

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

        if RSN_CAPABILITIES_TAG in dot11_elt_dict.keys():

            rsn_cap_list = dot11_elt_dict[RSN_CAPABILITIES_TAG]
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

        if POWER_MIN_MAX_TAG in dot11_elt_dict.keys():

            # octet 3 of power capabilites
            max_power = dot11_elt_dict[POWER_MIN_MAX_TAG][1]
            min_power = dot11_elt_dict[POWER_MIN_MAX_TAG][0]

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
        if SUPPORTED_CHANNELS_TAG in dot11_elt_dict.keys():
            channel_sets_list = dot11_elt_dict[SUPPORTED_CHANNELS_TAG]
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
        """
        Check for 802.11ax support

        TODO: Need to add more 11ax detection features and add them in to the
              report. For example: support for OFDMA UL, OFDMA DL, MU-MIMO UL
              MU-MIMO DL, BSS Colouring etc.
        """
        dot11ax_draft = Capability(
            name="802.11ax_draft",
            value="Not supported",
            db_key="802.11ax_draft",
            db_value="0",
        )
        if he_disabled:
            dot11ax_draft.value = "Reporting disabled (--no11ax option used)"
        else:
            if EXT_IE_TAG in dot11_elt_dict.keys():

                ext_ie_id = str(dot11_elt_dict[EXT_IE_TAG][0])

                dot11ax_draft_ids = {"35": "802.11ax (Draft)"}

                # check for 802.11ax support
                if ext_ie_id in dot11ax_draft_ids.keys():
                    dot11ax_draft.value = "Supported (Draft)"
                    dot11ax_draft.db_value = 1

        return [dot11ax_draft]

    def analyze_assoc_req(self, frame) -> []:
        """ Tear apart the association request for analysis """
        log = logging.getLogger(inspect.stack()[0][3])

        log.debug("processing information elements for client MAC %s", frame.addr2)

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

        return capabilities
