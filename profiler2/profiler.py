# -*- coding: utf-8 -*-

"""
profiler2.profiler
~~~~~~~~~~~~~~~~~~

profiler code goes here, separate from fake ap code.
"""

# standard library imports
import csv, inspect, logging
from manuf import manuf
import os, sys
import time

# third party imports
from scapy.all import hexdump, wrpcap, Dot11Elt

# app imports
from .helpers import generate_menu_report, flag_last_object, bytes_to_int

from .constants import (
    POWER_MIN_MAX_TAG,
    SUPPORTED_CHANNELS_TAG,
    HT_CAPABILITIES_TAG,
    RSN_CAPABILITIES_TAG,
    FT_CAPABILITIES_TAG,
    RM_CAPABILITIES_TAG,
    EXT_CAPABILITIES_TAG,
    VHT_CAPABILITIES_TAG,
    EXT_IE_TAG,
)


class Profiler(object):
    def __init__(
        self, args, queue, clients_dir, reports_dir, channel, ssid, menu_report_file
    ):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.info(f"profiler pid: {os.getpid()}")
        self.args = args
        self.analyzed_hash = {}
        self.channel = channel
        self.ssid = ssid
        self.client_profiled_count = 0
        self.last_manuf = "N/A"
        self.clients_dir = clients_dir
        self.reports_dir = reports_dir
        self.menu_report_file = menu_report_file
        if self.args.menu_mode:
            generate_menu_report(
                menu_report_file,
                self.channel,
                self.ssid,
                self.client_profiled_count,
                self.last_manuf,
                args,
            )
        self.csv_file = os.path.join(
            self.reports_dir, f"db-{time.strftime('%Y-%m-%dt%H-%M-%S')}.csv"
        )

        while True:
            frame = queue.get()
            if frame.addr2 in self.analyzed_hash.keys():
                self.log(f"already seen {frame.addr2}, ignoring...")
            else:
                # self.log.debug(
                #    f"addr1 (TA): {frame.addr1} addr2 (RA): {frame.addr2} addr3 (SA): {frame.addr3} addr4 (DA): {frame.addr4}"
                # )
                self.analyzed_hash[frame.addr2] = frame

                self.log.debug(f"starting oui lookup for {frame.addr2}")
                lookup = manuf.MacParser(update=False)
                oui_manuf = lookup.get_manuf(frame.addr2)
                self.last_manuf = oui_manuf
                self.log.debug(f"{frame.addr2} oui lookup matched to {oui_manuf}")

                analysis, capabilities, capability_dict = self.analyze_assoc_req(
                    oui_manuf, frame
                )

                print(analysis)

                # TODO: PORT IP DETECTION CODE OVER
                # print results URL
                # global SSH_DEST_IP

                # if SSH_DEST_IP:
                #    print("[View PCAP & Client Report : http://{}/profiler/clients/{} ]\n".format(SSH_DEST_IP, mac_addr))

                self.log.debug(f"writing assoc req from {frame.addr2} to file")
                self.write_assoc_req(frame)

                self.write_analysis(
                    analysis, capabilities, capability_dict, frame.addr2, oui_manuf
                )

                self.client_profiled_count += 1
                self.log.debug(f"{self.client_profiled_count} clients profiled")

                if args.menu_mode:
                    generate_menu_report(
                        menu_report_file,
                        self.channel,
                        self.ssid,
                        self.client_profiled_count,
                        self.last_manuf,
                        args,
                    )
                if args.file_analysis_only:
                    self.log.info(
                        f"exiting because we analyzed 1 frame from {args.file_analysis_only}"
                    )
                    sys.exit()

    def write_analysis(self, analysis, capabilities, capability_dict, mac, oui_manuf):
        log = logging.getLogger(inspect.stack()[0][3])
        # dump out the text to a file
        mac = mac.replace(":", "-", 5)
        filename = os.path.join(self.clients_dir, f"{mac}.txt")
        try:
            with open(filename, "w") as writer:
                writer.write(analysis)
        except Exception as error:
            log.error(f"error creating file to dump client info ({filename})")
            log.exception(error)
            sys.exit(-1)

        # Check if csv file exists
        if not os.path.exists(self.csv_file):

            # create file with csv headers
            with open(self.csv_file, mode="w") as file_obj:
                writer = csv.DictWriter(
                    file_obj, fieldnames=["Client_Mac"] + ["OUI_Manuf"] + capabilities
                )
                writer.writeheader()

        # append data to csv file
        with open(self.csv_file, mode="a") as file_obj:
            writer = csv.DictWriter(
                file_obj, fieldnames=["Client_Mac"] + ["OUI_Manuf"] + capabilities
            )
            writer.writerow(
                {
                    "Client_Mac": mac,
                    "OUI_Manuf": oui_manuf,
                    "802.11k": capability_dict["802.11k"],
                    "802.11r": capability_dict["802.11r"],
                    "802.11v": capability_dict["802.11v"],
                    "802.11w": capability_dict["802.11w"],
                    "802.11n": capability_dict["802.11n"],
                    "802.11ac": capability_dict["802.11ac"],
                    "802.11ax_draft": capability_dict["802.11ax_draft"],
                    "Max_Power": capability_dict["Max_Power"],
                    "Min_Power": capability_dict["Min_Power"],
                    "Supported_Channels": capability_dict["Supported_Channels"],
                }
            )

    def write_assoc_req(self, frame):
        log = logging.getLogger(inspect.stack()[0][3])
        mac = frame.addr2.replace(":", "-", 5)
        dest = os.path.join(self.clients_dir, mac)

        if not os.path.isdir(dest):
            try:
                os.mkdir(dest)
            except Exception as error:
                log.error(f"problem creating {dest} directory")
                log.exception(f"{error}")
                sys.exit(-1)

        # dump out the frame to a file
        filename = os.path.join(dest, f"{mac}.pcap")
        wrpcap(filename, [frame])

    @staticmethod
    def process_information_elements(frame):
        buffer = bytes(frame)
        # strip radiotap header
        buffer = buffer[32:]
        # strip dot11
        buffer = buffer[24:]
        # strip params
        buffer = buffer[4:]
        # strip fcs
        buffer = buffer[:-4]
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

    def analyze_assoc_req(self, oui_manuf, frame):
        log = logging.getLogger(inspect.stack()[0][3])

        log.debug(f"processing {frame.addr2} information elements")
        dot11_elt_dict = self.process_information_elements(frame)

        log.debug(f"{hexdump(frame)}")
        log.debug(dot11_elt_dict)
        log.debug(f"analyzing {frame.addr2} assoc req")

        # dot11_elt = frame.getlayer(Dot11Elt)

        # common dictionary to store all tag lists
        # dot11_elt_dict = {}

        # analyze the 802.11 frame tag lists & store in a dictionary
        # while dot11_elt:

            # get tag number
            # dot11_elt_id = str(dot11_elt.ID)

            # get tag list
            # dot11_elt_info = dot11_elt.getfieldval("info")
            # dot11_elt_info = dot11_elt.info

            # convert tag list in to usable format (decimal list of values)
            # py2 to py3 notes:
            #     Python 3 map returns a generator.
            #     Python 2 str is a sequence of bytes.
            #     Python 3 str is a sequence of unicode characters.
            #     Python 3 bytes are handled by the bytes type.
            #     bytes objects yield integers when iterating or indexing, not characters
            # dec_array = list(bytes(dot11_elt_info))

            # print(f"{dot11_elt_id}, {dot11_elt_info}, {dec_array}")
            # print(f"{type(dot11_elt_id)}, {type(dot11_elt_info)}, {type(dec_array)}")

            # store each tag list in a common tag dictionary
            # dot11_elt_dict[dot11_elt_id] = dec_array

            # move to next layer - end of while loop
            # dot11_elt = dot11_elt.payload.getlayer(Dot11Elt)
        log.debug(f"IDs of IEs detected {dot11_elt_dict.keys()}")
        # dictionary to store capabilities as we decode them
        capability_dict = {}

        # check if 11n supported
        if HT_CAPABILITIES_TAG in dot11_elt_dict.keys():
            capability_dict["802.11n"] = "Supported"

            spatial_streams = 0

            # mcs octets 1 - 4 indicate # streams supported (up to 4 streams only)
            for mcs_octet in range(3, 7):

                mcs_octet_value = dot11_elt_dict[HT_CAPABILITIES_TAG][mcs_octet]

                if mcs_octet_value & 255:
                    spatial_streams += 1

            capability_dict["802.11n"] = f"Supported ({spatial_streams}ss)"
        else:
            capability_dict["802.11n"] = "Not reported*"

        # check if 11ac supported
        if VHT_CAPABILITIES_TAG in dot11_elt_dict.keys():

            # Check for number streams supported
            mcs_upper_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][5]
            mcs_lower_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][4]
            mcs_rx_map = (mcs_upper_octet * 256) + mcs_lower_octet

            # define the bit pair we need to look at
            spatial_streams = 0
            stream_mask = 3

            # move through each bit pair & test for '10' (stream supported)
            for mcs_bits in range(1, 9):

                if (mcs_rx_map & stream_mask) != stream_mask:

                    # stream mask bits both '1' when mcs map range not supported
                    spatial_streams += 1

                # shift to next mcs range bit pair (stream)
                stream_mask = stream_mask * 4

            vht_support = f"Supported ({spatial_streams}ss)"

            # check for SU & MU beam formee support
            mu_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][2]
            su_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][1]

            beam_form_mask = 16

            # bit 4 indicates support for both octets (1 = supported, 0 = not supported)
            if su_octet & beam_form_mask:
                vht_support += ", SU BF supported"
            else:
                vht_support += ", SU BF not supported"

            if mu_octet & beam_form_mask:
                vht_support += ", MU BF supported"
            else:
                vht_support += ", MU BF not supported"

            capability_dict["802.11ac"] = vht_support

        else:
            capability_dict["802.11ac"] = "Not reported*"

        # check if 11k supported
        if RM_CAPABILITIES_TAG in dot11_elt_dict.keys():
            capability_dict["802.11k"] = "Supported"
        else:
            capability_dict[
                "802.11k"
            ] = "Not reported* - treat with caution, many clients lie about this"

        if not self.args.ft_enabled:
            capability_dict["802.11r"] = "Reporting disabled (--no11r option used)"
        elif FT_CAPABILITIES_TAG in dot11_elt_dict.keys():
            capability_dict["802.11r"] = "Supported"
        else:
            capability_dict["802.11r"] = "Not reported*"

        # check if 11v supported
        capability_dict["802.11v"] = "Not reported*"

        if EXT_CAPABILITIES_TAG in dot11_elt_dict.keys():

            ext_cap_list = dot11_elt_dict[EXT_CAPABILITIES_TAG]

            # check octet 3 exists
            if 3 <= len(ext_cap_list):

                # bit 4 of octet 3 in the extended capabilites field
                octet3 = ext_cap_list[2]
                bss_trans_support = int("00001000", 2)

                # 'And' octet 3 to test for bss transition support
                if octet3 & bss_trans_support:
                    capability_dict["802.11v"] = "Supported"

        # check if 11w supported
        capability_dict["802.11w"] = "Not reported"
        if RSN_CAPABILITIES_TAG in dot11_elt_dict.keys():

            rsn_cap_list = dot11_elt_dict[RSN_CAPABILITIES_TAG]
            rsn_len = len(rsn_cap_list) - 2
            pmf_oct = rsn_cap_list[rsn_len]

            # bit 8 of 2nd last octet in the rsn capabilites field
            if 127 <= pmf_oct:
                capability_dict["802.11w"] = "Supported"

        # check if power capabilites supported
        capability_dict["Max_Power"] = "Not reported"
        capability_dict["Min_Power"] = "Not reported"

        if POWER_MIN_MAX_TAG in dot11_elt_dict.keys():

            # octet 3 of power capabilites
            max_power = dot11_elt_dict[POWER_MIN_MAX_TAG][1]
            min_power = dot11_elt_dict[POWER_MIN_MAX_TAG][0]

            # check if signed
            if min_power > 127:
                signed_min_power = (256 - min_power) * (-1)
            else:
                signed_min_power = min_power

            capability_dict["Max_Power"] = f"{max_power} dBm"
            capability_dict["Min_Power"] = f"{signed_min_power} dBm"

        # check supported channels
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

            capability_dict["Supported_Channels"] = ", ".join(map(str, channel_list))

        else:
            capability_dict["Supported_Channels"] = "Not reported"

        # check for Ext tags (e.g. 802.11ax draft support)

        if not self.args.he_enabled:
            capability_dict[
                "802.11ax_draft"
            ] = "Reporting disabled (--no11ax option used)"
        else:
            capability_dict["802.11ax_draft"] = "Not Supported"

            if EXT_IE_TAG in dot11_elt_dict.keys():

                ext_ie_id = str(dot11_elt_dict[EXT_IE_TAG][0])

                dot11ax_draft_ids = {"35": "802.11ax (Draft)"}

                # check for 802.11ax support
                if ext_ie_id in dot11ax_draft_ids.keys():
                    capability_dict["802.11ax_draft"] = "Supported (Draft)"
            # TODO: Need to add more 11ax detection features and add them in to the
            #        report. For example: support for OFDMA UL, OFDMA DL, MU-MIMO UL
            #        MU-MIMO DL, BSS Colouring etc.

        report_text = ""

        # start report
        report_text += "\n"
        report_text += "-" * 60
        report_text += f"\nClient capabilities report - Client MAC: {frame.addr2}\n"
        report_text += f"(OUI manufacturer lookup: {oui_manuf or 'Unknown'})\n"
        report_text += "-" * 60
        report_text += "\n"

        # print out capabilities (in nice format)
        capabilities = [
            "802.11k",
            "802.11r",
            "802.11v",
            "802.11w",
            "802.11n",
            "802.11ac",
            "802.11ax_draft",
            "Max_Power",
            "Min_Power",
            "Supported_Channels",
        ]
        for key in capabilities:
            report_text += "{:<20} {:<20}".format(key, capability_dict[key]) + "\n"

        report_text += (
            "\n\n"
            + "* Reported client capabilities are dependent on these features being available from the wireless network at time of client association\n\n"
        )

        return report_text, capabilities, capability_dict
