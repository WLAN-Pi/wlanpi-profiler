# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.profiler
~~~~~~~~~~~~~~~~~

profiler code goes here, separate from fake ap code.
"""

import csv
import inspect
import json
import logging
import os
import signal
import sys
import time
import traceback
import warnings
from queue import Empty
from typing import Any, Optional

# Suppress cryptography deprecation warnings before importing scapy
# (TripleDES moving to cryptography.hazmat.decrepit)
try:
    from cryptography.utils import CryptographyDeprecationWarning

    warnings.filterwarnings(
        "ignore",
        message="TripleDES has been moved",
        category=CryptographyDeprecationWarning,
    )
except ImportError:
    pass  # cryptography not installed

try:
    from manuf2 import manuf  # type: ignore
except ModuleNotFoundError:
    manuf = None  # OUI lookups will be disabled

from scapy.all import Dot11, RadioTap, wrpcap  # type: ignore

from .__version__ import __version__
from .constants import (
    _20MHZ_FREQUENCY_CHANNEL_MAP,
    EHT_CAPABILITIES_IE_EXT_TAG,
    EXT_CAPABILITIES_IE_TAG,
    FT_CAPABILITIES_IE_TAG,
    HE_6_GHZ_BAND_CAP_IE_EXT_TAG,
    HE_CAPABILITIES_IE_EXT_TAG,
    HE_SPATIAL_REUSE_IE_EXT_TAG,
    HT_CAPABILITIES_IE_TAG,
    IE_EXT_TAG,
    MLE_EXT_TAG,
    POWER_MIN_MAX_IE_TAG,
    RM_CAPABILITIES_IE_TAG,
    RSN_CAPABILITIES_IE_TAG,
    RSNX_TAG,
    SSID_PARAMETER_SET_IE_TAG,
    SUPPORTED_CHANNELS_IE_TAG,
    SUPPORTED_OPERATING_CLASSES_IE_TAG,
    VENDOR_SPECIFIC_IE_TAG,
    VHT_CAPABILITIES_IE_TAG,
)
from .helpers import (
    Base64Encoder,
    Capability,
    flag_last_object,
    get_bit,
    is_randomized,
    is_valid_mac,
    is_valid_ssid,
    set_directory_permissions,
    set_file_permissions,
    update_last_profile_record,
)


class Profiler:
    """Code handling analysis of client capablities"""

    def _setup_subprocess_logging(self, config: Optional[dict[str, Any]]) -> None:
        """Configure logging for profiler subprocess.

        When running as a multiprocessing.Process, the logging configuration from
        the parent process is not inherited. This method sets up logging so that
        INFO and above messages are printed to stdout.
        """
        debug = False
        if config:
            debug = config.get("GENERAL", {}).get("debug", False)

        logging_level = logging.DEBUG if debug else logging.INFO

        # Use same format as helpers.setup_logger for consistency
        logging.basicConfig(
            level=logging_level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            stream=sys.stdout,
            force=True,  # Override any existing configuration
        )

    def __init__(
        self, config: Optional[dict[str, Any]] = None, queue: Optional[Any] = None
    ) -> None:
        try:
            # Re-initialize logging for this subprocess since it doesn't inherit
            # the parent's logging configuration
            self._setup_subprocess_logging(config)

            self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
            self.parent_pid = os.getppid()
            self.log.debug(
                "profiler pid: %s; parent pid: %s", os.getpid(), self.parent_pid
            )
            self.analyzed_hash: dict[int, Any] = {}
            self.config = config
            if config:
                self.log.debug("profiler __init__: processing config")
                channel = config.get("GENERAL").get("channel")
                if channel:
                    self.channel = int(channel)
                else:
                    self.log.warning("profiler cannot determine channel from config")
                self.listen_only = config.get("GENERAL").get("listen_only")
                self.files_path = config.get("GENERAL").get("files_path")
                # Support both single path and list of paths
                if not isinstance(self.files_path, list):
                    self.files_path = [self.files_path]
                self.pcap_analysis = config.get("GENERAL").get("pcap_analysis")
                self.ft_disabled = config.get("GENERAL").get("ft_disabled")
                self.he_disabled = config.get("GENERAL").get("he_disabled")
                self.be_disabled = config.get("GENERAL").get("be_disabled")
                self.log.debug(
                    "profiler __init__: ft_disabled=%s, he_disabled=%s, be_disabled=%s",
                    self.ft_disabled,
                    self.he_disabled,
                    self.be_disabled,
                )
                # Use first path for backwards compatibility with single-path vars
                self.reports_dir = os.path.join(str(self.files_path[0]), "reports")
                self.clients_dir = os.path.join(str(self.files_path[0]), "clients")
                self.csv_file = os.path.join(
                    self.reports_dir, f"profiler-{time.strftime('%Y-%m-%d')}.csv"
                )
            self.client_profiled_count = 0
            try:
                self.lookup = manuf.MacParser(update=False) if manuf else None
            except Exception as manuf_error:
                self.log.warning(
                    "Failed to initialize manuf.MacParser: %s. OUI lookups will be disabled.",
                    manuf_error,
                )
                self.lookup = None
            self.last_manuf = "N/A"
            self.running = True
            self.run(queue)
        except Exception as e:
            # Log to both logger and stderr since subprocess errors may not propagate
            error_msg = f"FATAL ERROR in profiler __init__: {type(e).__name__}: {e}"
            self.log.error(error_msg, exc_info=True)

            sys.stderr.write(f"\n{error_msg}\n")
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
            raise

    def run(self, queue) -> None:
        """Runner which performs checks prior to profiling an association request"""

        try:
            self.log.debug("profiler run(): starting")

            # Set up signal handlers for graceful shutdown
            def shutdown_handler(signum, _frame):
                self.log.info(f"Received signal {signum}, shutting down gracefully")
                self.running = False

            signal.signal(signal.SIGTERM, shutdown_handler)
            signal.signal(signal.SIGINT, shutdown_handler)

            self.log.debug("profiler run(): signal handlers registered")

            if queue:
                buffer: dict = {}
                buffer_squelch = 3

                while self.running:
                    # Always use timeout so we can check self.running flag periodically
                    try:
                        frame = queue.get(timeout=1)
                    except Empty:
                        if self.pcap_analysis:
                            # Queue is empty and we're in pcap mode - analysis complete
                            self.log.info(
                                "finished analyzing %s",
                                self.pcap_analysis,
                            )
                            sys.exit(0)
                        # Live mode - timeout expired, check running flag and continue
                        continue

                    # Process the frame (only reached if we got one from queue)
                    if frame and isinstance(frame, (RadioTap, Dot11)):
                        # Defense-in-depth: filter invalid MACs (should already be filtered upstream)
                        if not is_valid_mac(frame.addr2):
                            continue

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

            self.log.info("Profiler subprocess shutting down cleanly")
        except Exception as error:
            # log to both logger and stderr since subprocess errors may not propagate
            msg = f"FATAL ERROR in profiler run(): {type(error).__name__}: {error}"
            self.log.error(msg, exc_info=True)

            sys.stderr.write(f"\n{msg}\n")
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
            raise

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
        if freq:
            if freq > 2411 and freq < 2485:
                band = "2.4GHz"
            elif freq > 5100 and freq < 5900:
                band = "5GHz"
            elif freq > 5900 and freq < 7120:
                band = "6GHz"
                is_6ghz = True
            else:
                band = "unknown"
        else:
            band = "unknown"

        ssid, oui_manuf, chipset, capabilities = self.analyze_assoc_req(frame, is_6ghz)

        # Filter corrupted frames with invalid SSIDs
        if not is_valid_ssid(ssid):
            self.log.debug(
                "Skipping frame from %s with invalid/corrupted SSID", frame.addr2
            )
            return

        analysis_hash = hash(f"{frame.addr2}: {capabilities}")
        if analysis_hash in self.analyzed_hash:
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
                    text_report_oui_manuf = f"{oui_manuf} (Randomized MAC)"

            self.last_manuf = oui_manuf
            self.analyzed_hash[analysis_hash] = frame

            if self.listen_only:
                self.log.info(
                    "discovered association request for %s to %s",
                    frame.addr2,
                    ssid,
                )

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

        # Output all capabilities in expanded format (40-char field width)
        for capability in capabilities:
            if capability.name and capability.value:
                # Use consistent 40-character field width for all capabilities
                out = f"{capability.name:<40} {capability.value}"
                if out.strip():
                    text_report += out + "\n"

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
        """Write report files out to directories on the WLAN Pi (supports multi-path)"""
        log = logging.getLogger(inspect.stack()[0][3])
        client_mac = frame.addr2.replace(":", "-", 5)

        # Loop through all configured paths
        for _path_idx, files_path in enumerate(self.files_path):
            files_path_str = str(files_path)
            clients_dir = os.path.join(files_path_str, "clients")
            reports_dir = os.path.join(files_path_str, "reports")
            csv_file = os.path.join(
                reports_dir, f"profiler-{time.strftime('%Y-%m-%d')}.csv"
            )
            dest = os.path.join(clients_dir, client_mac)

            if not os.path.isdir(dest):
                try:
                    os.makedirs(dest, exist_ok=True)
                    # Set permissions and group ownership for webui access
                    set_directory_permissions(dest)
                except OSError:
                    log.exception("problem creating %s directory", dest)
                    continue  # Skip this path and try the next

            data = {}

            data["mac"] = client_mac
            data["is_laa"] = randomized
            data["manuf"] = oui_manuf
            data["chipset"] = chipset

            # Schema v2: Add capture SSID
            if hasattr(frame, "info") and frame.info:
                try:
                    data["capture_ssid"] = frame.info.decode("utf-8", errors="ignore")
                except (AttributeError, UnicodeDecodeError):
                    data["capture_ssid"] = (
                        self.config.get("GENERAL", {}).get("ssid", "")
                        if self.config
                        else ""
                    )
            elif listen_only:
                data["capture_ssid"] = ""  # Unknown in listen-only mode
            else:
                data["capture_ssid"] = (
                    self.config.get("GENERAL", {}).get("ssid", "")
                    if self.config
                    else ""
                )

            # Schema v2: Add capture BSSID (AP MAC address)
            if hasattr(frame, "addr1"):
                data["capture_bssid"] = frame.addr1
            else:
                data["capture_bssid"] = ""

            # Schema v2: Add capture manufacturer (lookup AP's OUI)
            if data.get("capture_bssid"):
                try:
                    data["capture_manuf"] = (
                        self.lookup.get_manuf(data["capture_bssid"])
                        if self.lookup
                        else "Unknown"
                    ) or "Unknown"
                except Exception:
                    data["capture_manuf"] = "Unknown"
            else:
                data["capture_manuf"] = "Unknown"

            # Schema v2: Keep band as string
            data["capture_band"] = str(band[0]) if band != "unknown" else "0"
            data["capture_channel"] = channel

            features = {}
            for capability in capabilities:
                if capability.db_key:
                    features[capability.db_key] = capability.db_value
            data["features"] = features
            data["pcapng"] = json.dumps(bytes(frame), cls=Base64Encoder)
            data["schema_version"] = 2
            data["profiler_version"] = __version__

            # Capture source metadata - indicates if this was from controlled AP or external pcap
            # "profiler" = live capture with controlled AP settings (channel, SSID, IEs)
            # "external" = external pcap with unknown AP settings
            if self.pcap_analysis:
                data["capture_source"] = "external"
            else:
                data["capture_source"] = "profiler"

            # if there is a malformed radiotap header
            band_suffix = ""
            if band == "unknown":
                band_suffix = ""
            else:
                band_suffix = f"_{band}"

            text_filename = os.path.join(dest, f"{client_mac}{band_suffix}.txt")

            json_filename = os.path.join(dest, f"{client_mac}{band_suffix}.json")

            try:
                log.debug("writing json report to %s", json_filename)
                with open(json_filename, "w") as write_json_file:
                    json.dump(data, write_json_file)
                # Set permissions and group ownership for webui access
                set_file_permissions(json_filename)

                log.debug("writing text report to %s", text_filename)
                with open(text_filename, "w") as file_writer:
                    file_writer.write(text_report)
                # Set permissions and group ownership for webui access
                set_file_permissions(text_filename)

            except OSError:
                log.exception(
                    "error creating flat files to dump client info (%s)", text_filename
                )
                continue  # Skip this path and try the next

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
            # Set permissions and group ownership for webui access
            set_file_permissions(pcap_filename)

            # check if csv file exists (use path-specific csv_file)
            if not os.path.exists(csv_file):
                # create file with csv headers
                with open(csv_file, mode="w") as file_obj:
                    csv_writer = csv.DictWriter(file_obj, fieldnames=out_fieldnames)
                    csv_writer.writeheader()
                # Set permissions and group ownership for webui access
                set_file_permissions(csv_file)

            # append data to csv file
            with open(csv_file, mode="a") as file_obj:
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
        information_elements: dict = {}

        # Handle empty buffer (malformed frame with no IEs)
        if not buffer:
            return information_elements

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

    def resolve_oui_manuf(self, mac: str, dot11_elt_dict):
        """Resolve client's manuf using manuf database and other heuristics"""
        log = logging.getLogger(inspect.stack()[0][3])

        # log.debug("starting oui lookup for %s", mac)
        oui_manuf = self.lookup.get_manuf(mac) if self.lookup else ""

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
            or oui_manuf.lower() in sanitize
        ) and VENDOR_SPECIFIC_IE_TAG in dot11_elt_dict:
            # inspect vendor specific IEs and see if there's an IE with
            # an OUI that we know can only be included if the manuf
            # of the client is the vendor that maps to that OUI
            for element_data in dot11_elt_dict[VENDOR_SPECIFIC_IE_TAG]:
                try:
                    vendor_mac = f"{element_data[0]:02X}:{element_data[1]:02X}:{element_data[2]:02X}:00:00:00"
                    oui_manuf_vendor = (
                        self.lookup.get_manuf(vendor_mac) if self.lookup else None
                    )
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
                    log.debug(f"IndexError in {VENDOR_SPECIFIC_IE_TAG}")

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
        chipset = ""
        manufs = []

        if VENDOR_SPECIFIC_IE_TAG in dot11_elt_dict:
            for element_data in dot11_elt_dict[VENDOR_SPECIFIC_IE_TAG]:
                try:
                    oui = f"{element_data[0]:02X}:{element_data[1]:02X}:{element_data[2]:02X}:00:00:00"
                    manufs.append(self.lookup.get_manuf(oui) if self.lookup else None)
                except IndexError:
                    log.debug(f"IndexError for {VENDOR_SPECIFIC_IE_TAG}")

        matches = ["broadcom", "qualcomm", "mediatek", "intel", "infineon"]
        _break = False
        for manufacturer in manufs:
            if manufacturer is None:  # Skip None values
                continue
            for match in matches:
                if manufacturer.lower().startswith(match):
                    chipset = match.title()
                    _break = True
                    break
            if _break:
                break

        return chipset

    @staticmethod
    def analyze_ssid_ie(dot11_elt_dict) -> str:
        """Parse SSID Information Element from 802.11 association request.

        Extracts the network name (SSID) from the SSID parameter set IE.
        Handles both UTF-8 and Latin-1 encoded SSIDs for international character support.

        Args:
            dot11_elt_dict: Dictionary containing parsed 802.11 information elements
                           from association request frame

        Returns:
            str: Network SSID name, or empty string if SSID IE not present

        Note:
            References IEEE 802.11-2020 Section 9.4.2.2 (SSID element)
        """
        out = ""
        if SSID_PARAMETER_SET_IE_TAG in dot11_elt_dict:
            try:
                ssid = bytes(dot11_elt_dict[SSID_PARAMETER_SET_IE_TAG]).decode("utf-8")
            except UnicodeDecodeError:
                ssid = bytes(dot11_elt_dict[SSID_PARAMETER_SET_IE_TAG]).decode(
                    "latin-1"
                )
            out = f"{ssid}"
        return out

    @staticmethod
    def analyze_ht_capabilities_ie(dot11_elt_dict) -> list:
        """Parse HT Capabilities Information Element from 802.11n association request.

        Extracts 802.11n (High Throughput) capabilities including spatial stream support
        by analyzing the MCS (Modulation and Coding Scheme) set octets. The number of
        spatial streams is determined by checking which MCS octets have non-zero values.

        Args:
            dot11_elt_dict: Dictionary containing parsed 802.11 information elements
                           from association request frame

        Returns:
            List[Capability]: List containing two Capability objects:
                - dot11n: Whether 802.11n is supported (Supported/Not reported*)
                - dot11n_nss: Number of spatial streams (1-4)

        Note:
            References IEEE 802.11-2020 Section 9.4.2.56 (HT Capabilities element).
            MCS octets 1-4 (indices 3-6 in IE data) indicate spatial stream support.
        """
        dot11n = Capability(
            name="802.11n", value="Not reported*", db_key="dot11n", db_value=0
        )
        dot11n_nss = Capability(
            name="802.11n/HT NSS", value="", db_key="dot11n_nss", db_value=0
        )

        if HT_CAPABILITIES_IE_TAG in dot11_elt_dict:
            ht_data = dot11_elt_dict[HT_CAPABILITIES_IE_TAG]
            # HT Capabilities IE should be 26 bytes; we need at least 7 bytes
            # to access MCS octets at indices 3-6
            if len(ht_data) >= 7:
                spatial_streams = 0

                # mcs octets 1 - 4 indicate # streams supported (up to 4 streams only)
                for mcs_octet in range(3, 7):
                    mcs_octet_value = ht_data[mcs_octet]

                    if mcs_octet_value & 255:
                        spatial_streams += 1

                dot11n.value = "Supported"
                dot11n.db_value = 1
                dot11n_nss.value = str(spatial_streams)
                dot11n_nss.db_value = spatial_streams
            else:
                # Malformed HT Capabilities IE - mark as supported but unknown NSS
                dot11n.value = "Supported"
                dot11n.db_value = 1

        return [dot11n, dot11n_nss]

    @staticmethod
    def analyze_vht_capabilities_ie(dot11_elt_dict) -> list:
        """Parse VHT Capabilities Information Element from 802.11ac association request.

        Extracts 802.11ac (Very High Throughput) capabilities including spatial streams,
        MCS support, beamforming capabilities (SU/MU), and channel width support.

        Args:
            dot11_elt_dict: Dictionary containing parsed 802.11 information elements
                           from association request frame

        Returns:
            List[Capability]: List containing Capability objects for:
                - dot11ac: Whether 802.11ac is supported
                - dot11ac_nss: Number of spatial streams
                - dot11ac_mcs: Maximum MCS index supported
                - dot11ac_su_bf: Single-user beamformee support
                - dot11ac_mu_bf: Multi-user beamformee support
                - dot11ac_160mhz: 160 MHz channel width support

        Note:
            References IEEE 802.11-2020 Section 9.4.2.158 (VHT Capabilities element)
        """
        dot11ac = Capability(
            name="802.11ac", value="Not reported*", db_key="dot11ac", db_value=0
        )
        dot11ac_nss = Capability(
            name="802.11ac/VHT NSS", value="", db_key="dot11ac_nss", db_value=0
        )
        dot11ac_mcs = Capability(
            name="802.11ac/VHT MCS", value="", db_key="dot11ac_mcs", db_value=""
        )
        dot11ac_su_bf = Capability(
            name="802.11ac/SU Beamformee",
            value="Not reported*",
            db_key="dot11ac_su_bf",
            db_value=-1,
        )
        dot11ac_mu_bf = Capability(
            name="802.11ac/MU Beamformee",
            value="Not reported*",
            db_key="dot11ac_mu_bf",
            db_value=-1,
        )
        dot11ac_bf_sts = Capability(db_key="dot11ac_bf_sts", db_value=0)
        dot11ac_160_mhz = Capability(
            name="802.11ac/160 MHz",
            value="Not reported*",
            db_key="dot11ac_160_mhz",
            db_value=-1,
        )

        if VHT_CAPABILITIES_IE_TAG in dot11_elt_dict:
            vht_caps = dot11_elt_dict[VHT_CAPABILITIES_IE_TAG]
            if len(vht_caps) < 12:  # VHT Capabilities IE must be 12 bytes
                # Malformed IE - return default values
                return [
                    dot11ac,
                    dot11ac_nss,
                    dot11ac_mcs,
                    dot11ac_su_bf,
                    dot11ac_mu_bf,
                    dot11ac_160_mhz,
                    dot11ac_bf_sts,
                ]

            # determine number of spatial streams (NSS) supported
            mcs_upper_octet = vht_caps[5]
            mcs_lower_octet = vht_caps[4]
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
            mcs_list = ", ".join(mcs) if len(mcs) > 1 else (mcs[0] if mcs else "")
            dot11ac.value = "Supported"
            dot11ac_nss.value = str(nss)
            dot11ac_nss.db_value = nss
            dot11ac_mcs.value = mcs_list
            dot11ac_mcs.db_value = mcs_list

            # check for SU & MU beam formee support
            mu_octet = vht_caps[2]
            su_octet = vht_caps[1]
            bf_sts_octet = vht_caps[1]
            onesixty = vht_caps[0]

            # 160 MHz
            if get_bit(onesixty, 2):
                dot11ac_160_mhz.value = "Supported"
                dot11ac_160_mhz.db_value = 1
            else:
                dot11ac_160_mhz.value = "Not supported"
                dot11ac_160_mhz.db_value = 0

            # bit 4 indicates support for both octets (1 = supported, 0 = not supported)
            beam_form_mask = 16

            # SU BF
            if su_octet & beam_form_mask:
                dot11ac_su_bf.value = "Supported"
                dot11ac_su_bf.db_value = 1
            else:
                dot11ac_su_bf.value = "Not supported"
                dot11ac_su_bf.db_value = 0

            # MU BF
            if mu_octet & beam_form_mask:
                dot11ac_mu_bf.value = "Supported"
                dot11ac_mu_bf.db_value = 1
            else:
                dot11ac_mu_bf.value = "Not supported"
                dot11ac_mu_bf.db_value = 0

            # BF STS - bits 5,6,7 of VHT caps byte 1 (bit 7 is MSB)
            vht_bf_sts_binary_string = (
                f"{int(get_bit(bf_sts_octet, 7))}"  # MSB
                f"{int(get_bit(bf_sts_octet, 6))}"
                f"{int(get_bit(bf_sts_octet, 5))}"  # LSB
            )
            vht_bf_sts_value = int(vht_bf_sts_binary_string, base=2)
            dot11ac_bf_sts.db_value = vht_bf_sts_value

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
    def analyze_rm_capabilities_ie(dot11_elt_dict) -> list:
        """Parse RM (Radio Measurement) Capabilities IE for 802.11k support.

        Detects 802.11k radio resource measurement capabilities which enable clients
        to perform neighbor reports, beacons reports, and other RF measurements.

        Args:
            dot11_elt_dict: Dictionary containing parsed 802.11 information elements
                           from association request frame

        Returns:
            List[Capability]: Single-element list with dot11k support status

        Note:
            References IEEE 802.11-2020 Section 9.4.2.38 (RRM Capabilities element).
            Many clients report 802.11k support but don't fully implement it.
        """
        dot11k = Capability(
            name="802.11k",
            value="Not reported* - treat with caution, many clients lie about this",
            db_key="dot11k",
            db_value=-1,
        )
        if RM_CAPABILITIES_IE_TAG in dot11_elt_dict:
            dot11k.value = "Supported"
            dot11k.db_value = 1

        return [dot11k]

    @staticmethod
    def analyze_ft_capabilities_ie(dot11_elt_dict, ft_disabled: bool) -> list:
        """Parse FT (Fast Transition) Capabilities IE for 802.11r support.

        Detects 802.11r fast BSS transition support via mobility domain element.
        Can be disabled via ft_disabled flag for testing compatibility with legacy clients.

        Args:
            dot11_elt_dict: Dictionary containing parsed 802.11 information elements
            ft_disabled: If True, suppresses FT advertising even if client supports it

        Returns:
            List[Capability]: Single-element list with dot11r support status

        Note:
            References IEEE 802.11-2020 Section 9.4.2.47 (Mobility Domain element)
        """
        dot11r = Capability(
            name="802.11r", value="Not reported*", db_key="dot11r", db_value=-1
        )
        if ft_disabled:
            dot11r.value = "Reporting disabled (--no11r option used)"
        elif FT_CAPABILITIES_IE_TAG in dot11_elt_dict:
            dot11r.value = "Supported"
            dot11r.db_value = 1
        else:
            pass

        return [dot11r]

    @staticmethod
    def analyze_extended_capabilities_ie(dot11_elt_dict) -> list:
        """Parse Extended Capabilities IE for 802.11v/aa/QoS feature support.

        Extracts extended capability flags from the bitmap including:
        - 802.11v BSS Transition Management (bit 19)
        - 802.11aa SCS - Stream Classification Service (bit 54)
        - QoS R1 MSCS - Mirrored Stream Classification Service (bit 85)

        Args:
            dot11_elt_dict: Dictionary containing parsed 802.11 information elements
                           from association request frame

        Returns:
            List[Capability]: List containing:
                - dot11v: BSS Transition support
                - scs_support: SCS capability
                - mscs_support: MSCS capability

        Note:
            References IEEE 802.11-2020 Section 9.4.2.26 (Extended Capabilities element).
            Bit positions are specified in Table 9-153.
        """
        dot11v = Capability(
            name="802.11v", value="Not reported*", db_key="dot11v", db_value=-1
        )

        scs_support = Capability(
            name="802.11aa/SCS",
            value="Not reported*",
            db_key="dot11aa_scs_support",
            db_value=-1,
        )

        mscs_support = Capability(
            name="QoS R1/MSCS",
            value="Not reported*",
            db_key="qos_r1_mscs_support",
            db_value=-1,
        )

        if EXT_CAPABILITIES_IE_TAG in dot11_elt_dict:
            ext_cap_list = dot11_elt_dict[EXT_CAPABILITIES_IE_TAG]

            # check octet 3 exists (802.11v BSS Transition)
            if len(ext_cap_list) >= 3:
                # bit 4 of octet 3 in the extended capabilites field
                octet3 = ext_cap_list[2]
                bss_trans_support = int("00001000", 2)

                # 'And' octet 3 to test for bss transition support
                if octet3 & bss_trans_support:
                    dot11v.value = "Supported"
                    dot11v.db_value = 1
                else:
                    dot11v.value = "Not supported"
                    dot11v.db_value = 0

            # check octet 7 exists (802.11aa SCS - Stream Classification Service)
            # Bit 54 overall = Octet 7, Bit 6
            if len(ext_cap_list) >= 7:
                octet7 = ext_cap_list[6]
                scs_bit = int("01000000", 2)  # bit 6

                if octet7 & scs_bit:
                    scs_support.value = "Supported"
                    scs_support.db_value = 1
                else:
                    scs_support.value = "Not supported"
                    scs_support.db_value = 0

            # check octet 10 exists (QoS R1 MSCS - Mirrored SCS)
            # Bit 85 overall = Byte 10 (0-indexed), Bit 5
            if len(ext_cap_list) >= 11:  # Need at least 11 bytes to access index 10
                octet10 = ext_cap_list[10]  # Bit 85 is in byte 10 (0-indexed)
                mscs_bit = int("00100000", 2)  # bit 5

                if octet10 & mscs_bit:
                    mscs_support.value = "Supported"
                    mscs_support.db_value = 1
                else:
                    mscs_support.value = "Not supported"
                    mscs_support.db_value = 0

        return [dot11v, scs_support, mscs_support]

    @staticmethod
    def analyze_rsn_capabilities_ie(dot11_elt_dict) -> list:
        """Parse RSN (Robust Security Network) Capabilities IE from association request.

        Extracts security capabilities including 802.11w/MFP (Management Frame Protection),
        cipher suites (group and pairwise), and AKM (Authentication and Key Management) suites.
        Parses the RSN element structure to determine encryption and authentication methods.

        Args:
            dot11_elt_dict: Dictionary containing parsed 802.11 information elements
                           from association request frame

        Returns:
            List[Capability]: List containing four Capability objects:
                - dot11w: MFP support level (Not reported/Optional/Required)
                - group_cipher: Group cipher suite (CCMP, TKIP, GCMP-256, etc.)
                - pairwise_cipher: Pairwise cipher suites
                - akm_suite: Authentication methods (PSK, SAE, FT, etc.)

        Note:
            References IEEE 802.11-2020 Section 9.4.2.25 (RSN element).
            Handles malformed RSN IEs gracefully with debug logging.
        """
        dot11w = Capability(
            name="802.11w/MFP", value="Not reported", db_key="dot11w", db_value=0
        )

        group_cipher = Capability(
            name="Group Cipher",
            value="Not reported",
            db_key="group_cipher",
            db_value=0,
        )

        pairwise_cipher = Capability(
            name="Pairwise Cipher",
            value="Not reported",
            db_key="pairwise_cipher",
            db_value=0,
        )

        akm_suite = Capability(
            name="AKM", value="Not reported", db_key="akm", db_value=0
        )

        log = logging.getLogger("profiler")

        if RSN_CAPABILITIES_IE_TAG in dot11_elt_dict:
            rsn_cap_list = dot11_elt_dict[RSN_CAPABILITIES_IE_TAG]

            # Parse cipher suites from RSN IE
            # RSN IE structure: Version(2) + Group Cipher(4) + Pairwise Count(2) + Pairwise List(4*n) + AKM Count(2) + AKM List(4*n)
            # Standard OUI: 00-0F-AC
            if len(rsn_cap_list) >= 8:  # Minimum: version + group cipher + count
                try:
                    # Complete cipher suite type mapping (00-0F-AC suite)
                    cipher_types = {
                        0: "Use group",
                        1: "WEP-40",
                        2: "TKIP",
                        3: "Reserved",
                        4: "CCMP-128",
                        5: "WEP-104",
                        6: "BIP-CMAC-128",
                        7: "Group not allowed",
                        8: "GCMP-128",
                        9: "GCMP-256",
                        10: "CCMP-256",
                        11: "BIP-GMAC-128",
                        12: "BIP-GMAC-256",
                        13: "BIP-CMAC-256",
                        14: "Reserved",
                        15: "Reserved",
                    }

                    # Parse group cipher suite (bytes 2-5: OUI + Type)
                    if (
                        len(rsn_cap_list) >= 6
                        and rsn_cap_list[2] == 0x00
                        and rsn_cap_list[3] == 0x0F
                        and rsn_cap_list[4] == 0xAC
                    ):
                        group_suite_type = rsn_cap_list[5]
                        cipher_name = cipher_types.get(group_suite_type, "Unknown")
                        group_cipher.value = f"{cipher_name} ({group_suite_type})"
                        group_cipher.db_value = group_suite_type

                    # Parse pairwise cipher suites (all of them)
                    if len(rsn_cap_list) >= 10:
                        pairwise_count = rsn_cap_list[6] | (rsn_cap_list[7] << 8)
                        offset = 8
                        pairwise_ciphers = []
                        pairwise_suite_types = []

                        for _i in range(pairwise_count):
                            if offset + 4 <= len(rsn_cap_list):
                                # Check for 00-0F-AC OUI
                                if (
                                    rsn_cap_list[offset] == 0x00
                                    and rsn_cap_list[offset + 1] == 0x0F
                                    and rsn_cap_list[offset + 2] == 0xAC
                                ):
                                    suite_type = rsn_cap_list[offset + 3]
                                    cipher_name = cipher_types.get(
                                        suite_type, "Unknown"
                                    )
                                    pairwise_ciphers.append(
                                        f"{cipher_name} ({suite_type})"
                                    )
                                    pairwise_suite_types.append(suite_type)

                                offset += 4
                            else:
                                break

                        # Set pairwise cipher value (all ciphers with suite types, comma-separated)
                        if pairwise_ciphers:
                            pairwise_cipher.value = ", ".join(pairwise_ciphers)
                            # db_value stores the first (preferred) cipher suite type as integer
                            pairwise_cipher.db_value = pairwise_suite_types[0]

                        # Parse AKM suites (after pairwise ciphers) - get all of them
                        if offset + 2 <= len(rsn_cap_list):
                            akm_count = rsn_cap_list[offset] | (
                                rsn_cap_list[offset + 1] << 8
                            )
                            offset += 2

                            # Complete AKM suite type mapping (00-0F-AC suite)
                            akm_types = {
                                0: "Reserved",
                                1: ".1X-SHA-1",
                                2: "PSK",
                                3: "FT-.1X-SHA-256",
                                4: "FT-PSK",
                                5: ".1X-SHA-256",
                                6: "PSK-SHA-256",
                                7: "TDLS-SHA-256",
                                8: "SAE",
                                9: "FT-SAE",
                                10: "APPeerKey",
                                11: ".1X-SuiteB-SHA-256",
                                12: ".1X-CNSA-SHA-384",
                                13: "FT-.1X-SHA-384",
                                14: "FILS-SHA-256",
                                15: "FILS-SHA-384",
                                16: "FT-FILS-SHA-256",
                                17: "FT-FILS-SHA-384",
                                18: "OWE",
                                19: "FT-PSK-SHA-384",
                                20: "PSK-SHA-384",
                                21: "PASN",
                                22: "FT-.1X-SHA-384",
                                23: ".1X-SHA-384",
                                24: "SAE-GDH",
                                25: "FT-SAE-GDH",
                            }

                            akm_suites = []
                            akm_suite_types = []

                            for _i in range(akm_count):
                                if offset + 4 <= len(rsn_cap_list):
                                    # Check for 00-0F-AC OUI
                                    if (
                                        rsn_cap_list[offset] == 0x00
                                        and rsn_cap_list[offset + 1] == 0x0F
                                        and rsn_cap_list[offset + 2] == 0xAC
                                    ):
                                        akm_type = rsn_cap_list[offset + 3]
                                        akm_name = akm_types.get(akm_type, "Unknown")
                                        akm_suites.append(f"{akm_name} ({akm_type})")
                                        akm_suite_types.append(akm_type)

                                    offset += 4
                                else:
                                    break

                            # Set AKM suite value (all AKMs with suite types, comma-separated)
                            if akm_suites:
                                akm_suite.value = ", ".join(akm_suites)
                                # db_value stores the first (preferred) AKM suite type as integer
                                akm_suite.db_value = akm_suite_types[0]

                        # Parse RSN Capabilities (for MFP/802.11w)
                        # RSN Capabilities is a 2-byte field after AKM suites
                        # offset is now pointing right after the last AKM suite
                        if offset + 2 <= len(rsn_cap_list):
                            rsn_capabilities = rsn_cap_list[offset] | (
                                rsn_cap_list[offset + 1] << 8
                            )

                            # Check bit 7 (0x80) - Management Frame Protection Capable
                            if rsn_capabilities & 0x0080:
                                dot11w.value = "Supported"
                                dot11w.db_value = 1
                            else:
                                dot11w.value = "Not supported"
                                # Keep db_value=0 (already set in definition)

                except (IndexError, ValueError) as error:
                    # Malformed RSN IE, skip cipher suite parsing
                    # Expected for some malformed frames - log for debugging
                    log.debug(
                        "Malformed RSN IE in frame, skipping cipher suite parsing: %s",
                        error,
                    )

        return [group_cipher, pairwise_cipher, akm_suite, dot11w]

    @staticmethod
    def analyze_rsnx_ie(dot11_elt_dict) -> list:
        """Check for RSNX capabilities (SAE H2E)"""
        rsnx_sae_h2e = Capability(
            name="RSNX SAE H2E",
            value="Not reported",
            db_key="rsnx_sae_h2e",
            db_value=-1,  # -1 = not reported, 0 = not supported, 1 = supported
        )

        if RSNX_TAG in dot11_elt_dict:
            rsnx_data = dot11_elt_dict[RSNX_TAG]
            if len(rsnx_data) > 0:
                rsnx_byte = rsnx_data[0]
                # Bit 5 is SAE H2E
                if (rsnx_byte >> 5) & 1:
                    rsnx_sae_h2e.value = "Supported"
                    rsnx_sae_h2e.db_value = 1
                else:
                    # RSNX element present but SAE H2E bit not set
                    rsnx_sae_h2e.value = "Not supported"
                    rsnx_sae_h2e.db_value = 0

        return [rsnx_sae_h2e]

    @staticmethod
    def analyze_power_capability_ie(dot11_elt_dict) -> list:
        """Check for supported power capabilities"""
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

        if POWER_MIN_MAX_IE_TAG in dot11_elt_dict:
            power_data = dot11_elt_dict[POWER_MIN_MAX_IE_TAG]
            # Power Capability IE should have at least 2 octets (min and max power)
            if len(power_data) >= 2:
                # octet 3 of power capabilites
                max_power = power_data[1]
                min_power = power_data[0]

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
    def analyze_supported_channels_ie(dot11_elt_dict, is_6ghz: bool) -> list:
        """Check supported channels"""
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
        if SUPPORTED_CHANNELS_IE_TAG in dot11_elt_dict:
            channel_sets_list = dot11_elt_dict[SUPPORTED_CHANNELS_IE_TAG]
            channel_list = []

            is_2ghz = False
            is_5ghz = False

            while len(channel_sets_list) >= 2:
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
                if _range:  # Guard against empty ranges
                    channel_ranges.append(f"{_range[0]}-{_range[-1]}")

            supported_channels.value = f"{', '.join(channel_ranges)}**"
            supported_channels.db_value = channel_list

        return [supported_channels, number_of_supported_channels]

    @staticmethod
    def analyze_operating_classes(dot11_elt_dict) -> list:
        """Check if 6 GHz is a supported alternative operating class"""
        six_ghz_operating_class_cap = Capability(
            db_key="six_ghz_operating_class_supported",
            db_value=0,
        )

        supported_6ghz_alternative_operating_classes = []
        six_ghz_alternative_operating_classes = [131, 132, 133, 134, 135]
        if SUPPORTED_OPERATING_CLASSES_IE_TAG in dot11_elt_dict:
            supported_operating_classes = dot11_elt_dict[
                SUPPORTED_OPERATING_CLASSES_IE_TAG
            ]
            # pop current operating class from list
            if supported_operating_classes:
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
    ) -> list:
        """Check for 802.11ax and 802.11be support"""
        dot11ax = Capability(
            name="802.11ax",
            value="Not reported*",
            db_key="dot11ax",
            db_value=0,
        )
        dot11ax_six_ghz = Capability(
            db_key="dot11ax_six_ghz",
            db_value=0,
        )
        dot11ax_punctured_preamble = Capability(
            name="802.11ax/Punctured Preamble",
            value="Not reported*",
            db_key="dot11ax_punctured_preamble",
            db_value=-1,
        )
        dot11ax_he_su_beamformee = Capability(
            name="802.11ax/SU Beamformee",
            value="Not reported*",
            db_key="dot11ax_he_su_beamformee",
            db_value=-1,
        )
        dot11ax_he_beamformee_sts = Capability(
            db_key="dot11ax_he_beamformee_sts", db_value=0
        )
        dot11ax_nss = Capability(
            name="802.11ax/HE NSS", value="", db_key="dot11ax_nss", db_value=0
        )
        dot11ax_mcs = Capability(
            name="802.11ax/HE MCS", value="", db_key="dot11ax_mcs", db_value=""
        )
        dot11ax_twt = Capability(
            name="802.11ax/TWT",
            value="Not reported*",
            db_key="dot11ax_twt",
            db_value=-1,
        )
        dot11ax_uora = Capability(
            name="802.11ax/UORA",
            value="Not reported*",
            db_key="dot11ax_uora",
            db_value=-1,
        )
        dot11ax_bsr = Capability(
            name="802.11ax/BSR",
            value="Not reported*",
            db_key="dot11ax_bsr",
            db_value=-1,
        )
        dot11ax_he_er_su_ppdu = Capability(
            name="802.11ax/HE ER SU PPDU",
            value="Not reported*",
            db_key="dot11ax_he_er_su_ppdu",
            db_value=-1,
        )
        dot11ax_spatial_reuse = Capability(db_key="dot11ax_spatial_reuse", db_value=0)
        dot11ax_160_mhz = Capability(
            name="802.11ax/160 MHz",
            value="Not reported*",
            db_key="dot11ax_160_mhz",
            db_value=-1,
        )

        log = logging.getLogger("profiler")

        if he_disabled:
            dot11ax.value = "Reporting disabled (--no11ax option used)"
        else:
            if IE_EXT_TAG in dot11_elt_dict:
                # Debug: Log all Extension IE IDs found
                ext_ie_ids = [
                    int(str(element_data[0]))
                    for element_data in dot11_elt_dict[IE_EXT_TAG]
                ]
                log.debug(
                    f"Extension IEs (tag 255) found: {ext_ie_ids} (35=HE Caps, 36=HE Op, 39=6GHz, 107=MLE, 108=EHT Caps)"
                )

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

                        mcs_sorted = sorted(set(mcs))
                        mcs_str = (
                            ", ".join(mcs_sorted)
                            if len(mcs_sorted) > 1
                            else (mcs_sorted[0] if mcs_sorted else "")
                        )
                        dot11ax.value = "Supported"
                        dot11ax_mcs.value = mcs_str
                        dot11ax_mcs.db_value = mcs_str
                        dot11ax_nss.value = str(nss)
                        dot11ax_nss.db_value = nss

                        onesixty_octet = element_data[7]
                        if get_bit(onesixty_octet, 3):
                            dot11ax_160_mhz.value = "Supported"
                            dot11ax_160_mhz.db_value = 1
                        else:
                            dot11ax_160_mhz.value = "Not supported"
                            dot11ax_160_mhz.db_value = 0

                        twt_octet = element_data[1]
                        if get_bit(twt_octet, 1):
                            dot11ax_twt.value = "Supported"
                            dot11ax_twt.db_value = 1
                        else:
                            dot11ax_twt.value = "Not supported"
                            dot11ax_twt.db_value = 0

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
                            dot11ax_punctured_preamble.value = "Supported"
                            dot11ax_punctured_preamble.db_value = 1
                        else:
                            dot11ax_punctured_preamble.value = "Not supported"
                            dot11ax_punctured_preamble.db_value = 0

                        su_beamformer_octet = element_data[10]
                        su_beamformer_octet_binary_string = ""
                        for bit_position in range(8):
                            su_beamformer_octet_binary_string += (
                                f"{int(get_bit(su_beamformer_octet, bit_position))}"
                            )

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
                            dot11ax_he_su_beamformee.value = "Supported"
                            dot11ax_he_su_beamformee.db_value = 1
                        else:
                            dot11ax_he_su_beamformee.value = "Not supported"
                            dot11ax_he_su_beamformee.db_value = 0

                        # BF STS - bits 2,3,4 of PHY byte 4 (bit 4 is MSB)
                        he_bf_sts_octet = element_data[11]

                        he_bf_sts_binary_string = (
                            f"{int(get_bit(he_bf_sts_octet, 4))}"  # MSB
                            f"{int(get_bit(he_bf_sts_octet, 3))}"
                            f"{int(get_bit(he_bf_sts_octet, 2))}"  # LSB
                        )
                        he_bf_sts_value = int(he_bf_sts_binary_string, base=2)
                        dot11ax_he_beamformee_sts.db_value = he_bf_sts_value

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
                            dot11ax_he_er_su_ppdu.value = "Supported"
                            dot11ax_he_er_su_ppdu.db_value = 1
                        else:
                            dot11ax_he_er_su_ppdu.value = "Not supported"
                            dot11ax_he_er_su_ppdu.db_value = 0

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
                            dot11ax_uora.value = "Supported"
                            dot11ax_uora.db_value = 1
                        else:
                            dot11ax_uora.value = "Not supported"
                            dot11ax_uora.db_value = 0

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
                            dot11ax_bsr.value = "Supported"
                            dot11ax_bsr.db_value = 1
                        else:
                            dot11ax_bsr.value = "Not supported"
                            dot11ax_bsr.db_value = 0
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
            value="Not reported*",
            db_key="dot11be",
            db_value=0,
        )
        dot11be_nss = Capability(
            name="802.11be/EHT NSS",
            value="",
            db_key="dot11be_nss",
            db_value=0,
        )
        dot11be_mcs = Capability(
            name="802.11be/EHT MCS",
            value="",
            db_key="dot11be_mcs",
            db_value="",
        )
        dot11be_320_mhz = Capability(
            name="802.11be/320 MHz in 6 GHz",
            value="Not reported*",
            db_key="dot11be_320_mhz",
            db_value=-1,
        )

        # EHT MAC Capabilities
        dot11be_epcs = Capability(
            name="802.11be/EPCS Support",
            value="Not reported*",
            db_key="dot11be_epcs_support",
            db_value=-1,
        )
        dot11be_om_control = Capability(
            name="802.11be/EHT OM Control",
            value="Not reported*",
            db_key="dot11be_om_support",
            db_value=-1,
        )
        dot11be_rtwt = Capability(
            name="802.11be/R-TWT Support",
            value="Not reported*",
            db_key="dot11be_rtwt_support",
            db_value=-1,
        )
        dot11be_scs_traffic = Capability(
            name="802.11be/SCS Traffic Desc",
            value="Not reported*",
            db_key="dot11be_scs_traffic_description_support",
            db_value=-1,
        )

        # EHT PHY Capabilities
        dot11be_su_beamformee = Capability(
            name="802.11be/SU Beamformee",
            value="Not reported*",
            db_key="dot11be_su_beamformee",
            db_value=-1,
        )
        dot11be_mcs15_support = Capability(
            name="802.11be/EHT-MCS 15 In MRU",
            value="Not reported*",
            db_key="dot11be_mcs15_support",
            db_value=-1,
        )
        dot11be_eht_dup_6ghz = Capability(
            name="802.11be/EHT DUP (MCS 14) 6 GHz",
            value="Not reported*",
            db_key="dot11be_mcs14_support",
            db_value=-1,
        )

        # Multi-Link Element (MLE) Capabilities
        dot11be_mle = Capability(
            name="802.11be/MLE",
            value="Not reported*",
            db_key="dot11be_mle",
            db_value=-1,
        )

        dot11be_mle_mlc_type = Capability(
            name="802.11be/MLE/MLC Type",
            value="Not reported*",
            db_key="dot11be_mle_mlc_type",
            db_value=-1,
        )

        dot11be_mle_emlsr_support = Capability(
            name="802.11be/MLE/EMLSR",
            value="Not reported*",
            db_key="dot11be_mle_emlsr_support",
            db_value=-1,
        )

        dot11be_mle_emlsr_padding_delay = Capability(
            name="802.11be/MLE/EMLSR Padding Delay",
            value="Not reported*",
            db_key="dot11be_mle_emlsr_padding_delay",
            db_value=-1,
        )

        dot11be_mle_emlsr_transition_delay = Capability(
            name="802.11be/MLE/EMLSR Transition Delay",
            value="Not reported*",
            db_key="dot11be_mle_emlsr_transition_delay",
            db_value=-1,
        )

        dot11be_mle_emlmr_support = Capability(
            name="802.11be/MLE/EMLMR",
            value="Not reported*",
            db_key="dot11be_mle_emlmr_support",
            db_value=-1,
        )

        dot11be_mle_max_simultaneous_links = Capability(
            name="802.11be/MLE/Max Sim. Links",
            value="Not reported*",
            db_key="dot11be_mle_max_simultaneous_links",
            db_value=-1,
        )

        dot11be_mle_t2lm_negotiation_support = Capability(
            name="802.11be/MLE/T2LM Negot.",
            value="Not reported*",
            db_key="dot11be_mle_t2lm_negotiation_support",
            db_value=-1,
        )

        dot11be_mle_link_reconfig_support = Capability(
            name="802.11be/MLE/Link Reconfig",
            value="Not reported*",
            db_key="dot11be_mle_link_reconfig_support",
            db_value=-1,
        )

        if be_disabled:
            dot11be.value = "Reporting disabled (--no11be option used)"
        else:
            if IE_EXT_TAG in dot11_elt_dict:
                for element_data in dot11_elt_dict[IE_EXT_TAG]:
                    ext_ie_id = int(str(element_data[0]))

                    if ext_ie_id == EHT_CAPABILITIES_IE_EXT_TAG:
                        # EHT is supported
                        dot11be.value = "Supported"
                        dot11be.db_value = 1

                        # Parse EHT MAC Capabilities (bytes 1-2, 16-bit field)
                        if len(element_data) >= 3:
                            # Combine bytes 1-2 into 16-bit value (little-endian)
                            eht_mac_caps = element_data[1] | (element_data[2] << 8)

                            # EPCS Priority Access Support (bit 0)
                            if eht_mac_caps & 0x0001:
                                dot11be_epcs.value = "Supported"
                                dot11be_epcs.db_value = 1
                            else:
                                dot11be_epcs.value = "Not supported"
                                dot11be_epcs.db_value = 0

                            # EHT OM Control Support (bit 1)
                            if eht_mac_caps & 0x0002:
                                dot11be_om_control.value = "Supported"
                                dot11be_om_control.db_value = 1
                            else:
                                dot11be_om_control.value = "Not supported"
                                dot11be_om_control.db_value = 0

                            # Restricted TWT Support (bit 4)
                            if eht_mac_caps & 0x0010:
                                dot11be_rtwt.value = "Supported"
                                dot11be_rtwt.db_value = 1
                            else:
                                dot11be_rtwt.value = "Not supported"
                                dot11be_rtwt.db_value = 0

                            # SCS Traffic Description Support (bit 5)
                            if eht_mac_caps & 0x0020:
                                dot11be_scs_traffic.value = "Supported"
                                dot11be_scs_traffic.db_value = 1
                            else:
                                dot11be_scs_traffic.value = "Not supported"
                                dot11be_scs_traffic.db_value = 0

                        # Parse EHT PHY Capabilities
                        # PHY capabilities are 9 bytes starting at element_data[3]
                        if len(element_data) >= 5:
                            # Parse PHY bits 0-15 (bytes 3-4)
                            eht_phy_bits_0_15 = element_data[3] | (element_data[4] << 8)

                            # SU Beamformee (bit 6, mask 0x0040)
                            if eht_phy_bits_0_15 & 0x0040:
                                dot11be_su_beamformee.value = "Supported"
                                dot11be_su_beamformee.db_value = 1
                            else:
                                dot11be_su_beamformee.value = "Not supported"
                                dot11be_su_beamformee.db_value = 0

                            # 320 MHz support in 6 GHz (bit 1, mask 0x0002)
                            if eht_phy_bits_0_15 & 0x0002:
                                dot11be_320_mhz.value = "Supported"
                                dot11be_320_mhz.db_value = 1
                            else:
                                dot11be_320_mhz.value = "Not supported"
                                dot11be_320_mhz.db_value = 0

                        # MCS 15 and MCS 14 (EHT DUP) support - PHY bits 40-63
                        # These are in bytes 8-10 of element_data (PHY bytes 5-7)
                        if len(element_data) >= 11:
                            # Combine bytes 8-10 into 24-bit value (little-endian)
                            eht_phy_bits_40_63 = (
                                element_data[8]
                                | (element_data[9] << 8)
                                | (element_data[10] << 16)
                            )

                            # Support of MCS 15 (mask 0x007800, 4 bits)
                            mcs15_bits = (eht_phy_bits_40_63 & 0x007800) >> 11
                            if mcs15_bits > 0:
                                dot11be_mcs15_support.value = "Supported"
                                dot11be_mcs15_support.db_value = (
                                    mcs15_bits  # Store the actual capability value
                                )
                            else:
                                dot11be_mcs15_support.value = "Not supported"
                                dot11be_mcs15_support.db_value = 0

                            # Support of EHT DUP (MCS 14) in 6 GHz (mask 0x008000, bit 15)
                            if eht_phy_bits_40_63 & 0x008000:
                                dot11be_eht_dup_6ghz.value = "Supported"
                                dot11be_eht_dup_6ghz.db_value = 1
                            else:
                                dot11be_eht_dup_6ghz.value = "Not supported"
                                dot11be_eht_dup_6ghz.db_value = 0

                        # Parse EHT MCS and NSS Set
                        # Structure: EXT_TAG (1) + MAC (2) + PHY (9) + MCS/NSS Set (variable)
                        # MCS/NSS starts at byte 12 (index 12)
                        # Format: Each MCS map is 3 bytes (Rx/Tx pairs for MCS 0-9, 10-11, 12-13)
                        if (
                            len(element_data) >= 15
                        ):  # Need at least 3 bytes for one MCS map
                            mcs_nss_offset = 12  # After MAC (2) + PHY (9) + ext_tag (1)

                            # Parse first MCS map (BW <= 80 MHz)
                            if len(element_data) >= mcs_nss_offset + 3:
                                nss = 0
                                mcs = []

                                # Each byte has two 4-bit fields: RX (bits 0-3) and TX (bits 4-7)
                                # Process all 3 bytes (MCS 0-9, 10-11, 12-13)
                                for byte_idx in range(3):
                                    byte_val = element_data[mcs_nss_offset + byte_idx]
                                    rx_nss = byte_val & 0x0F  # Lower 4 bits

                                    if rx_nss < 15:  # 15 means not supported
                                        nss = max(nss, rx_nss)

                                    # Determine MCS range based on byte index
                                    if byte_idx == 0 and rx_nss > 0:
                                        mcs.append("0-9")
                                    elif byte_idx == 1 and rx_nss > 0:
                                        mcs.append("10-11")
                                    elif byte_idx == 2 and rx_nss > 0:
                                        mcs.append("12-13")

                                if nss > 0:
                                    mcs = sorted(set(mcs))
                                    mcs_str = (
                                        ", ".join(mcs)
                                        if len(mcs) > 1
                                        else mcs[0]
                                        if mcs
                                        else ""
                                    )

                                    if mcs_str:
                                        dot11be_nss.value = str(nss)
                                        dot11be_nss.db_value = nss
                                        dot11be_mcs.value = mcs_str
                                        dot11be_mcs.db_value = mcs_str

                    # Parse Multi-Link Element (MLE)
                    if ext_ie_id == MLE_EXT_TAG:  # 107
                        # MLE is present
                        dot11be_mle.value = "Supported"
                        dot11be_mle.db_value = 1

                        if (
                            len(element_data) >= 3
                        ):  # Need at least ext_id + 2 bytes for control
                            # Parse Multi-Link Control (bytes 1-2)
                            mlc_control = element_data[1] | (element_data[2] << 8)

                            # Extract MLC Type (bits 0-2)
                            mlc_type_val = mlc_control & 0x0007
                            dot11be_mle_mlc_type.value = str(mlc_type_val)
                            dot11be_mle_mlc_type.db_value = mlc_type_val

                            # Extract presence bitmap
                            eml_capa_present = (mlc_control & 0x0080) != 0  # bit 7
                            mld_capa_present = (mlc_control & 0x0100) != 0  # bit 8

                            # Calculate offset to Common Info fields
                            # MLE structure: Ext ID (1) + MLC Control (2 bytes) + Common Info
                            # Common Info starts at byte 3 (0-indexed)
                            # First read Common Info Length field
                            if len(element_data) < 4:
                                continue  # Not enough data

                            element_data[3]
                            offset = 4  # Start after Ext ID (1) + MLC Control (2) + Length (1)

                            # Skip MLD MAC Address (6 bytes) - always present for Type 0
                            if mlc_type_val == 0:
                                offset += 6

                            # Skip optional fields based on presence bitmap
                            if mlc_control & 0x0010:  # Link ID present (bit 4)
                                offset += 1
                            if mlc_control & 0x0020:  # BSS Params present (bit 5)
                                offset += 1
                            if mlc_control & 0x0040:  # Medium Sync present (bit 6)
                                offset += 2

                            # Parse EML Capabilities
                            if eml_capa_present and offset + 2 <= len(element_data):
                                eml_caps = element_data[offset] | (
                                    element_data[offset + 1] << 8
                                )
                                offset += 2

                                # EMLSR Support (bit 0)
                                if eml_caps & 0x0001:
                                    dot11be_mle_emlsr_support.value = "Supported"
                                    dot11be_mle_emlsr_support.db_value = 1
                                else:
                                    dot11be_mle_emlsr_support.value = "Not supported"
                                    dot11be_mle_emlsr_support.db_value = 0

                                # EMLSR Padding Delay (bits 1-3)
                                padding_val = (eml_caps >> 1) & 0x0007
                                dot11be_mle_emlsr_padding_delay.value = str(padding_val)
                                dot11be_mle_emlsr_padding_delay.db_value = padding_val

                                # EMLSR Transition Delay (bits 4-6)
                                transition_val = (eml_caps >> 4) & 0x0007
                                dot11be_mle_emlsr_transition_delay.value = str(
                                    transition_val
                                )
                                dot11be_mle_emlsr_transition_delay.db_value = (
                                    transition_val
                                )

                                # EMLMR Support (bit 7)
                                if eml_caps & 0x0080:
                                    dot11be_mle_emlmr_support.value = "Supported"
                                    dot11be_mle_emlmr_support.db_value = 1
                                else:
                                    dot11be_mle_emlmr_support.value = "Not supported"
                                    dot11be_mle_emlmr_support.db_value = 0

                            # Parse MLD Capabilities
                            if mld_capa_present and offset + 2 <= len(element_data):
                                mld_caps = element_data[offset] | (
                                    element_data[offset + 1] << 8
                                )

                                # Max Simultaneous Links (bits 0-3)
                                max_links_val = mld_caps & 0x000F
                                dot11be_mle_max_simultaneous_links.value = str(
                                    max_links_val
                                )
                                dot11be_mle_max_simultaneous_links.db_value = (
                                    max_links_val
                                )

                                # T2LM Negotiation Support (bits 5-6)
                                t2lm_val = (mld_caps >> 5) & 0x0003
                                dot11be_mle_t2lm_negotiation_support.value = str(
                                    t2lm_val
                                )
                                dot11be_mle_t2lm_negotiation_support.db_value = t2lm_val

                                # Link Reconfiguration Support (bit 13)
                                if mld_caps & 0x2000:
                                    dot11be_mle_link_reconfig_support.value = (
                                        "Supported"
                                    )
                                    dot11be_mle_link_reconfig_support.db_value = 1
                                else:
                                    dot11be_mle_link_reconfig_support.value = (
                                        "Not supported"
                                    )
                                    dot11be_mle_link_reconfig_support.db_value = 0

        return [
            dot11ax,
            dot11ax_nss,
            dot11ax_mcs,
            dot11ax_twt,
            dot11ax_uora,
            dot11ax_bsr,
            dot11ax_punctured_preamble,
            dot11ax_he_su_beamformee,
            dot11ax_he_beamformee_sts,
            dot11ax_he_er_su_ppdu,
            dot11ax_six_ghz,
            dot11ax_160_mhz,
            dot11be,
            dot11be_nss,
            dot11be_mcs,
            dot11be_320_mhz,
            dot11be_su_beamformee,
            dot11be_epcs,
            dot11be_om_control,
            dot11be_rtwt,
            dot11be_scs_traffic,
            dot11be_mcs15_support,
            dot11be_eht_dup_6ghz,
            dot11be_mle,
            dot11be_mle_mlc_type,
            dot11be_mle_emlsr_support,
            dot11be_mle_emlsr_padding_delay,
            dot11be_mle_emlsr_transition_delay,
            dot11be_mle_emlmr_support,
            dot11be_mle_max_simultaneous_links,
            dot11be_mle_t2lm_negotiation_support,
            dot11be_mle_link_reconfig_support,
        ]

    def analyze_assoc_req(self, frame, is_6ghz: bool):
        """Analyze 802.11 association request frame to extract client capabilities.

        This is the main analysis function that orchestrates parsing of all information
        elements (IEs) from an association request frame to build a comprehensive profile
        of the client's Wi-Fi capabilities including PHY layer support (802.11n/ac/ax/be),
        security features, power management, channel support, and vendor-specific features.

        Args:
            frame: Scapy Dot11 packet containing the association request
            is_6ghz: Whether the client is associating on a 6 GHz channel

        Returns:
            Tuple[str, str, list]: Three-element tuple containing:
                - client_mac (str): Client MAC address (with randomization detection)
                - oui_manuf (str): OUI manufacturer lookup result
                - capabilities (list): List of Capability objects for all detected features

        Note:
            Calls all analyze_*_ie() static methods to parse individual IEs.
            Handles both 2.4/5 GHz and 6 GHz band differences.
            References IEEE 802.11-2020 Section 9.3.3.6 (Association Request frame format)
        """
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

        # check if 11v/aa/QoS supported (Extended Capabilities)
        capabilities += self.analyze_extended_capabilities_ie(dot11_elt_dict)

        # check if 11w supported
        capabilities += self.analyze_rsn_capabilities_ie(dot11_elt_dict)

        # check for RSNX (SAE H2E) support
        capabilities += self.analyze_rsnx_ie(dot11_elt_dict)

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
