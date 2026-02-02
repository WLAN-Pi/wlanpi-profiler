# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024-2026 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.fakeap
~~~~~~~~~~~~~~~

fake ap code handling beaconing and sniffing for the profiler
"""

import contextlib
import datetime
import inspect
import logging
import multiprocessing
import os
import socket
import struct
import sys
from time import sleep, time
from typing import Any

# suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import platform

    from scapy.all import (  # type: ignore  # type: ignore
        Dot11,
        Dot11Auth,
        Dot11Beacon,  # type: ignore
        Dot11Elt,  # type: ignore
        Dot11ProbeResp,  # type: ignore
        RadioTap,
        Scapy_Exception,
        get_if_hwaddr,
        hexdump,
        sniff,
    )
    from scapy.all import conf as scapyconf  # type: ignore

    if platform.system() == "Linux":
        try:
            from scapy.all import get_if_raw_hwaddr  # type: ignore
        except ImportError:
            from scapy.arch.unix import get_if_raw_hwaddr  # type: ignore
except ModuleNotFoundError as error:
    if error.name == "scapy":
        print("ERROR: scapy module is required for live capture mode.")
        print("Install with: pip install scapy")
    else:
        print(f"ERROR: {error}")
    sys.exit(-1)

from .__version__ import __version__
from .constants import (
    DOT11_SUBTYPE_ASSOC_REQ,
    DOT11_SUBTYPE_AUTH_REQ,
    DOT11_SUBTYPE_BEACON,
    DOT11_SUBTYPE_PROBE_REQ,
    DOT11_SUBTYPE_PROBE_RESP,
    DOT11_SUBTYPE_REASSOC_REQ,
    DOT11_TYPE_MANAGEMENT,
)
from .helpers import get_wlanpi_version, has_bad_fcs, is_valid_mac


class _Utils:
    """Fake AP helper functions"""

    @staticmethod
    def build_wlanpi_vendor_ie_type_0(testing: bool) -> Any:
        """
        OUI type 0 will follow a type-length-value (TLV) encoding like so <221><total-length><oui><oui_type>[[<type><length><value>] ...]

        | Byte Offset | Field Length   | Field Name | Description                   |
        | ----------- | -------------  | ---------- | ----------------------------- |
        | 0           | 1 Bytes        | Subtype    | Type identifier for attribute |

        Followed by TLVs:

            Type 0

            | Field Length | Field Name              | Description                           |
            | 1 Bytes      | Type                    |                                       |
            | 1 Bytes      | Profiler version length | Length of profiler version data field |
            | N Bytes      | Profiler version data   | Profiler version                      |

            Type 1

            | Field Length | Field Name                    | Description                                 |
            | 1 Bytes      | Type                          |                                             |
            | 1 Bytes      | WLAN Pi system version length | Length of WLAN Pi system version data field |
            | N Bytes      | WLAN Pi system version data   | WLAN Pi system version                      |
        """
        oui = b"\x31\x41\x59"
        subtype = b"\x00"

        profiler_version = __version__
        if testing:
            profiler_version = "6.6.6"
        profiler_version_type = (0).to_bytes(1, "big")
        profiler_version_data = bytes(f"{profiler_version}".encode("ascii"))
        profiler_version_length = len(profiler_version_data).to_bytes(1, "big")
        profiler_version_tlv = (
            profiler_version_type + profiler_version_length + profiler_version_data
        )

        system_version = get_wlanpi_version()
        if testing:
            system_version = "9.9.9"
        system_version_type = (1).to_bytes(1, "big")
        system_version_data = bytes(f"{system_version}".encode("ascii"))
        system_version_length = len(system_version_data).to_bytes(1, "big")
        system_version_tlv = (
            system_version_type + system_version_length + system_version_data
        )

        wlanpi_vendor_data = oui + subtype + profiler_version_tlv + system_version_tlv
        return Dot11Elt(ID=0xDD, info=wlanpi_vendor_data)

    @staticmethod
    def build_fake_frame_ies_2ghz_5ghz(
        ssid,
        mac,
        channel,
        ft_disabled,
        he_disabled,
        be_disabled,
        security_mode,
        profiler_tlv_disabled,
        testing,
    ) -> Dot11Elt:
        """Build base frame for beacon and probe resp"""
        ssid_bytes: bytes = bytes(ssid, "utf-8")
        essid = Dot11Elt(ID="SSID", info=ssid_bytes)

        rates_data = [140, 18, 152, 36, 176, 72, 96, 108]
        rates = Dot11Elt(ID="Rates", info=bytes(rates_data))

        channel = bytes([channel])  # type: ignore
        dsset = Dot11Elt(ID="DSset", info=channel)

        dtim_data = b"\x00\x04\x00\x03\x00\x00"  # Fixed: DTIM count=0, period=4 (was 5, 4 - invalid!)
        dtim = Dot11Elt(ID="TIM", info=dtim_data)

        ht_cap_data = b"\xef\x19\x1b\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        ht_capabilities = Dot11Elt(ID=0x2D, info=ht_cap_data)

        # Map security_mode to AKM suites and optionally mobility domain
        # security_mode can be: wpa2, ft-wpa2, wpa3-mixed, ft-wpa3-mixed
        mobility_domain = None  # Only created for FT modes

        if ft_disabled or security_mode in ["wpa2", "wpa3-mixed"]:
            # No FT modes
            if security_mode == "wpa3-mixed":
                # WPA2/WPA3 transition - add GCMP-256 for WPA3
                # RSN format: version(2) + group_cipher(4) + pairwise_count(2) + pairwise_ciphers(4*n) + akm_count(2) + akms(4*m) + rsn_caps(2)
                # Pairwise ciphers: CCMP (for WPA2) + GCMP-256 (for WPA3)
                pairwise_ciphers = b"\x02\x00\x00\x0f\xac\x04\x00\x0f\xac\x09"  # Count=2, CCMP, GCMP-256
                akm = b"\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x08\x80\x00"  # PSK + SAE
                rsn_data = b"\x01\x00\x00\x0f\xac\x04" + pairwise_ciphers + akm
            else:
                # WPA2 only
                akm = b"\x01\x00\x00\x0f\xac\x02\x80\x00"
                rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04" + akm
        else:
            # FT modes (ft-wpa2 or ft-wpa3-mixed)
            mobility_domain_data = b"\x45\xc2\x00"
            mobility_domain = Dot11Elt(ID=0x36, info=mobility_domain_data)
            if security_mode == "ft-wpa3-mixed":
                # FT-WPA2 + FT-WPA3 transition - add GCMP-256 for WPA3
                pairwise_ciphers = b"\x02\x00\x00\x0f\xac\x04\x00\x0f\xac\x09"  # Count=2, CCMP, GCMP-256
                akm = b"\x04\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x00\x0f\xac\x08\x00\x0f\xac\x09\x8c\x00"
                rsn_data = b"\x01\x00\x00\x0f\xac\x04" + pairwise_ciphers + akm
            else:
                # FT-WPA2 only
                akm = b"\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x8c\x00"
                rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04" + akm

        rsn = Dot11Elt(ID=0x30, info=rsn_data)

        ht_info_data = (
            bytes(channel)
            + b"\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        ht_information = Dot11Elt(ID=0x3D, info=ht_info_data)

        rm_enabled_data = b"\x02\x00\x00\x00\x00"
        rm_enabled_cap = Dot11Elt(ID=0x46, info=rm_enabled_data)

        extended_data = b"\x00\x00\x08\x00\x00\x00\x00\x40"
        extended = Dot11Elt(ID=0x7F, info=extended_data)

        vht_cap_data = b"\x32\x00\x80\x03\xaa\xff\x00\x00\xaa\xff\x00\x00"
        vht_capabilities = Dot11Elt(ID=0xBF, info=vht_cap_data)

        vht_op_data = b"\x00\x24\x00\x00\x00"
        vht_operation = Dot11Elt(ID=0xC0, info=vht_op_data)

        wmm_data = b"\x00\x50\xf2\x02\x01\x01\x8a\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"
        wmm = Dot11Elt(ID=0xDD, info=wmm_data)

        he_cap_data = b"\x23\x0d\x01\x00\x02\x40\x00\x04\x70\x0c\x89\x7f\x03\x80\x04\x00\x00\x00\xaa\xaa\xaa\xaa\x7b\x1c\xc7\x71\x1c\xc7\x71\x1c\xc7\x71\x1c\xc7\x71"
        he_capabilities = Dot11Elt(ID=0xFF, info=he_cap_data)

        he_op_data = b"\x24\xf4\x3f\x00\x19\xfc\xff"
        he_operation = Dot11Elt(ID=0xFF, info=he_op_data)

        spatial_reuse_data = b"\x27\x05\x00"
        spatial_reuse = Dot11Elt(ID=0xFF, info=spatial_reuse_data)

        mu_edca_data = b"\x26\x09\x03\xa4\x28\x27\xa4\x28\x42\x73\x28\x62\x72\x28"
        mu_edca = Dot11Elt(ID=0xFF, info=mu_edca_data)

        eht_cap_data = b"\x6c\x00\x00\xe2\xff\xdb\x00\x18\x36\xd8\x1e\x00\x44\x44\x44\x44\x44\x44\x44\x44\x44"
        eht_capabilities = Dot11Elt(ID=0xFF, info=eht_cap_data)

        # EHT CBW
        # 0111 7 or 1100 C - 320 MHz
        # 0011 3 or 1011 B - 160 MHz
        # 0010 2 or 1010 A - 80 MHz
        # 0001 1 or 1001 9 - 40 MHz
        # 0000 0 or 1000 8 - 20 MHz
        # eht_op_data = b"\x6a\x05\x11\x00\x00\x00\xf8\x4f\x3f" # 20 MHz CBW
        # eht_op_data24 = b"\x6a\x05\x11\x00\x00\x00\xf9\x4f\x3f" # 40 MHz CBW
        # eht_op_data = b"\x6a\x05\x11\x00\x00\x00\xfa\x4f\x3f" # 80 MHz CBW
        eht_op_data5 = b"\x6a\x05\x11\x00\x00\x00\xfb\x4f\x3f"  # 160 MHz CBW
        # eht_op_data6 = b"\x6a\x05\x11\x00\x00\x00\xfc\x4f\x3f" # 320 MHz CBW

        eht_operation = Dot11Elt(ID=0xFF, info=eht_op_data5)

        # Multi-Link Element (MLE) - currently not included in frame
        # mac = mac.replace(":", "")
        # mle_data = b"\x6b\xb0\x01\x0d" + b"\x40\xed\x00\xad\xaa\x1b" + b"\x02\x00\x01\x00\x41\x00"
        # mle_data = (
        #     b"\x6b\xb0\x01\x0d" + bytes.fromhex(mac) + b"\x02\x00\x01\x00\x41\x00"
        # )
        # mle = Dot11Elt(ID=0xFF, info=mle_data)

        frame = essid / rates / dsset / dtim / ht_capabilities / rsn

        # Add mobility domain if FT is enabled
        if mobility_domain is not None:
            frame = frame / mobility_domain

        frame = (
            frame
            / ht_information
            / rm_enabled_cap
            / extended
            / vht_capabilities
            / vht_operation
        )

        if not profiler_tlv_disabled:
            # Add WLAN Pi vendor IE
            frame = frame / _Utils.build_wlanpi_vendor_ie_type_0(testing)

        frame = frame / wmm

        if not he_disabled:
            frame = frame / he_capabilities / he_operation / spatial_reuse / mu_edca

        if not be_disabled:
            frame = frame / eht_operation / eht_capabilities
            # frame = frame / mle / eht_operation / eht_capabilities

        return frame

    @staticmethod
    def build_fake_frame_ies_6ghz(
        ssid, channel, ft_disabled, be_disabled, profiler_tlv_disabled, testing
    ) -> Dot11Elt:
        """Build base frame for beacon and probe resp"""
        log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        log.debug("building 6 GHz frame")
        ssid_bytes: bytes = bytes(ssid, "utf-8")
        essid = Dot11Elt(ID="SSID", info=ssid_bytes)

        rates_data = [140, 18, 152, 36, 176, 72, 96, 108]
        rates = Dot11Elt(ID="Rates", info=bytes(rates_data))

        # Note: DSset (channel) element not used in 6 GHz frames
        # channel = bytes([channel])  # type: ignore
        # dsset = Dot11Elt(ID="DSset", info=channel)

        dtim_data = b"\x00\x04\x00\x03\x00\x00"  # Fixed: DTIM count=0, period=4 (was 5, 4 - invalid!)
        dtim = Dot11Elt(ID="TIM", info=dtim_data)

        rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x02\x00\x00\x0f\xac\x08\x00\x0f\xac\x09\xe8\x00"

        mobility_domain_data = b"\x45\xc2\x00"
        mobility_domain = Dot11Elt(ID=0x36, info=mobility_domain_data)

        rsn = Dot11Elt(ID=0x30, info=rsn_data)

        rm_enabled_data = b"\x02\x00\x00\x00\x00"
        rm_enabled_cap = Dot11Elt(ID=0x46, info=rm_enabled_data)

        extended_data = b"\x04\x00\x08\x00\x00\x00\x00\x40\x00\x40\x09"
        extended = Dot11Elt(ID=0x7F, info=extended_data)

        txpowerenv1_data = b"\x58\x2e"
        txpowerenv1 = Dot11Elt(ID=0xC3, info=txpowerenv1_data)

        txpowerenv2_data = b"\x18\xfe"
        txpowerenv2 = Dot11Elt(ID=0xC3, info=txpowerenv2_data)

        wmm_data = b"\x00\x50\xf2\x02\x01\x01\x8a\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"
        wmm = Dot11Elt(ID=0xDD, info=wmm_data)

        he_cap_data = b"\x23\x0d\x01\x00\x02\x40\x00\x04\x70\x0c\x89\x7f\x03\x80\x04\x00\x00\x00\xaa\xaa\xaa\xaa\x7b\x1c\xc7\x71\x1c\xc7\x71\x1c\xc7\x71\x1c\xc7\x71"
        he_capabilities = Dot11Elt(ID=0xFF, info=he_cap_data)

        he_op_data = b"\x24\xf4\x3f\x00\x19\xfc\xff"
        he_operation = Dot11Elt(ID=0xFF, info=he_op_data)

        spatial_reuse_data = b"\x27\x05\x00"
        spatial_reuse = Dot11Elt(ID=0xFF, info=spatial_reuse_data)

        mu_edca_data = b"\x26\x09\x03\xa4\x28\x27\xa4\x28\x42\x73\x28\x62\x72\x28"
        mu_edca = Dot11Elt(ID=0xFF, info=mu_edca_data)

        six_ghz_cap_data = b"\x3b\x00\x00"
        six_ghz_cap = Dot11Elt(ID=0xFF, info=six_ghz_cap_data)

        eht_cap_data = b"\x6c\x00\x00\xe2\xff\xdb\x00\x18\x36\xd8\x1e\x00\x44\x44\x44\x44\x44\x44\x44\x44\x44"
        eht_capabilities = Dot11Elt(ID=0xFF, info=eht_cap_data)

        # EHT CBW
        # 0111 7 or 1100 C - 320 MHz
        # 0011 3 or 1011 B - 160 MHz
        # 0010 2 or 1010 A - 80 MHz
        # 0001 1 or 1001 9 - 40 MHz
        # 0000 0 or 1000 8 - 20 MHz
        # eht_op_data = b"\x6a\x05\x11\x00\x00\x00\xf8\x4f\x3f" # 20 MHz CBW
        # eht_op_data24 = b"\x6a\x05\x11\x00\x00\x00\xf9\x4f\x3f" # 40 MHz CBW
        # eht_op_data = b"\x6a\x05\x11\x00\x00\x00\xfa\x4f\x3f" # 80 MHz CBW
        # eht_op_data5 = b"\x6a\x05\x11\x00\x00\x00\xfb\x4f\x3f" # 160 MHz CBW
        eht_op_data6 = b"\x6a\x05\x11\x00\x00\x00\xfc\x4f\x3f"  # 320 MHz CBW
        eht_operation = Dot11Elt(ID=0xFF, info=eht_op_data6)

        rsnex_data = b"\x20"
        rsnex = Dot11Elt(ID=0xF4, info=rsnex_data)

        frame = (
            essid
            / rates
            / dtim
            / rsn
            / mobility_domain
            / rm_enabled_cap
            / extended
            / txpowerenv1
            / txpowerenv2
        )

        if not profiler_tlv_disabled:
            frame = frame / _Utils.build_wlanpi_vendor_ie_type_0(testing)

        frame = (
            frame
            / wmm
            / he_capabilities
            / he_operation
            / spatial_reuse
            / mu_edca
            / six_ghz_cap
            / rsnex
        )

        if not be_disabled:
            frame = frame / eht_capabilities / eht_operation

        return frame

    @staticmethod
    def build_fake_frame_ies(config, mac, testing=False) -> Dot11Elt:
        """Build base frame for beacon and probe resp"""
        logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        ssid: str = config.get("GENERAL").get("ssid")
        mac = mac
        channel: int = int(config.get("GENERAL").get("channel"))
        frequency: int = int(config.get("GENERAL").get("frequency"))
        ft_disabled: bool = config.get("GENERAL").get("ft_disabled")
        he_disabled: bool = config.get("GENERAL").get("he_disabled")
        be_disabled: bool = config.get("GENERAL").get("be_disabled")
        profiler_tlv_disabled: bool = config.get("GENERAL").get("profiler_tlv_disabled")
        security_mode: str = config.get("GENERAL").get("security_mode", "ft-wpa3-mixed")

        if frequency > 5950:
            frame = _Utils.build_fake_frame_ies_6ghz(
                ssid, channel, ft_disabled, be_disabled, profiler_tlv_disabled, testing
            )
        else:
            frame = _Utils.build_fake_frame_ies_2ghz_5ghz(
                ssid,
                mac,
                channel,
                ft_disabled,
                he_disabled,
                be_disabled,
                security_mode,
                profiler_tlv_disabled,
                testing,
            )
        # for gathering data to validate tests:
        #
        # frame_bytes = bytes(frame)
        # print(frame_bytes)
        return frame

    @staticmethod
    def get_mac(interface: str) -> str:
        """Get the mac address for a specified interface"""
        try:
            mac = get_if_hwaddr(interface)
        except Scapy_Exception:
            mac = ":".join(format(x, "02x") for x in get_if_raw_hwaddr(interface)[1])
        return mac

    @staticmethod
    def next_sequence_number(sequence_number) -> int:
        """Update a sequence number of type multiprocessing Value"""
        sequence_number.value = (sequence_number.value + 1) % 4096
        return sequence_number.value


class TxBeacons(multiprocessing.Process):
    """Handle Tx of fake AP frames"""

    def __init__(
        self,
        config,
        boot_time: datetime.datetime,
        lock,
        sequence_number,
    ):
        super().__init__()
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.debug("beacon pid: %s; parent pid: %s", os.getpid(), os.getppid())
        self.boot_time = boot_time
        self.config = config
        self.sequence_number = sequence_number
        self.ssid: str = config.get("GENERAL").get("ssid")
        self.interface: str = config.get("GENERAL").get("interface")
        channel: str = config.get("GENERAL").get("channel")
        if not channel:
            raise ValueError("cannot determine channel to beacon on")
        self.channel = int(channel)
        scapyconf.iface = self.interface
        self.l2socket = None
        try:
            self.l2socket = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
            )
            self.l2socket.bind((self.interface, 0))
        except OSError as error:
            if error.strerror and "No such device" in error.strerror:
                self.log.warning(
                    "TxBeacons: no such device (%s) ... exiting ...", self.interface
                )
                sys.exit(1)
        if not self.l2socket:
            self.log.error(
                "TxBeacons(): unable to create raw socket with %s ... exiting ...",
                self.interface,
            )
            sys.exit(1)
        self.log.debug("Raw AF_PACKET socket created for beacons on %s", self.interface)

        # Set socket priority for beacons
        try:
            self.l2socket.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 7)
            self.log.info("Socket priority set to 7 (highest) for beacons")
        except OSError as e:
            self.log.warning("Could not set socket priority for beacons: %s", e)
        self.beacon_interval = 0.102_400

        # Beacon process uses its own local sequence counter (no lock contention!)
        self.beacon_seq = 0

        with lock:
            self.mac = _Utils.get_mac(self.interface)
            dot11 = Dot11(
                type=DOT11_TYPE_MANAGEMENT,
                subtype=DOT11_SUBTYPE_BEACON,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self.mac,
                addr3=self.mac,
            )
            dot11beacon = Dot11Beacon(cap=0x1111)
            beacon_frame_ies = _Utils.build_fake_frame_ies(self.config, self.mac)
            self.beacon_frame = RadioTap() / dot11 / dot11beacon / beacon_frame_ies

            # Pre-serialize beacon frame for fast transmission
            beacon_bytes = bytes(self.beacon_frame)

            # Calculate offsets for sequence number
            radiotap_len = struct.unpack("<H", beacon_bytes[2:4])[0]
            self.seq_offset = radiotap_len + 22

            # Store as bytearray for efficient updates
            self.beacon_template = bytearray(beacon_bytes)

            self.log.debug(
                "Beacon template created: %d bytes, seq_offset=%d",
                len(self.beacon_template),
                self.seq_offset,
            )

        self.log.debug(f"origin beacon hexdump {hexdump(self.beacon_frame)}")

    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, "l2socket") and self.l2socket:
            with contextlib.suppress(Exception):
                self.l2socket.close()
            self.l2socket = None

    def __del__(self):
        """Destructor to ensure socket cleanup"""
        self.cleanup()

    def run(self):
        """Main beacon transmission loop - called by multiprocessing.Process.start()"""
        self.log.debug("TxBeacons process started, beginning beacon transmission")
        try:
            while True:
                self.beacon()
                sleep(self.beacon_interval)
        except KeyboardInterrupt:
            self.log.info("TxBeacons received shutdown signal")
        except Exception as e:
            self.log.error("TxBeacons encountered error: %s", e, exc_info=True)
            from profiler.status import ProfilerState, StatusReason, write_status

            write_status(
                state=ProfilerState.FAILED,
                reason=StatusReason.FAKEAP_CRASHED,
                error=str(e),
            )
        finally:
            self.log.debug("TxBeacons shutting down")
            self.cleanup()

    def beacon(self) -> None:
        """Update and Tx Beacon Frame"""
        # Use local sequence counter (no lock, no contention!)
        self.beacon_seq = (self.beacon_seq + 1) % 4096
        seq_num = self.beacon_seq

        # Fast byte-level patching of pre-serialized template
        frame_bytes = bytearray(self.beacon_template)

        # Patch sequence number (bits 4-15 of sequence control field)
        frame_bytes[self.seq_offset : self.seq_offset + 2] = struct.pack(
            "<H", seq_num << 4
        )

        # Send via raw socket
        if not self.l2socket:
            return
        try:
            self.l2socket.send(frame_bytes)
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if error.strerror and event in error.strerror:
                    self.log.warning(
                        "beacon(): network is down or no such device (%s) ... exiting ...",
                        self.interface,
                    )
                    sys.exit(1)


class Sniffer(multiprocessing.Process):
    """Handle sniffing probes and association requests"""

    def __init__(
        self,
        config,
        boot_time: datetime.datetime,
        lock,
        sequence_number,
        queue,
        args,
    ):
        super().__init__()
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.debug("sniffer pid: %s; parent pid: %s", os.getpid(), os.getppid())

        self.queue = queue
        self.boot_time = boot_time
        self.config = config
        self.sequence_number = sequence_number
        self.ssid: str = config.get("GENERAL").get("ssid")
        self.interface: str = config.get("GENERAL").get("interface")
        channel: str = config.get("GENERAL").get("channel")
        if not channel:
            raise ValueError("cannot determine channel to sniff")
        self.channel = int(channel)
        self.listen_only: bool = config.get("GENERAL").get("listen_only")
        self.assoc_reqs: dict = {}

        # Monitoring metrics (track client interactions)
        self.seen_macs: set = set()  # All unique MACs observed
        self.authed_macs: set = set()  # MACs that sent auth request
        self.assoc_macs: set = set()  # MACs that sent assoc request
        self.total_probe_requests = 0  # Total probe requests (can be >1 per MAC)
        self.total_auth_requests = 0  # Total auth requests (can be >1 per MAC)
        self.total_assoc_requests = 0  # Total assoc requests (can be >1 per MAC)
        self.invalid_frame_count = 0  # Corrupted/invalid frames filtered
        self.bad_fcs_count = 0  # Frames with bad FCS (checksum mismatch)
        self.last_stats_log_time: float = 0  # For periodic logging
        self.last_metrics_update_time: float = (
            0  # For debouncing monitoring metrics writes
        )
        self.metrics_update_interval = 10.0  # Write to disk every 10 seconds
        self.metrics_dirty = False  # Track if metrics changed since last write

        # BPF filters for improved kernel-level packet filtering
        # Default to enabled for better performance
        if hasattr(args, "no_bpf_filters") and args.no_bpf_filters:
            # Explicit --no-bpf-filters flag
            self.bpf_filter = ""
            self.log.info("BPF filters disabled (filtering in Python instead)")
        else:
            # Enable BPF filters by default for performance
            self.bpf_filter = "type mgt subtype probe-req or type mgt subtype auth or type mgt subtype assoc-req or type mgt subtype reassoc-req"
            self.log.info(
                "BPF filters enabled (kernel-level filtering for better performance)"
            )
        # mgt bpf filter: assoc-req, assoc-resp, reassoc-req, reassoc-resp, probe-req, probe-resp, beacon, atim, disassoc, auth, deauth
        # ctl bpf filter: ps-poll, rts, cts, ack, cf-end, cf-end-ack
        scapyconf.iface = self.interface
        # self.log.debug(scapyconf.ifaces)
        self.l2socket = None
        try:
            self.l2socket = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
            )
            self.l2socket.bind((self.interface, 0))
        except OSError as error:
            if error.strerror and "No such device" in error.strerror:
                self.log.warning(
                    "Sniffer: No such device (%s) ... exiting ...", self.interface
                )
                sys.exit(1)
        if not self.l2socket:
            self.log.error(
                "Sniffer(): unable to create raw socket with %s ... exiting ...",
                self.interface,
            )
            sys.exit(1)
        self.log.debug("Raw AF_PACKET socket created for %s", self.interface)

        # Set socket priority for probe responses
        try:
            self.l2socket.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 7)
            self.log.info("Socket priority set to 7 (highest) for probe responses")
        except OSError as e:
            self.log.warning("Could not set socket priority for responses: %s", e)

        self.received_frame_cb = self.received_frame
        # Determine if we're in Rx-only mode (listen-only or hostapd mode)
        if self.listen_only:
            # Check if this is hostapd mode (ap_mode=True) or true listen-only
            ap_mode = config.get("GENERAL", {}).get("ap_mode", False)
            if ap_mode:
                self.log.info(
                    "Sniffer in Rx-only mode (hostapd AP handles probe/auth responses)"
                )
            else:
                self.log.info(
                    "Sniffer in Rx-only mode (passive monitoring, no AP responses)"
                )
            self.dot11_probe_request_cb = lambda *args, **kwargs: None  # No-op
            self.dot11_auth_cb = lambda *args, **kwargs: None  # No-op
        else:
            self.dot11_probe_request_cb = self.probe_response
            self.dot11_auth_cb = self.auth
        self.dot11_assoc_request_cb = self.assoc_req
        with lock:
            self.mac = _Utils.get_mac(self.interface)
            probe_resp_ies = _Utils.build_fake_frame_ies(self.config, self.mac)
            self.probe_response_frame = (
                RadioTap()
                / Dot11(
                    subtype=DOT11_SUBTYPE_PROBE_RESP, addr2=self.mac, addr3=self.mac
                )
                / Dot11ProbeResp(cap=0x1111)
                / probe_resp_ies
            )
            self.auth_frame = (
                RadioTap()
                / Dot11(subtype=DOT11_SUBTYPE_AUTH_REQ, addr2=self.mac, addr3=self.mac)
                / Dot11Auth(seqnum=0x02)
            )

            # Pre-serialize frames to bytearrays for fast patching
            probe_resp_bytes = bytes(self.probe_response_frame)
            auth_bytes = bytes(self.auth_frame)

            # Calculate RadioTap header length (bytes 2-3, little-endian)
            radiotap_len = struct.unpack("<H", probe_resp_bytes[2:4])[0]

            # 802.11 MAC header offsets (after RadioTap header)
            # Frame Control (2) + Duration (2) + addr1 (6) + addr2 (6) + addr3 (6) + Seq (2)
            self.addr1_offset = radiotap_len + 4
            self.seq_offset = radiotap_len + 22

            # Store templates as bytearrays for efficient in-place updates
            self.probe_response_template = bytearray(probe_resp_bytes)
            self.auth_template = bytearray(auth_bytes)

            # Pre-allocate buffers for zero-allocation response path
            self.probe_response_buffer = bytearray(len(probe_resp_bytes))
            self.auth_buffer = bytearray(len(auth_bytes))

            # MAC address cache for repeated clients (LRU with 128 entries)
            from functools import lru_cache

            @lru_cache(maxsize=128)
            def parse_mac_cached(mac_str):
                return bytes.fromhex(mac_str.replace(":", ""))

            self._parse_mac = parse_mac_cached

            # Sniffer process uses its own local sequence counter (no lock contention!)
            self.sniffer_seq = 0

            # Only log frame template details in fake AP mode (not needed in hostapd mode)
            if not self.listen_only:
                self.log.debug(
                    "Frame templates created: probe=%d bytes, auth=%d bytes, addr1_offset=%d, seq_offset=%d (using local seq counter)",
                    len(self.probe_response_template),
                    len(self.auth_template),
                    self.addr1_offset,
                    self.seq_offset,
                )

    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, "l2socket") and self.l2socket:
            with contextlib.suppress(Exception):
                self.l2socket.close()
            self.l2socket = None

    def __del__(self):
        """Destructor to ensure socket cleanup"""
        self.cleanup()

    def run(self):
        """Main process loop - called by multiprocessing.Process.start()"""
        try:
            sniff(
                iface=self.interface,
                prn=self.received_frame_cb,
                store=0,
                filter=self.bpf_filter,
                promisc=False,
            )
        except KeyboardInterrupt:
            self.log.info("Sniffer received shutdown signal")
            self.log_session_stats()  # Log final stats on shutdown
        except Scapy_Exception as error:
            if "ailed to compile filter" in str(error):
                self.log.warning(
                    "BPF filter compilation failed on %s, retrying without filters",
                    self.interface,
                )
                self.log.info(
                    "Running without BPF filters (filtering in Python instead)"
                )
                # Retry without BPF filters
                try:
                    sniff(
                        iface=self.interface,
                        prn=self.received_frame_cb,
                        store=0,
                        filter="",
                        promisc=False,
                    )
                except Exception:
                    self.log.exception(
                        "scapy.sniff() failed even without BPF filters: %s",
                        exc_info=True,
                    )
                    from profiler.status import (
                        ProfilerState,
                        StatusReason,
                        write_status,
                    )

                    write_status(
                        state=ProfilerState.FAILED,
                        reason=StatusReason.FAKEAP_CRASHED,
                        error="scapy.sniff() failed without BPF filters",
                    )
                    sys.exit(1)
            else:
                self.log.exception(
                    "scappy.sniff() problem in fakeap.py sniffer(): %s",
                    exc_info=True,
                )
                from profiler.status import ProfilerState, StatusReason, write_status

                write_status(
                    state=ProfilerState.FAILED,
                    reason=StatusReason.FAKEAP_CRASHED,
                    error=f"scapy.sniff() error: {error}",
                )
                sys.exit(1)
        finally:
            # Always log final stats and write final metrics on exit
            self.log.info("Sniffer shutting down")
            if self.invalid_frame_count > 0:
                self.log.info(
                    f"Filtered {self.invalid_frame_count} invalid/corrupted frames during session"
                )
            if self.bad_fcs_count > 0:
                self.log.info(
                    f"Filtered {self.bad_fcs_count} frames with bad FCS during session"
                )
            self.log_session_stats()
            # Force write final monitoring metrics (bypass debounce)
            self._update_monitoring_metrics(force=True)

    def received_frame(self, packet) -> None:
        """Handle incoming packets for profiling"""
        # Check if this is a Dot11 packet (802.11 management frame)
        if not packet.haslayer(Dot11):
            return  # Ignore non-802.11 packets

        # Periodic stats logging (every 60 seconds)
        current_time = time()
        if current_time - self.last_stats_log_time >= 60:
            self.log_session_stats()
            self.last_stats_log_time = current_time

        # Track all unique MACs seen (any frame type)
        mac = packet.addr2
        if mac and mac not in self.seen_macs:
            self.seen_macs.add(mac)
            self._update_monitoring_metrics()

        if packet.subtype == DOT11_SUBTYPE_AUTH_REQ:  # auth
            if packet.addr1 == self.mac:  # if we are the receiver
                self.log.debug("rx auth sent from MAC %s", packet.addr2)
                # Track auth metrics
                self.total_auth_requests += 1
                if mac not in self.authed_macs:
                    self.authed_macs.add(mac)
                    self._update_monitoring_metrics()
                self.dot11_auth_cb(packet.addr2)
        elif packet.subtype == DOT11_SUBTYPE_PROBE_REQ:  # probe request
            self.total_probe_requests += 1
            if Dot11Elt in packet and packet[Dot11Elt].ID == 0:
                ssid = packet[Dot11Elt].info
                try:
                    decoded = ssid.decode("latin-1")
                except UnicodeDecodeError:
                    decoded = ""
                if ssid == self.ssid.encode() or packet[Dot11Elt].len == 0:
                    self.dot11_probe_request_cb(packet, ssid, decoded)
        elif (
            packet.subtype == DOT11_SUBTYPE_ASSOC_REQ
            or packet.subtype == DOT11_SUBTYPE_REASSOC_REQ
        ):
            # Track assoc metrics
            self.total_assoc_requests += 1
            if mac not in self.assoc_macs:
                self.assoc_macs.add(mac)
                self._update_monitoring_metrics()

            if packet.addr1 == self.mac:  # if we are the receiver
                self.dot11_assoc_request_cb(packet)
            if self.listen_only:
                self.dot11_assoc_request_cb(packet)

            # self.log.debug("packet dump for %s %s", packet.addr2, packet.show(dump=True))
            if Dot11Elt in packet:
                if packet[Dot11Elt].ID == 0:
                    self.log.debug(
                        "assoc req seen for %s (%s) by MAC %s",
                        packet[Dot11Elt].info,
                        packet.addr1,
                        packet.addr2,
                    )
            else:
                self.log.debug("SSID missing in assoc req by MAC %s", packet.addr2)

    def probe_response(
        self, probe_request: Any, ssid: bytes = b"", decoded: str = ""
    ) -> None:
        """Send probe resp to assist with profiler discovery"""
        t_start = time()

        # Use local sequence counter (no lock, no contention!)
        self.sniffer_seq = (self.sniffer_seq + 1) % 4096
        seq_num = self.sniffer_seq
        lock_wait_ms = 0.0  # No lock anymore!
        lock_ms = 0.0

        # Fast byte-level patching using pre-allocated buffer
        t_manip_start = time()

        # Reuse buffer (in-place copy for zero allocation)
        self.probe_response_buffer[:] = self.probe_response_template

        # Parse destination MAC from string to bytes (with caching)
        client_mac_bytes = self._parse_mac(probe_request.addr2)

        # Patch addr1 (destination MAC)
        self.probe_response_buffer[self.addr1_offset : self.addr1_offset + 6] = (
            client_mac_bytes
        )

        # Patch sequence number (bits 4-15 of sequence control field)
        self.probe_response_buffer[self.seq_offset : self.seq_offset + 2] = struct.pack(
            "<H", seq_num << 4
        )

        t_manip_end = time()
        manip_ms = (t_manip_end - t_manip_start) * 1000

        # Send via raw socket
        if not self.l2socket:
            return
        t_send_start = time()
        try:
            self.l2socket.send(self.probe_response_buffer)
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if error.strerror and event in error.strerror:
                    self.log.exception(
                        "probe_response(): network is down or no such device ... exiting ..."
                    )
                    sys.exit(1)
        t_send_end = time()
        send_ms = (t_send_end - t_send_start) * 1000

        t_end = time()
        total_ms = (t_end - t_start) * 1000

        self.log.debug(
            "rx probe req for %s (%s) by MAC %s | seq=%d wait=%.3fms lock=%.3fms manip=%.3fms send=%.3fms total=%.3fms",
            ssid,
            decoded,
            probe_request.addr2,
            seq_num,
            lock_wait_ms,
            lock_ms,
            manip_ms,
            send_ms,
            total_ms,
        )

    def assoc_req(self, frame: Any) -> None:
        """Put association request on queue for the Profiler"""
        if not is_valid_mac(frame.addr2) or not is_valid_mac(frame.addr1):
            self.invalid_frame_count += 1
            return

        if has_bad_fcs(frame):
            self.bad_fcs_count += 1
            self.log.debug("dropping frame with bad FCS from %s", frame.addr2)
            return

        self.assoc_reqs[frame.addr2] = frame
        self.log.debug("adding assoc req from %s to queue", frame.addr2)
        self.queue.put(frame)

    def auth(self, receiver: str) -> None:
        """Send authentication frame to get the station to prompt an assoc request"""
        t_start = time()

        # Use local sequence counter (no lock, no contention!)
        self.sniffer_seq = (self.sniffer_seq + 1) % 4096
        seq_num = self.sniffer_seq
        lock_ms = 0.0  # No lock anymore!

        # Fast byte-level patching using pre-allocated buffer
        t_manip_start = time()

        # Reuse buffer (in-place copy for zero allocation)
        self.auth_buffer[:] = self.auth_template

        # Parse destination MAC from string to bytes (with caching)
        client_mac_bytes = self._parse_mac(receiver)

        # Patch addr1 (destination MAC)
        self.auth_buffer[self.addr1_offset : self.addr1_offset + 6] = client_mac_bytes

        # Patch sequence number (bits 4-15 of sequence control field)
        self.auth_buffer[self.seq_offset : self.seq_offset + 2] = struct.pack(
            "<H", seq_num << 4
        )

        t_manip_end = time()
        manip_ms = (t_manip_end - t_manip_start) * 1000

        # Send via raw socket
        if not self.l2socket:
            return
        t_send_start = time()
        try:
            self.l2socket.send(self.auth_buffer)
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if error.strerror and event in error.strerror:
                    self.log.warning(
                        "auth(): network is down or no such device ... exiting ..."
                    )
                    sys.exit(1)
        t_send_end = time()
        send_ms = (t_send_end - t_send_start) * 1000

        t_end = time()
        total_ms = (t_end - t_start) * 1000

        self.log.debug(
            "tx authentication (0x0B) to %s | seq=%d lock=%.3fms manip=%.3fms send=%.3fms total=%.3fms",
            receiver,
            seq_num,
            lock_ms,
            manip_ms,
            send_ms,
            total_ms,
        )

    def _update_monitoring_metrics(self, force: bool = False) -> None:
        """Update monitoring metrics in info file (debounced to reduce disk I/O)

        Args:
            force: If True, bypass debounce and write immediately (e.g., on shutdown)
        """
        from .status import update_monitoring_metrics_in_info

        # Mark that metrics have changed
        self.metrics_dirty = True

        # Check if enough time has passed since last update (debounce)
        current_time = time()
        time_since_last_update = current_time - self.last_metrics_update_time

        if not force and time_since_last_update < self.metrics_update_interval:
            # Too soon - skip this update to reduce disk I/O
            return

        # Only write if metrics actually changed
        if not self.metrics_dirty and not force:
            return

        # Calculate failed profile count: MACs that authed but never sent assoc
        failed_count = len(self.authed_macs - self.assoc_macs)

        update_monitoring_metrics_in_info(
            total_clients_seen=len(self.seen_macs),
            failed_profile_count=failed_count,
            invalid_frame_count=self.invalid_frame_count,
            bad_fcs_count=self.bad_fcs_count,
        )

        # Reset debounce timer and dirty flag
        self.last_metrics_update_time = current_time
        self.metrics_dirty = False

    def log_session_stats(self) -> None:
        """Log current session statistics"""
        failed_count = len(self.authed_macs - self.assoc_macs)

        self.log.debug(
            f"Session stats: probes={self.total_probe_requests}, "
            f"auths={self.total_auth_requests}, "
            f"assocs={self.total_assoc_requests}, "
            f"unique_clients={len(self.seen_macs)}, "
            f"failed={failed_count}, "
            f"invalid_frames={self.invalid_frame_count}, "
            f"bad_fcs={self.bad_fcs_count}"
        )
