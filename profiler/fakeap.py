# -*- coding: utf-8 -*-
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.fakeap
~~~~~~~~~~~~~~~

fake ap code handling beaconing and sniffing for the profiler
"""

# standard library imports
import datetime
import inspect
import logging
import multiprocessing
import os
import signal
import sys
from time import sleep, time
from typing import Dict

# suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# third party imports
try:
    from scapy.all import Dot11Beacon  # type: ignore
    from scapy.all import Dot11Elt  # type: ignore
    from scapy.all import Dot11ProbeResp  # type: ignore
    from scapy.all import (  # type: ignore
        Dot11,
        Dot11Auth,
        RadioTap,
        Scapy_Exception,
    )
    from scapy.all import conf as scapyconf  # type: ignore
    from scapy.all import (  # type: ignore
        get_if_hwaddr,
        get_if_raw_hwaddr,
        hexdump,
        sniff,
    )
except ModuleNotFoundError as error:
    if error.name == "scapy":
        print("required module scapy not found.")
    else:
        print(f"{error}")
    sys.exit(signal.SIGABRT)

from .__version__ import __version__

# app imports
from .constants import (
    DOT11_SUBTYPE_ASSOC_REQ,
    DOT11_SUBTYPE_AUTH_REQ,
    DOT11_SUBTYPE_BEACON,
    DOT11_SUBTYPE_PROBE_REQ,
    DOT11_SUBTYPE_PROBE_RESP,
    DOT11_SUBTYPE_REASSOC_REQ,
    DOT11_TYPE_MANAGEMENT,
)
from .helpers import get_wlanpi_version


class _Utils:
    """Fake AP helper functions"""

    def build_wlanpi_vendor_ie_type_0(testing):
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
        profiler_version_type = int(0).to_bytes(1, "big")
        profiler_version_data = bytes(f"{profiler_version}".encode("ascii"))
        profiler_version_length = len(profiler_version_data).to_bytes(1, "big")
        profiler_version_tlv = (
            profiler_version_type + profiler_version_length + profiler_version_data
        )

        system_version = get_wlanpi_version()
        if testing:
            system_version = "9.9.9"
        system_version_type = int(1).to_bytes(1, "big")
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
        wpa3_personal_transition,
        wpa3_personal,
        profiler_tlv_disabled,
        testing,
    ) -> Dot11Elt:
        """Build base frame for beacon and probe resp"""
        ssid_bytes: "bytes" = bytes(ssid, "utf-8")
        essid = Dot11Elt(ID="SSID", info=ssid_bytes)

        rates_data = [140, 18, 152, 36, 176, 72, 96, 108]
        rates = Dot11Elt(ID="Rates", info=bytes(rates_data))

        channel = bytes([channel])  # type: ignore
        dsset = Dot11Elt(ID="DSset", info=channel)

        dtim_data = b"\x05\x04\x00\x03\x00\x00"
        dtim = Dot11Elt(ID="TIM", info=dtim_data)

        ht_cap_data = b"\xef\x19\x1b\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        ht_capabilities = Dot11Elt(ID=0x2D, info=ht_cap_data)

        if ft_disabled:
            akm = b"\x01\x00\x00\x0f\xac\x02\x80\x00"
            if wpa3_personal_transition:
                akm = b"\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x08\x80\x00"
            if wpa3_personal:
                akm = b"\x01\x00\x00\x0f\xac\x08\x90\x00"
            rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04" + akm
        else:
            mobility_domain_data = b"\x45\xc2\x00"
            mobility_domain = Dot11Elt(ID=0x36, info=mobility_domain_data)
            akm = b"\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x8c\x00"
            if wpa3_personal_transition:
                akm = b"\x04\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x00\x0f\xac\x08\x00\x0f\xac\x09\x8c\x00"
            if wpa3_personal:
                akm = b"\x02\x00\x00\x0f\xac\x08\x00\x0f\xac\x09\x9c\x00"
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

        mac = mac.replace(":", "")
        # mle_data = b"\x6b\xb0\x01\x0d" + b"\x40\xed\x00\xad\xaa\x1b" + b"\x02\x00\x01\x00\x41\x00"
        mle_data = (
            b"\x6b\xb0\x01\x0d" + bytes.fromhex(mac) + b"\x02\x00\x01\x00\x41\x00"
        )
        mle = Dot11Elt(ID=0xFF, info=mle_data)

        frame = essid / rates / dsset / dtim / ht_capabilities / rsn

        if not ft_disabled:
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
        ssid_bytes: "bytes" = bytes(ssid, "utf-8")
        essid = Dot11Elt(ID="SSID", info=ssid_bytes)

        rates_data = [140, 18, 152, 36, 176, 72, 96, 108]
        rates = Dot11Elt(ID="Rates", info=bytes(rates_data))

        channel = bytes([channel])  # type: ignore
        dsset = Dot11Elt(ID="DSset", info=channel)

        dtim_data = b"\x05\x04\x00\x03\x00\x00"
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
        ssid: "str" = config.get("GENERAL").get("ssid")
        mac = mac
        channel: int = int(config.get("GENERAL").get("channel"))
        frequency: int = int(config.get("GENERAL").get("frequency"))
        ft_disabled: "bool" = config.get("GENERAL").get("ft_disabled")
        he_disabled: "bool" = config.get("GENERAL").get("he_disabled")
        be_disabled: "bool" = config.get("GENERAL").get("be_disabled")
        profiler_tlv_disabled: "bool" = config.get("GENERAL").get(
            "profiler_tlv_disabled"
        )
        wpa3_personal_transition: "bool" = config.get("GENERAL").get(
            "wpa3_personal_transition"
        )
        wpa3_personal: "bool" = config.get("GENERAL").get("wpa3_personal")

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
                wpa3_personal_transition,
                wpa3_personal,
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
        super(TxBeacons, self).__init__()
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.debug("beacon pid: %s; parent pid: %s", os.getpid(), os.getppid())
        self.boot_time = boot_time
        self.config = config
        self.sequence_number = sequence_number
        self.ssid: "str" = config.get("GENERAL").get("ssid")
        self.interface: "str" = config.get("GENERAL").get("interface")
        channel: "str" = config.get("GENERAL").get("channel")
        if not channel:
            raise ValueError("cannot determine channel to beacon on")
        self.channel = int(channel)
        scapyconf.iface = self.interface
        self.l2socket = None
        try:
            self.l2socket = scapyconf.L2socket(iface=self.interface)
        except OSError as error:
            if "No such device" in error.strerror:
                self.log.warning(
                    "TxBeacons: no such device (%s) ... exiting ...", self.interface
                )
                sys.exit(signal.SIGALRM)
        if not self.l2socket:
            self.log.error(
                "TxBeacons(): unable to create L2socket with %s ... exiting ...",
                self.interface,
            )
            sys.exit(signal.SIGALRM)
        self.log.debug(self.l2socket.outs)
        self.beacon_interval = 0.102_400

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

        self.log.debug(f"origin beacon hexdump {hexdump(self.beacon_frame)}")
        self.log.info("starting beacon transmissions")
        self.every(self.beacon_interval, self.beacon)

    def every(self, interval: float, task) -> None:
        """Attempt to address beacon drift"""
        start_time = time()
        while True:
            task()
            sleep(interval - ((time() - start_time) % interval))

    def beacon(self) -> None:
        """Update and Tx Beacon Frame"""
        frame = self.beacon_frame
        with self.sequence_number.get_lock():
            frame.sequence_number = _Utils.next_sequence_number(self.sequence_number)

        # print(f"frame.sequence_number: {frame.sequence_number}")
        # frame.sequence_number value is updating here, but not updating in pcap for some adapters
        # this appears to impact MediaTek adapters vs RealTek

        # ts = int((datetime.now().timestamp() - self.boot_time) * 1000000)
        # frame[Dot11Beacon].timestamp = ts

        # INFO: SCAPY TIMESTAMP FIELD INFORMATION
        # class LELongField(LongField):
        #     def __init__(self, name, default):
        #         Field.__init__(self, name, default, "<Q")
        #
        # < is little-endian
        # unsigned long long
        # size is 8

        # self.log.debug("frame timestamp: %s", convert_timestamp_to_uptime(ts))
        # scapy is doing something werid with our timestamps.
        # pcap shows wrong timestamp values
        try:
            self.l2socket.send(frame)  # type: ignore
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if event in error.strerror:
                    self.log.warning(
                        "beacon(): network is down or no such device (%s) ... exiting ...",
                        self.interface,
                    )
                    sys.exit(signal.SIGALRM)


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
        super(Sniffer, self).__init__()
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.debug("sniffer pid: %s; parent pid: %s", os.getpid(), os.getppid())

        self.queue = queue
        self.boot_time = boot_time
        self.config = config
        self.sequence_number = sequence_number
        self.ssid: "str" = config.get("GENERAL").get("ssid")
        self.interface: "str" = config.get("GENERAL").get("interface")
        channel: "str" = config.get("GENERAL").get("channel")
        if not channel:
            raise ValueError("cannot determine channel to sniff")
        self.channel = int(channel)
        self.listen_only: "bool" = config.get("GENERAL").get("listen_only")
        self.assoc_reqs: "Dict" = {}

        self.bpf_filter = "type mgt subtype probe-req or type mgt subtype auth or type mgt subtype assoc-req or type mgt subtype reassoc-req"
        if args.no_bpf_filters:
            self.bpf_filter = ""
        # mgt bpf filter: assoc-req, assoc-resp, reassoc-req, reassoc-resp, probe-req, probe-resp, beacon, atim, disassoc, auth, deauth
        # ctl bpf filter: ps-poll, rts, cts, ack, cf-end, cf-end-ack
        scapyconf.iface = self.interface
        # self.log.debug(scapyconf.ifaces)
        self.l2socket = None
        try:
            self.l2socket = scapyconf.L2socket(iface=self.interface)
        except OSError as error:
            if "No such device" in error.strerror:
                self.log.warning(
                    "Sniffer: No such device (%s) ... exiting ...", self.interface
                )
                sys.exit(signal.SIGALRM)
        if not self.l2socket:
            self.log.error(
                "Sniffer(): unable to create L2socket with %s ... exiting ...",
                self.interface,
            )
            sys.exit(signal.SIGALRM)
        self.log.debug(self.l2socket.outs)

        self.received_frame_cb = self.received_frame
        self.dot11_probe_request_cb = self.probe_response
        self.dot11_assoc_request_cb = self.assoc_req
        self.dot11_auth_cb = self.auth
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
        try:
            sniff(
                iface=self.interface,
                prn=self.received_frame_cb,
                store=0,
                filter=self.bpf_filter,
            )
        except Scapy_Exception as error:
            if "ailed to compile filter" in str(error):
                self.log.exception(
                    "we had a problem creating BPF filters on L2socket/%s",
                    self.interface,
                    exc_info=True,
                )
                self.log.info("try running with --no_bpf_filters")
            else:
                self.log.exception(
                    "scappy.sniff() problem in fakeap.py sniffer(): %s",
                    exc_info=True,
                )
            signal.SIGALRM

    def received_frame(self, packet) -> None:
        """Handle incoming packets for profiling"""
        if packet.subtype == DOT11_SUBTYPE_AUTH_REQ:  # auth
            if packet.addr1 == self.mac:  # if we are the receiver
                self.log.debug("rx auth sent from MAC %s", packet.addr2)
                self.dot11_auth_cb(packet.addr2)
        elif packet.subtype == DOT11_SUBTYPE_PROBE_REQ:  # probe request
            if Dot11Elt in packet:
                if packet[Dot11Elt].ID == 0:
                    ssid = packet[Dot11Elt].info
                    try:
                        decoded = ssid.decode("latin-1")
                    except UnicodeDecodeError:
                        decoded = ""
                    self.log.debug(
                        "rx probe req for %s (%s) by MAC %s",
                        ssid,
                        decoded,
                        packet.addr2,
                    )
                    if ssid == self.ssid.encode() or packet[Dot11Elt].len == 0:
                        self.dot11_probe_request_cb(packet)
        elif (
            packet.subtype == DOT11_SUBTYPE_ASSOC_REQ
            or packet.subtype == DOT11_SUBTYPE_REASSOC_REQ
        ):
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

    def probe_response(self, probe_request) -> None:
        """Send probe resp to assist with profiler discovery"""
        frame = self.probe_response_frame
        with self.sequence_number.get_lock():
            frame.sequence_number = _Utils.next_sequence_number(self.sequence_number)
        frame[Dot11].addr1 = probe_request.addr2
        try:
            self.l2socket.send(frame)  # type: ignore
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if event in error.strerror:
                    self.log.exception(
                        "probe_response(): network is down or no such device ... exiting ..."
                    )
                    sys.exit(signal.SIGALRM)
        self.log.debug("tx probe resp to %s", probe_request.addr2)

    def assoc_req(self, frame) -> None:
        """Put association request on queue for the Profiler"""
        self.assoc_reqs[frame.addr2] = frame
        self.log.debug("adding assoc req from %s to queue", frame.addr2)
        self.queue.put(frame)

    def auth(self, receiver) -> None:
        """Send authentication frame to get the station to prompt an assoc request"""
        frame = self.auth_frame
        frame[Dot11].addr1 = receiver
        with self.sequence_number.get_lock():
            frame.sequence_number = (
                _Utils.next_sequence_number(self.sequence_number) - 1
            )

        self.log.debug("tx authentication (0x0B) to %s", receiver)

        try:
            self.l2socket.send(frame)  # type: ignore
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if event in error.strerror:
                    self.log.warning(
                        "auth(): network is down or no such device ... exiting ..."
                    )
                    sys.exit(signal.SIGALRM)
