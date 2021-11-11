# -*- coding: utf-8 -*-
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2020-2021 Josh Schmelzle
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
    from scapy.all import Dot11, Dot11Auth, RadioTap, Scapy_Exception  # type: ignore
    from scapy.all import conf as scapyconf  # type: ignore
    from scapy.all import get_if_hwaddr, get_if_raw_hwaddr, sniff  # type: ignore
except ModuleNotFoundError as error:
    if error.name == "scapy":
        print("required module scapy not found.")
    else:
        print(f"{error}")
    sys.exit(signal.SIGABRT)

# app imports
from .constants import (
    CHANNELS,
    DOT11_SUBTYPE_ASSOC_REQ,
    DOT11_SUBTYPE_AUTH_REQ,
    DOT11_SUBTYPE_BEACON,
    DOT11_SUBTYPE_PROBE_REQ,
    DOT11_SUBTYPE_PROBE_RESP,
    DOT11_SUBTYPE_REASSOC_REQ,
    DOT11_TYPE_MANAGEMENT,
)


class _Utils:
    """Fake AP helper functions"""

    @staticmethod
    def build_fake_frame_ies(config) -> Dot11Elt:
        """Build base frame for beacon and probe resp"""
        ssid: "str" = config.get("GENERAL").get("ssid")
        channel = int(config.get("GENERAL").get("channel"))

        is_6ghz = False
        if channel in CHANNELS["6G"]:
            is_6ghz = True

        ft_disabled: "bool" = config.get("GENERAL").get("ft_disabled")
        he_disabled: "bool" = config.get("GENERAL").get("he_disabled")

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
            rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x80\x00"
        else:
            mobility_domain_data = b"\x45\xc2\x00"
            mobility_domain = Dot11Elt(ID=0x36, info=mobility_domain_data)
            rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x8c\x00"

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

        six_ghz_cap_data = b"\x3b\x00\x00"
        six_ghz_cap = Dot11Elt(ID=0xFF, info=six_ghz_cap_data)

        # reduced_neighbor_report_data = b"\x02"
        # reduced_neighbor_report = Dot11Elt(ID=0xFF, info=reduced_neighbor_report_data)

        # custom_hash = {"pver": f"{__version__}", "sver": get_wlanpi_version()}
        # custom_data = bytes(f"{custom_hash}", "utf-8")
        # custom = Dot11Elt(ID=0xDE, info=custom_data)

        if is_6ghz:
            frame = essid / rates / dsset / dtim / rsn / rm_enabled_cap / extended
        elif ft_disabled:
            frame = (
                essid
                / rates
                / dsset
                / dtim
                / ht_capabilities
                / rsn
                / ht_information
                / rm_enabled_cap
                / extended
                / vht_capabilities
                / vht_operation
            )
        else:
            frame = (
                essid
                / rates
                / dsset
                / dtim
                / ht_capabilities
                / rsn
                / ht_information
                / mobility_domain
                / rm_enabled_cap
                / extended
                / vht_capabilities
                / vht_operation
            )
        if he_disabled:
            frame = frame / wmm
        else:
            frame = (
                frame
                # / reduced_neighbor_report
                / he_capabilities
                / he_operation
                / spatial_reuse
                / mu_edca
                / six_ghz_cap
                / wmm
                # / custom
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
        try:
            self.l2socket = scapyconf.L2socket(iface=self.interface)
        except OSError as error:
            if "No such device" in error.strerror:
                self.log.warning(
                    "TxBeacons: No such device (%s) ... exiting ...", self.interface
                )
                sys.exit(signal.SIGTERM)
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
            beacon_frame_ies = _Utils.build_fake_frame_ies(self.config)
            self.beacon_frame = RadioTap() / dot11 / dot11beacon / beacon_frame_ies

        # self.log.debug(f"origin beacon hexdump {hexdump(self.beacon_frame)}")
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
            self.l2socket.send(frame)
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if event in error.strerror:
                    self.log.info("exiting...")
                    sys.exit(signal.SIGTERM)


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
        if args.no_sniffer_filter:
            self.bpf_filter = ""
        # mgt bpf filter: assoc-req, assoc-resp, reassoc-req, reassoc-resp, probe-req, probe-resp, beacon, atim, disassoc, auth, deauth
        # ctl bpf filter: ps-poll, rts, cts, ack, cf-end, cf-end-ack
        scapyconf.iface = self.interface
        # self.log.debug(scapyconf.ifaces)
        try:
            self.l2socket = scapyconf.L2socket(iface=self.interface)
        except OSError as error:
            if "No such device" in error.strerror:
                self.log.warning(
                    "Sniffer: No such device (%s) ... exiting ...", self.interface
                )
                sys.exit(signal.SIGTERM)
        self.log.debug(self.l2socket.outs)

        self.received_frame_cb = self.received_frame
        self.dot11_probe_request_cb = self.probe_response
        self.dot11_assoc_request_cb = self.assoc_req
        self.dot11_auth_cb = self.auth
        with lock:
            probe_resp_ies = _Utils.build_fake_frame_ies(self.config)
            self.mac = _Utils.get_mac(self.interface)
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

        sniff(
            iface=self.interface,
            prn=self.received_frame_cb,
            store=0,
            filter=self.bpf_filter,
        )

    def received_frame(self, packet) -> None:
        """Handle incoming packets for profiling"""
        if packet.subtype == DOT11_SUBTYPE_AUTH_REQ:  # auth
            if packet.addr1 == self.mac:  # if we are the receiver
                self.dot11_auth_cb(packet.addr2)
        elif packet.subtype == DOT11_SUBTYPE_PROBE_REQ:
            ssid = packet[Dot11Elt].info
            # self.log.debug("probe req for %s by MAC %s", ssid, packet.addr)
            if ssid == self.ssid or packet[Dot11Elt].len == 0:
                self.dot11_probe_request_cb(packet)
        elif (
            packet.subtype == DOT11_SUBTYPE_ASSOC_REQ
            or packet.subtype == DOT11_SUBTYPE_REASSOC_REQ
        ):
            if packet.addr1 == self.mac:  # if we are the receiver
                self.dot11_assoc_request_cb(packet)
            if self.listen_only:
                self.dot11_assoc_request_cb(packet)

    def probe_response(self, probe_request) -> None:
        """Send probe resp to assist with profiler discovery"""
        frame = self.probe_response_frame
        with self.sequence_number.get_lock():
            frame.sequence_number = _Utils.next_sequence_number(self.sequence_number)
        frame[Dot11].addr1 = probe_request.addr2
        try:
            self.l2socket.send(frame)
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if event in error.strerror:
                    self.log.exception("exiting...")
                    sys.exit(signal.SIGTERM)
        # self.log.debug("sent probe resp to %s", probe_request.addr2)

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

        # self.log.debug("sending authentication (0x0B) to %s", receiver)

        try:
            self.l2socket.send(frame)
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if event in error.strerror:
                    self.log.info("exiting...")
                    sys.exit(signal.SIGTERM)
