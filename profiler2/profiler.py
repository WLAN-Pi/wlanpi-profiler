# -*- coding: utf-8 -*-

"""
profiler2.profiler
~~~~~~~~~~~~~~~~~~

fake ap profiler code
"""

# standard library imports
import binascii, inspect, logging, os, sys, multiprocessing, threading
from time import gmtime, sleep, time
from datetime import timedelta, datetime
from ctypes import c_ulonglong

# third party imports
_pyx_presence = True

try:
    import scapy
    import pyx
except ModuleNotFoundError as error:
    if error.name == "scapy":
        print(
            "required module scapy not found. try installing scapy with `python -m pip install --pre scapy[basic]`."
        )
        sys.exit(-1)
    if error.name == "pyx":
        _pyx_presence = False

# logging.getLogger("scapy").setLevel(logging.DEBUG)

from scapy.all import (
    Dot11,
    Dot11AssoReq,
    Dot11Auth,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltRates,
    Dot11ProbeReq,
    Dot11ProbeResp,
    hexdump,
    conf as scapyconf,
    sendp,
    sniff,
)

# app imports
from .constants import (
    DOT11_SUBTYPE_ASSOC_REQ,
    DOT11_SUBTYPE_REASSOC_REQ,
    DOT11_SUBTYPE_AUTH_REQ,
    DOT11_SUBTYPE_BEACON,
    DOT11_SUBTYPE_PROBE_REQ,
    DOT11_SUBTYPE_PROBE_RESP,
    DOT11_TYPE_MANAGEMENT,
)

from .helpers import (
    convert_timestamp_to_uptime,
    next_sequence_number,
    get_radiotap_header,
    build_fake_frame_ies,
    prep_interface,
    get_mac,
    get_frequency_bytes,
)


class AnalyzeFrame(object):
    client_assoc_hash = {}

    def __init__(self):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])

    def assoc_req(self, frame):
        if frame.addr2 not in self.client_assoc_hash.keys():
            self.client_assoc_hash[frame.addr2] = frame
            self.log.debug(f"assoc: {self.client_assoc_hash.keys()}")
            self.analyze_assoc(frame)
        else:
            self.log.debug(f"{frame.addr2} was already seen")

    def analyze_assoc(self, frame):
        self.log.debug(
            f"addr1 (TA): {frame.addr1} addr2 (RA): {frame.addr2} addr3 (SA): {frame.addr3} addr4 (DA): {frame.addr4}"
        )
        print("hexdump of frame:\n")
        hexdump(frame)


class TxBeacons(object):
    def __init__(
        self, args, boot_time, lock, sequence_number, ssid, interface, channel
    ):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.info(f"scapy version: {scapy.__version__}")
        self.log.info(f"beacons pid: {os.getpid()}")
        self.boot_time = boot_time
        self.args = args
        self.sequence_number = sequence_number
        self.ssid = ssid
        self.interface = interface
        self.channel = channel
        scapyconf.iface = self.interface
        self.l2socket = scapyconf.L2socket(iface=self.interface)
        self.log.info(self.l2socket.outs)
        self.beacon_interval = 0.102400

        with lock:
            self.mac = get_mac(interface)
            dot11 = Dot11(
                type=DOT11_TYPE_MANAGEMENT,
                subtype=DOT11_SUBTYPE_BEACON,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self.mac,
                addr3=self.mac,
            )
            dot11beacon = Dot11Beacon(beacon_interval=1, cap=0x1111)
            beacon_frame_ies = build_fake_frame_ies(
                self.ssid, self.channel, self.args.dot11r
            )
            self.beacon_frame = (
                get_radiotap_header(self.channel)
                / dot11
                / dot11beacon
                / beacon_frame_ies
            )

        # self.log.debug("origin beacon hexdump")
        # self.log.debug(hexdump(self.beacon_frame))
        self.log.info("starting beacon transmissions")
        self.every(self.beacon_interval, self.beacon)

    def every(self, interval, task):
        start_time = time()
        while True:
            task()
            sleep(interval - ((time() - start_time) % interval))

    def beacon(self):
        frame = self.beacon_frame
        with self.sequence_number.get_lock():
            frame.sequence_number = next_sequence_number(self.sequence_number)

        # print(f"frame.sequence_number: {frame.sequence_number}")
        # frame.sequence_number value is updating here, but not updating in pcap for some adapters
        # TODO: investigate. appears to impact MediaTek adapters vs RealTek

        # ts = int((datetime.now().timestamp() - self.boot_time) * 1000000)
        # frame[Dot11Beacon].timestamp = ts

        # self.log.debug(f"frame timestamp: {convert_timestamp_to_uptime(ts)}")
        # scapy is doing something werid with our timestamps.
        # pcap shows wrong timestamp values
        # TODO: investigate (low priority)
        self.l2socket.send(frame)


class Sniffer(object):
    def __init__(
        self, args, boot_time, lock, sequence_number, ssid, interface, channel
    ):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.info(f"sniffer pid: {os.getpid()}")

        self.boot_time = boot_time
        self.args = args
        self.sequence_number = sequence_number
        self.ssid = ssid
        self.interface = interface
        self.channel = channel
        self.associated = []

        self.bpf_filter = "type mgt subtype probe-req or type mgt subtype auth or type mgt subtype assoc-req or type mgt subtype reassoc-req"
        # mgt bpf filter: assoc-req, assoc-resp, reassoc-req, reassoc-resp, probe-req, probe-resp, beacon, atim, disassoc, auth, deauth
        # ctl bpf filter: ps-poll, rts, cts, ack, cf-end, cf-end-ack
        scapyconf.iface = self.interface
        self.l2socket = scapyconf.L2socket(iface=self.interface)
        self.log.info(self.l2socket.outs)

        self.received_frame_cb = self.received_frame
        self.dot11_probe_request_cb = self.probe_response
        self.dot11_assoc_request_cb = self.assoc_req
        self.dot11_auth_cb = self.auth
        with lock:
            probe_resp_ies = build_fake_frame_ies(
                self.ssid, self.channel, self.args.dot11r
            )
            self.mac = get_mac(interface)
            self.probe_response_frame = (
                get_radiotap_header(self.channel)
                / Dot11(
                    subtype=DOT11_SUBTYPE_PROBE_RESP, addr2=self.mac, addr3=self.mac
                )
                / Dot11ProbeResp(cap=0x1111)
                / probe_resp_ies
            )
            self.auth_frame = (
                get_radiotap_header(self.channel)
                / Dot11(subtype=DOT11_SUBTYPE_AUTH_REQ, addr2=self.mac, addr3=self.mac)
                / Dot11Auth(seqnum=0x02)
            )
        self.log.info("starting sniffer")
        sniff(
            iface=self.interface,
            prn=self.received_frame_cb,
            store=0,
            filter=self.bpf_filter,
        )

    def received_frame(self, packet):
        """ handles incoming packets for profiling """
        try:
            if packet.type == DOT11_TYPE_MANAGEMENT:
                if packet.subtype == DOT11_SUBTYPE_AUTH_REQ:  # auth
                    if packet.addr1 == self.mac:  # if we are the receiver
                        self.dot11_auth_cb(packet.addr2)
                elif packet.subtype == DOT11_SUBTYPE_PROBE_REQ:
                    print(packet.fields)
                    print(dir(packet))
                    if Dot11Elt in packet:
                        ssid = packet[Dot11Elt].info
                        # self.log.debug(f"probe req for {ssid} by MAC {packet.addr2}")
                        if ssid == self.ssid or packet[Dot11Elt].len == 0:
                            self.dot11_probe_request_cb(packet)
                elif (
                    packet.subtype == DOT11_SUBTYPE_ASSOC_REQ
                    or packet.subtype == DOT11_SUBTYPE_REASSOC_REQ
                ):
                    if packet.addr1 == self.mac:  # if we are the receiver
                        self.dot11_assoc_request_cb(packet)
        except AttributeError as error:
            self.log.exception(error)
        except Exception as error:
            self.log.exception(error)

    def probe_response(self, probe_request):
        """ send probe resp to assist with profiler discovery """
        frame = self.probe_response_frame
        with self.sequence_number.get_lock():
            frame.sequence_number = next_sequence_number(self.sequence_number)
        frame[Dot11].addr1 = probe_request.addr2

        self.l2socket.send(frame)

    def assoc_req(self, frame):
        if frame.addr2 not in self.associated:
            self.associated.append(frame.addr2)

            self.log.info(f"{frame.addr2} added to associated list {self.associated}")

        # TODO: trigger analysis of association request

    def auth(self, receiver):
        """ required to get the station to send an assoc request """
        frame = self.auth_frame
        frame[Dot11].addr1 = receiver
        with self.sequence_number.get_lock():
            frame.sequence_number = next_sequence_number(self.sequence_number) - 1

        # self.log.debug(f"sending authentication (0x0B) to {receiver}")
        self.l2socket.send(frame)
