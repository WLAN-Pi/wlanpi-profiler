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
profiler2.fakeap
~~~~~~~~~~~~~~~~

fake ap code handling beaconing and sniffing for the profiler
"""

# standard library imports
import inspect
import logging
import os
import sys
from time import sleep, time

# third party imports

try:
    from scapy.all import (
        Dot11,
        Dot11Auth,
        Dot11Beacon,
        Dot11Elt,
        Dot11ProbeResp,
        RadioTap,
    )
    from scapy.all import conf as scapyconf
    from scapy.all import sniff
except ModuleNotFoundError as error:
    if error.name == "scapy":
        print(
            "required module scapy not found. try installing scapy with `python -m pip install --pre scapy[basic]`."
        )
        sys.exit(-1)


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
from .helpers import build_fake_frame_ies, get_mac, next_sequence_number


class TxBeacons(object):
    """ Handle Tx of fake AP frames """

    def __init__(self, config, boot_time, lock, sequence_number):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.debug("beacon pid: %s; parent pid: %s", os.getpid(), os.getppid())
        self.boot_time = boot_time
        self.config = config
        self.sequence_number = sequence_number
        self.ssid = config.get("GENERAL").get("ssid")
        self.interface = config.get("GENERAL").get("interface")
        self.channel = int(config.get("GENERAL").get("channel"))
        scapyconf.iface = self.interface
        self.l2socket = scapyconf.L2socket(iface=self.interface)
        self.log.debug(self.l2socket.outs)
        self.beacon_interval = 0.102_400

        with lock:
            self.mac = get_mac(self.interface)
            dot11 = Dot11(
                type=DOT11_TYPE_MANAGEMENT,
                subtype=DOT11_SUBTYPE_BEACON,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self.mac,
                addr3=self.mac,
            )
            dot11beacon = Dot11Beacon(cap=0x1111)
            beacon_frame_ies = build_fake_frame_ies(self.config)
            self.beacon_frame = RadioTap() / dot11 / dot11beacon / beacon_frame_ies

        # self.log.debug(f"origin beacon hexdump {hexdump(self.beacon_frame)}")
        self.log.info("starting beacon transmissions")
        self.every(self.beacon_interval, self.beacon)

    def every(self, interval, task):
        """ Attempt to address beacon drift """
        start_time = time()
        while True:
            task()
            sleep(interval - ((time() - start_time) % interval))

    def beacon(self):
        """ Update and Tx Beacon Frame """
        frame = self.beacon_frame
        with self.sequence_number.get_lock():
            frame.sequence_number = next_sequence_number(self.sequence_number)

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
            print(f"{error}; exiting...")
            sys.exit(-1)


class Sniffer(object):
    """ Handle sniffing probes and association requests """

    def __init__(self, config, boot_time, lock, sequence_number, queue):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.log.debug("sniffer %s; parent pid: %s", os.getpid(), os.getppid())

        self.queue = queue
        self.boot_time = boot_time
        self.config = config
        self.sequence_number = sequence_number
        self.ssid = config.get("GENERAL").get("ssid")
        self.interface = config.get("GENERAL").get("interface")
        self.channel = int(config.get("GENERAL").get("channel"))
        self.assoc_reqs = {}

        self.bpf_filter = "type mgt subtype probe-req or type mgt subtype auth or type mgt subtype assoc-req or type mgt subtype reassoc-req"
        # mgt bpf filter: assoc-req, assoc-resp, reassoc-req, reassoc-resp, probe-req, probe-resp, beacon, atim, disassoc, auth, deauth
        # ctl bpf filter: ps-poll, rts, cts, ack, cf-end, cf-end-ack
        scapyconf.iface = self.interface
        self.l2socket = scapyconf.L2socket(iface=self.interface)
        self.log.debug(self.l2socket.outs)

        self.received_frame_cb = self.received_frame
        self.dot11_probe_request_cb = self.probe_response
        self.dot11_assoc_request_cb = self.assoc_req
        self.dot11_auth_cb = self.auth
        with lock:
            probe_resp_ies = build_fake_frame_ies(self.config)
            self.mac = get_mac(self.interface)
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

    def received_frame(self, packet):
        """ Handle incoming packets for profiling """
        if packet.subtype == DOT11_SUBTYPE_AUTH_REQ:  # auth
            if packet.addr1 == self.mac:  # if we are the receiver
                self.dot11_auth_cb(packet.addr2)
        elif packet.subtype == DOT11_SUBTYPE_PROBE_REQ:
            ssid = packet[Dot11Elt].info.decode()
            # self.log.debug("probe req for %s by MAC %s", ssid, packet.addr)
            if ssid == self.ssid or packet[Dot11Elt].len == 0:
                self.dot11_probe_request_cb(packet)
        elif (
            packet.subtype == DOT11_SUBTYPE_ASSOC_REQ
            or packet.subtype == DOT11_SUBTYPE_REASSOC_REQ
        ):
            if packet.addr1 == self.mac:  # if we are the receiver
                self.dot11_assoc_request_cb(packet)

    def probe_response(self, probe_request):
        """ Send probe resp to assist with profiler discovery """
        frame = self.probe_response_frame
        with self.sequence_number.get_lock():
            frame.sequence_number = next_sequence_number(self.sequence_number)
        frame[Dot11].addr1 = probe_request.addr2
        self.l2socket.send(frame)
        # self.log.debug("sent probe resp to %s", probe_request.addr2)

    def assoc_req(self, frame):
        """ Put association request on queue for the Profiler """
        # if frame.addr2 in self.assoc_reqs.keys():
        #    self.log.info(
        #        "ignoring already seen assoc req from client mac %s", frame.addr2
        #    )
        # else:
        self.assoc_reqs[frame.addr2] = frame
        self.log.debug("adding assoc req from %s to queue", frame.addr2)
        self.queue.put(frame)

    def auth(self, receiver):
        """ Send authentication frame to get the station to prompt an assoc request """
        frame = self.auth_frame
        frame[Dot11].addr1 = receiver
        with self.sequence_number.get_lock():
            frame.sequence_number = next_sequence_number(self.sequence_number) - 1

        # self.log.debug("sending authentication (0x0B) to %s", receiver)
        self.l2socket.send(frame)
