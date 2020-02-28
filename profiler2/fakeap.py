# -*- coding: utf-8 -*-

"""
profiler2.fakeap
~~~~~~~~~~~~~~~~

fake ap code
"""

# standard library imports
import binascii, inspect, logging, os, sys, threading
from signal import SIGINT, signal
from time import gmtime, sleep, time

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

logging.getLogger("scapy").setLevel(2)

from scapy.all import (
    Dot11,
    Dot11AssoReq,
    Dot11Auth,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltRates,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RadioTap,
    get_if_hwaddr,
    get_if_raw_hwaddr,
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

from .helpers import build_fake_frame_ies, prep_interface, get_frequency_bytes


class AnalyzeFrame(object):
    client_assoc_hash = {}

    def __init__(self):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])

    def assoc_req(self, frame, conf):
        if frame.addr2 not in self.client_assoc_hash.keys():
            self.client_assoc_hash[frame.addr2] = frame
            self.log.debug(f"assoc: {self.client_assoc_hash.keys()}")
            self.analyze_assoc(frame, conf)
        else:
            self.log.debug(f"{frame.addr2} was already seen")

    def analyze_assoc(self, frame, conf):
        self.log.debug(
            f"addr1 (TA): {frame.addr1} addr2 (RA): {frame.addr2} addr3 (SA): {frame.addr3} addr4 (DA): {frame.addr4}"
        )

        print("hexdump of frame:\n")
        hexdump(frame)

        # if _pyx_presence:
        #    _thread = threading.Thread(
        #        target=self.graphical_dump(frame, conf["reporting"]["root"]), args=("Graphical Dump",)
        #    )
        #    _thread.start()

    def graphical_dump(self, frame, out_path):
        # this will slow things down quite a bit on SBCs like the NanoPi Neo2
        # c = frame.canvas_dump()
        # c.writePDFfile(os.path.join(out_path, f"{frame.addr2}.assoc.{int(time())}"))
        frame.pdfdump(
            os.path.join(out_path, f"{frame.addr2}.assoc.{int(time())}.pdf"),
            layer_shift=1,
        )


class FakeAP(object):
    class Sniffer(object):
        # init is created in the main thread.
        def __init__(self, ap):
            self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
            self.log.info(f"PyX presence? {_pyx_presence}")
            self.ap = ap
            self.received_frame_cb = self.received_frame
            self.dot11_probe_request_cb = self.probe_response
            self.dot11_assoc_request_cb = self.assoc_req
            self.dot11_auth_cb = self.auth

            probe_resp_ies = build_fake_frame_ies(
                self.ap.ssid, self.ap.channel, self.ap.args.dot11r
            )
            self.probe_response_frame = (
                self.ap.get_radiotap_header()
                / Dot11(
                    subtype=DOT11_SUBTYPE_PROBE_RESP,
                    addr2=self.ap.mac,
                    addr3=self.ap.mac,
                )
                / Dot11ProbeResp(cap=0x1111)
                / probe_resp_ies
            )
            self.auth_frame = (
                self.ap.get_radiotap_header()
                / Dot11(
                    subtype=DOT11_SUBTYPE_AUTH_REQ, addr2=self.ap.mac, addr3=self.ap.mac
                )
                / Dot11Auth(seqnum=0x02)
            )

        def received_frame(self, packet):
            try:
                # if frame.name != "Raw":
                # self.log.debug(frame.layers)
                # self.log.debug(frame.answers)
                # self.log.debug(frame.packetfields)
                # self.log.debug(frame.fields)
                # self.log.debug(frame.fields_desc)
                # self.log.debug(frame.fieldtype)
                # self.log.debug(frame.firstlayer)
                # self.log.debug(frame.name)

                if packet.type == DOT11_TYPE_MANAGEMENT:
                    if packet.subtype == DOT11_SUBTYPE_AUTH_REQ:  # auth
                        if packet.addr1 == self.ap.mac:  # if we are the receiver
                            self.dot11_auth_cb(packet.addr2)
                    elif (
                        packet.subtype == DOT11_SUBTYPE_ASSOC_REQ
                        or packet.subtype == DOT11_SUBTYPE_REASSOC_REQ
                    ):
                        if packet.addr1 == self.ap.mac:  # if we are the receiver
                            self.dot11_assoc_request_cb(packet)
                    elif packet.subtype == DOT11_SUBTYPE_PROBE_REQ:
                        if Dot11Elt in packet:
                            ssid = packet[Dot11Elt].info
                            #:self.log.debug(f"probe req for {ssid} by MAC {packet.addr2}")
                            if ssid == self.ap.ssid or packet[Dot11Elt].len == 0:
                                self.dot11_probe_request_cb(packet)
            except AttributeError as error:
                self.log.exception(error)
            except Exception as error:
                self.log.exception(error)

        def probe_response(self, frame):
            self.probe_response_frame.sequence_number = self.ap.next_sequence_number()
            self.probe_response_frame[Dot11].addr1 = frame.addr2
            # self.log.debug(f"sending probe resp to {frame.addr2}")
            self.ap.l2socket2.send(self.probe_response_frame)

        def assoc_req(self, frame):
            AnalyzeFrame().assoc_req(frame, self.ap.config)

        def auth(self, receiver):
            """ required to get the station to send an assoc request """
            self.auth_frame[Dot11].addr1 = receiver
            self.auth_frame.sequence_number = self.ap.next_sequence_number() - 1
            # self.log.debug(f"sending authentication (0x0B) to {receiver}")
            self.ap.l2socket2.send(self.auth_frame)

        # def probe_response(self, client_frame):
        #    dot11 = Dot11(
        #        subtype=DOT11_SUBTYPE_PROBE_RESP,
        #        addr1=client_frame.addr2,
        #        addr2=self.ap.mac,
        #        addr3=self.ap.mac
        #    )
        #
        #    frame = (
        #        RadioTap() / dot11 / Dot11ProbeResp(cap=0x1111) / self.probe_resp_ies
        #    )
        #
        #    self.ap.l2socket1.send(frame)

        # self.log.debug(
        #    f"{client_frame.addr1} {client_frame.addr2} {client_frame.addr3} {client_frame.addr4}"
        # )
        # self.log.debug(
        #    f"probe resp to request from {client_frame.addr2}, {client_frame.dBm_AntSignal})"
        # )

        # if client_frame.addr2 not in self.ap.client_probe_hash.keys():
        #    self.ap.client_probe_hash[client_frame.addr2] = client_frame
        #    self.log.debug(
        #        f"{len(self.ap.client_probe_hash.keys())} unique client probes seen"
        #    )

    class TxBeacons(threading.Thread):
        # init is created in the main thread.
        def __init__(self, ap):

            self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
            threading.Thread.__init__(self)
            threading.Thread.name = "TxBeacons"
            self.ap = ap
            self.setDaemon(True)
            self.boot_time = time()
            dot11 = Dot11(
                type=DOT11_TYPE_MANAGEMENT,
                subtype=DOT11_SUBTYPE_BEACON,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self.ap.mac,
                addr3=self.ap.mac,
            )
            dot11beacon = Dot11Beacon(beacon_interval=1, cap=0x1111)
            beacon_frame_ies = build_fake_frame_ies(
                self.ap.ssid, self.ap.channel, self.ap.args.dot11r
            )
            self.beacon_frame = (
                self.ap.get_radiotap_header() / dot11 / dot11beacon / beacon_frame_ies
            )
            # self.ap.get_radiotap_header() / dot11 / dot11beacon / beacon_frame_ies
            self.run_once = True

        def run(self):
            self.every(self.ap.beacon_interval, self.beacon)

        def every(self, interval, task):
            start_time = time()
            while True:
                task()
                sleep(interval - ((time() - start_time) % interval))

        def beacon(self):
            self.beacon_frame.sequence_number = self.ap.next_sequence_number()
            self.beacon_frame[Dot11Beacon].timestamp = self.ap.current_timestamp()
            self.ap.l2socket1.send(self.beacon_frame)
            # if self.ap.args.test and self.run_once:
            #    self.writepcap()

        def graphical_dump(self, name):
            # c = self.beacon_frame.canvas_dump()
            # this seems to slow things down quite a bit on SBCs like the NanoPi Neo2
            # c.writePDFfile(f"/var/www/html/profiler/beacon.{int(time())}")
            self.beacon_frame.pdfdump(
                f"/var/www/html/profiler/beacon.{int(time())}.pdf", layer_shift=1
            )

        def writepcap(self):
            log = logging.getLogger(inspect.stack()[0][3])
            _thread = threading.Thread(
                target=self.graphical_dump, args=("Graphical Dump",)
            )
            _thread.start()
            log.info(_thread)
            log.info(self.beacon_frame.summary())
            log.info(self.beacon_frame.show())
            log.info(hexdump(self.beacon_frame))
            from scapy.utils import PcapWriter

            pktdump = PcapWriter(
                f"/var/www/html/profiler/beacon.{int(time())}.pcap",
                append=True,
                sync=True,
            )
            pktdump.write(self.beacon_frame)
            self.run_once = False

    client_probe_hash = {}
    boot_time = time()

    def current_timestamp(self):
        return int(time() - self.boot_time)

    def next_sequence_number(self):
        self.mutex.acquire()
        self.sequence_number = (self.sequence_number + 1) % 4096
        temp = self.sequence_number
        self.mutex.release()
        return temp * 16  # Fragment number -> right 4 bits

    def get_ssid(self):
        if len(self.ssid) > 0:
            return self.ssid

    def get_mac(self):
        try:
            mac = get_if_hwaddr(self.interface)
        except scapy.error.Scapy_Exception:
            mac = ":".join(
                format(x, "02x") for x in get_if_raw_hwaddr(self.interface)[1]
            )
        return mac

    def sigint_handler(self, signal_received, frame):
        log = logging.getLogger(inspect.stack()[0][3])
        log.info("SIGINT or CTRL-C detected... exiting...")
        sys.exit(0)

    def get_radiotap_header(self):
        radiotap_packet = RadioTap(
            present="Flags+Rate+Channel+dBm_AntSignal+Antenna",
            notdecoded=b"\x8c\00"
            + get_frequency_bytes(self.channel)
            + b"\xc0\x00\xc0\x01\x00\x00",
        )
        return radiotap_packet

    def __init__(self, config, args):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.args = args

        self.config = config  # HACKY!

        self.interface = config["fakeap"]["interface"]
        self.ssid = config["fakeap"]["ssid"]
        self.channel = config["fakeap"]["channel"]

        if not prep_interface(self.interface, "monitor", self.channel):
            self.log.error("failed to prep interface")
            sys.exit(-1)

        signal(SIGINT, self.sigint_handler)
        self.beacon_interval = 0.102400
        self.mac = self.get_mac()
        self.sequence_number = 0
        self.mutex = threading.Lock()

        self.bpf_filter = "type mgt subtype probe-req or type mgt subtype auth or type mgt subtype assoc-req or type mgt subtype reassoc-req or type ctl subtype ack"
        # mgt: assoc-req, assoc-resp, reassoc-req, reassoc-resp,probe-req, probe-resp, beacon, atim, disassoc, auth, deauth.
        # ctl: ps-poll, rts, cts, ack, cf-end, cf-end-ack
        # self.bpf_filter = "type mgt"
        scapyconf.iface = self.interface
        self.l2socket1 = scapyconf.L2socket(iface=self.interface)
        self.l2socket2 = scapyconf.L2socket(iface=self.interface)
        self.log.info(self.l2socket1.outs)
        self.log.info(self.l2socket2.outs)

        self.sniffer = self.Sniffer(self)
        self.txbeacons = self.TxBeacons(self)
        # How to use libpcap: scapyconf.use_pcap = True
        # scapyconf.verb = 3
        if self.args.test:
            _file = open(f"/var/www/html/profiler/scapyconf.{int(time())}", "w")
            _file.write(str(scapyconf))
            _file.close()

    def beam_up(self):
        log = logging.getLogger(inspect.stack()[0][3])
        log.debug(f"current PID is {os.getpid()}")
        if not self.args.listen_only:
            log.info("starting beacon tx'r")
            self.txbeacons.start()
        log.info("starting sniffer")
        
        sniffer = threading.Thread(
            target=sniff(
                iface=self.interface,
                prn=self.sniffer.received_frame_cb,
                store=0,
                filter=self.bpf_filter,
            ),
            name="Sniffer",
            args=("Sniffer",),
        )
        sniffer.start()
