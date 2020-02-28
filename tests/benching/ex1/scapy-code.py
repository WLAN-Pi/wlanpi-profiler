from scapy.all import (
    RadioTap,
    Dot11,
    Dot11FCS,
    Dot11Beacon,
    Dot11Elt,
    sendp,
    hexdump,
    conf,
)

channel = 100
interface = "wlan0"
dest = "ff:ff:ff:ff:ff:ff"
source = "40:a5:ef:0c:16:81"

conf.use_pcap = False  # use libpcap instead of raw sockets
conf.iface = interface
l2socket = conf.L2socket(iface=interface)
l2socket.outs


def ssid(name):
    return bytes(str(name), "utf-8")


def build(name):
    dot11_header = Dot11(type=0, subtype=8, addr1=dest, addr2=source, addr3=source)
    beacon = Dot11Beacon(cap=0x1111)
    data = (
        beacon
        / Dot11Elt(ID="SSID", info=ssid(name))
        / Dot11Elt(ID="Rates", info=bytes([140, 18, 152, 36, 176, 72, 96, 108]))
    )
    return RadioTap() / dot11_header / data


hexdump(build("test"))

l2socket.send(build("test"))

interval = 0.102400
delay = 0.1
from time import time, sleep

start = time()
while True:
    sleep(delay)
    l2socket.send(build("test"))
    delay = interval - ((time() - start) % interval)
