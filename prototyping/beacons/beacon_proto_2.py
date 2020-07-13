#!/usr/bin/python3
# -*- coding: utf-8 -*-

""""
nic prep:

sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw wlan0 set channel 100
"""

from time import sleep, time

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, conf, hexdump  # , sendp

interface = "wlan0"
dest = "ff:ff:ff:ff:ff:ff"
source = "40:a5:ef:46:4d:f2"

conf.use_pcap = False  # True = libpcap instead of raw sockets
conf.iface = interface
l2socket = conf.L2socket(iface=interface)
l2socket.outs


def ssid(name):
    return bytes(str(name), "utf-8")


dot11_header = Dot11(type=0, subtype=8, addr1=dest, addr2=source, addr3=source)
beacon_ie = Dot11Beacon(cap=0x1111)
rates_ie = Dot11Elt(ID="Rates", info=bytes([140, 18, 152, 36, 176, 72, 96, 108]))


def build(name):
    header = Dot11(type=0, subtype=8, addr1=dest, addr2=source, addr3=source)
    data = (
        Dot11Beacon(cap=0x1111)
        / Dot11Elt(ID="SSID", info=ssid(name))
        / Dot11Elt(ID="Rates", info=bytes([140, 18, 152, 36, 176, 72, 96, 108]))
    )
    return RadioTap() / header / data


hexdump(build("something else"))

interval = 0.102_400
delay = interval
start = time()
while True:
    sleep(delay)
    build_and_send_time = time()
    l2socket.send(build("something else"))
    delay = interval - ((time() - start) % interval)
    f"beaconed={time()}, time_to_build_and_send={time() - build_and_send_time}, delay_before_next_beacon={delay}, interval={interval}"
