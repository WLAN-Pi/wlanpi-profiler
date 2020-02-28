#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
nic prep:

sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitordddddddddddddddddd
sudo ip link set wlan0 up
sudo iw wlan0 set channel 100
"""

from scapy.all import Dot11, Dot11Ack, Dot11Elt, RadioTap, hexdump, sendp

interface = "wlan0"
broadcast = "ff:ff:ff:ff:ff:ff"
source = "40:a5:ef:46:4d:f2"

header = Dot11(type=1, subtype=13, addr1=destination, addr2=source, addr3=source)

frame = RadioTap() / header

hexdump(frame)

sendp(frame, iface=interface)
