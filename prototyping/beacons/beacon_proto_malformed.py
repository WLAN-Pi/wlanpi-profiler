#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
nic prep:

sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw wlan0 set channel 100
"""

from scapy.all import Dot11, Dot11FCS, Dot11Beacon, Dot11Elt, RadioTap, hexdump, sendp

interface = "wlan0"
broadcast = "ff:ff:ff:ff:ff:ff"
source = "40:a5:ef:46:4d:f2"
ssid = "beacon test"

header_fcs = Dot11FCS(
    type=0, subtype=8, addr1=broadcast, addr2=source, addr3=source
) / Dot11Beacon(cap="ESS", timestamp=1)
header = Dot11(
    type=0, subtype=8, addr1=broadcast, addr2=source, addr3=source
) / Dot11Beacon(cap="ESS", timestamp=1)


def ies(name):
    return (
        Dot11Elt(ID="SSID", info=bytes(name, "utf-8"))
        / Dot11Elt(ID="Rates", info=bytes([140, 18, 152, 36, 176, 72, 96, 108]))
        / Dot11Elt(ID="DSset", info=bytes([60]))
        / Dot11Elt(ID="TIM", info=b"\x00\x01\x00\x00")
    )


frame_fcs = RadioTap() / header_fcs / ies("Dot11FCS header SSID")  # malformed frame
frame = RadioTap() / header / ies("Dot11 header SSID")  # good frame

hexdump(frame_fcs)  # malformed frame
hexdump(frame)  # good frame

sendp(frame_fcs, iface=interface)  # malformed frame
sendp(frame, iface=interface)  # good frame
