# Malformed frames using Dot11 FCS

In this example, I've observed malformed frames from Dot11FCS, while Dot11 looks good.

Dot11FCS is supposed to add the CRC automatically.

Lesson learned. Don't use Dot11FCS in Python3 with Scapy 2.4.3.

```
# card prep

sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw wlan0 set channel 100

# Dot11FCS vs Dot11

from scapy.all import RadioTap, Dot11, Dot11FCS, Dot11Beacon, Dot11Elt, sendp, hexdump

dest = "ff:ff:ff:ff:ff:ff"
source = "40:a5:ef:0c:16:81"
ssid = bytes("DONT MALFORM ME BRO", "utf-8")
frame_a = Dot11FCS(type=0, subtype=8, addr1=dest, addr2=source, addr3=source) / Dot11Beacon(cap="ESS", timestamp=1) / Dot11Elt(ID="SSID", info=ssid) / Dot11Elt(ID="Rates", info=bytes([140, 18, 152, 36, 176, 72, 96, 108]))
frame_b = Dot11(type=0, subtype=8, addr1=dest, addr2=source, addr3=source) / Dot11Beacon(cap="ESS", timestamp=1) / Dot11Elt(ID="SSID", info=ssid) / Dot11Elt(ID="Rates", info=bytes([140, 18, 152, 36, 176, 72, 96, 108]))
sendp(RadioTap() / frame_a, iface="wlan0")
sendp(RadioTap() / frame_b, iface="wlan0")
```

# Testing libpcap vs sockets test

how to perform a libpcap (apt install libpcap-dev) vs sockets test:

```
from scapy.all import RadioTap, Dot11, Dot11FCS, Dot11Beacon, Dot11Elt, sendp, hexdump

interface = "wlan0"
dest = "ff:ff:ff:ff:ff:ff"
source = "40:a5:ef:0c:16:81"

from scapy.all import conf as scapyconf
scapyconf.use_pcap = False # use libpcap instead of raw sockets
scapyconf.iface = interface
l2socket = scapyconf.L2socket(iface=interface)
l2socket.outs

# frame comes across good.
header = Dot11(type=0, subtype=8, addr1=dest, addr2=source, addr3=source)

# dot11fcs frame comes across as malformed!!! 
fcs_header = Dot11FCS(type=0, subtype=8, addr1=dest, addr2=source, addr3=source) 

ssid = bytes("RAW SOCKET", "utf-8")
data = Dot11Beacon(cap="ESS", timestamp=1) / Dot11Elt(ID="SSID", info=ssid) / Dot11Elt(ID="Rates", info=bytes([140, 18, 152, 36, 176, 72, 96, 108]))

frame = RadioTap() / header / data
frame_fcs = RadioTap() / fcs_header / data

hexdump(frame)
hexdump(frame_fcs)

l2socket.send(frame)
l2socket.send(frame_fcs)

sendp(frame)
sendp(frame_fcs)
```

custom radiotap test:

lessons learned:

1. don't make a custom RadioTap header. it doesn't seem to do anything. just pass in RadioTap()
2. don't use Dot11FCS, let scapy do it.
3. don't send your own time stamp, let scapy do it.
4. don't send your own sequence number. let scapy do it.