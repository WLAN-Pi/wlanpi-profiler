from scapy.all import rdpcap, sendp

cap = rdpcap("mobile-he-beacon-1.pcap")
cap
f = cap[0]

# optionally you could Tx the frame you just read like:
sendp(f)
