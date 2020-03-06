# Validation by OTA PCAP

- if using an Aruba AP to do a packet capture, make sure you use format type 3* or format type 5.
- type 3 is pcap+radio header and has a caveat:
    + Wireshark (version 3.0.3 - .7 tested) will incorrectly calculate FCS when signal = 100%.
    + so, move AP away from client so signal is < 100%. FCS should be calculated correctly.
- type 5 is peek with 11n/11ac header
- remote AP caps from Aruba require format type 5 (peek with 11n/11ac header), or format type 3 (pcap+radio header) if the signal is < 100%. otherwise wireshark may show malformed incorrectly.