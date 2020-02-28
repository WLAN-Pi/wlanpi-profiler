# unsure if any of this is worth saving.


def packet_handler(packet):
    """ TODO: DELETE THIS DEMO CODE """
    if packet.type == 0 and packet.subtype == 4:
        print(f"Probe Request from client MAC: {packet.addr2} {packet.dBm_AntSignal}")
    if packet.type == 0 and packet.subtype == 8:
        if packet.addr2 not in fakeap.ap_list:
            fakeap.ap_list.append(packet.addr2)
            print(
                f"Beacon from Access Point MAC: {packet.addr2} with SSID: {packet.info} {packet.dBm_AntSignal}"
            )


def listen(interface):
    """ TODO: DELETE THIS DEMO CODE """
    log = logging.getLogger(inspect.stack()[0][3])
    log.debug("listening...")

    # blocking code
    sniff(iface=interface, prn=fakeap.packet_handler)


def beacon_frame(self, interface, ssid):
    """ TODO: DELETE THIS DEMO CODE """
    dot11 = Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=self.ap.mac,
        addr3=self.ap.mac,
    )
    beacon = Dot11Beacon(beacon_interval=0x0064, cap=0x1111)
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    tim = Dot11Elt(ID="TIM", info="\x05\x04\x00\x03\x00\x00")
    rsn = Dot11Elt(
        ID="RSNinfo",
        info=(
            "\x01\x00"
            "\x00\x0f\xac\x02"
            "\x02\x00"
            "\x00\x0f\xac\x04"
            "\x00\x0f\xac\x02"
            "\x01\x00"
            "\x00\x0f\xac\x02"
            "\x00\x00"
        ),
    )

    frame = RadioTap() / dot11 / beacon / essid / tim / rsn

    frame.SC = self.ap.next_sc()

    frame[Dot11Beacon].timestamp = self.ap.current_timestamp()

    # frame.show()
    # print("Hexdump of frame:\n")
    # hexdump(frame)
    # input("\nPress enter to start\n")

    sendp(frame, iface=self.ap.interface, verbose=False)
    # blocking code
    # sendp(frame, iface=interface, inter=0.100, loop=1)
