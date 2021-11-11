# -*- coding: utf-8 -*-

from profiler.interface import Interface


class TestInterface:
    def test_parse_iw_dev_phys(self):
        multi_interfaces_per_phy = """
        phy#2
                Interface wlan2
                        ifindex 5
                        wdev 0x200000001
                        addr 00:c0:ca:28:2f:ac
                        type monitor
                        channel 36 (5180 MHz), width: 20 MHz, center1: 5180 MHz
                        txpower 20.00 dBm
                        multicast TXQ:
                                qsz-byt qsz-pkt flows   drops   marks   overlmt hashcol tx-bytes    tx-packets
                                0       0       0       0       0       0       0       0           0
        phy#0
                Interface mon0
                        ifindex 44
                        wdev 0x1f
                        addr d8:f8:83:12:24:08
                        type managed
                        txpower 0.00 dBm
                        multicast TXQ:
                                qsz-byt qsz-pkt flows   drops   marks   overlmt hashcol tx-bytes    tx-packets
                                0       0       0       0       0       0       0       0           0
                Interface wlan1
                        ifindex 4
                        wdev 0x1
                        addr d8:f8:83:12:24:07
                        type managed
                        txpower 0.00 dBm
                        multicast TXQ:
                                qsz-byt qsz-pkt flows   drops   marks   overlmt hashcol tx-bytes    tx-packets
                                0       0       0       0       0       0       0       0           0
        phy#1
                Interface wlan0
                        ifindex 3
                        wdev 0x100000001
                        addr dc:a6:32:f2:d2:c8
                        type managed
                        channel 34 (5170 MHz), width: 20 MHz, center1: 5170 MHz
                        txpower 31.00 dBm
        """

        single_interface_per_phy = """
        phy#2
                Interface wlan2
                        ifindex 5
                        wdev 0x200000001
                        addr 00:c0:ca:28:2f:ac
                        type monitor
                        channel 36 (5180 MHz), width: 20 MHz, center1: 5180 MHz
                        txpower 20.00 dBm
                        multicast TXQ:
                                qsz-byt qsz-pkt flows   drops   marks   overlmt hashcol tx-bytes    tx-packets
                                0       0       0       0       0       0       0       0           0
        phy#0
                Interface wlan1
                        ifindex 4
                        wdev 0x1
                        addr d8:f8:83:12:24:07
                        type managed
                        txpower 0.00 dBm
                        multicast TXQ:
                                qsz-byt qsz-pkt flows   drops   marks   overlmt hashcol tx-bytes    tx-packets
                                0       0       0       0       0       0       0       0           0
        phy#1
                Interface wlan0
                        ifindex 3
                        wdev 0x100000001
                        addr dc:a6:32:f2:d2:c8
                        type managed
                        channel 34 (5170 MHz), width: 20 MHz, center1: 5170 MHz
                        txpower 31.00 dBm
        """

        unnamed_interface = """
        phy#5
            Interface wlan1
                ifindex 15
                wdev 0x500000001
                addr 8c:88:2b:05:23:19
                type managed
                txpower 21.00 dBm
                multicast TXQ:
                    qsz-byt	qsz-pkt	flows	drops	marks	overlmt	hashcol	tx-bytes	tx-packets
                    0	0	0	0	0	0	0	0		0
        phy#1
            Unnamed/non-netdev interface
                wdev 0x100000002
                addr de:a6:32:16:12:f1
                type P2P-device
                txpower 31.00 dBm
            Interface wlan0
                ifindex 3
                wdev 0x100000001
                addr dc:a6:32:16:12:f1
                type managed
                channel 34 (5170 MHz), width: 20 MHz, center1: 5170 MHz
                txpower 31.00 dBm
        """
        phys = Interface.build_iw_phy_list(multi_interfaces_per_phy)
        for phy in phys:
            assert len(phys) == 3
            if phy.phy_id == '2':
                assert len(phy.interfaces) == 1
                for iface in phy.interfaces:
                    assert iface.name == 'wlan2'
                    assert iface.ifindex == '5'
                    assert "2f:ac" in iface.addr
            if phy.phy_id == '0':
                assert len(phy.interfaces) == 2
                iface1 = phy.interfaces[0]
                assert 'mon0' in iface1
                iface2 = phy.interfaces[1]
                assert 'wlan1' in iface2
            if phy.phy_id == '1':
                assert len(phy.interfaces) == 1
                assert 'wlan0' in phy.interfaces[0]
        
        phys = Interface.build_iw_phy_list(single_interface_per_phy)
        for phy in phys:
            assert len(phy.interfaces) == 1
            assert 'wlan' in phy.interfaces[0].name

        phys = Interface.build_iw_phy_list(unnamed_interface)
        print(phys)
        for phy in phys:
            assert len(phy.interfaces) == 1
            assert 'wlan' in phy.interfaces[0].name
            if phy.phy_id == '1':
                assert phy.interfaces[0].name == 'wlan0'
                assert phy.interfaces[0].ifindex == '3'
                assert phy.interfaces[0].addr == 'dc:a6:32:16:12:f1'
                assert phy.interfaces[0].type == 'managed'