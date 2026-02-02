# -*- coding: utf-8 -*-

from profiler.interface import Interface


class TestInterface:
    def test_parsing_iw_dev_wlan0_info(self):
        iw_dev_wlan0_info = """
        Interface wlan0
        ifindex 5
        wdev 0x1
        addr 70:cd:0d:bf:1f:08
        type managed
        wiphy 0
        txpower 0.00 dBm
        multicast TXQ:
                qsz-byt qsz-pkt flows   drops   marks   overlmt hashcol tx-bytes        tx-packets
                0       0       0       0       0       0       0       0               0
        """

        iw_dev_wlan2_info = """
        Interface wlan2
        ifindex 7
        wdev 0x200000001
        addr 8c:88:2b:00:26:36
        type managed
        wiphy 2
        txpower 22.00 dBm
        multicast TXQ:
                qsz-byt qsz-pkt flows   drops   marks   overlmt hashcol tx-bytes        tx-packets
                0       0       0       0       0       0       0       0               0
        """

        freq = Interface.get_frequency(iw_dev_wlan0_info, "wlan0")
        assert freq == None
        ch = Interface.get_channel(iw_dev_wlan0_info, "wlan0")
        assert ch == None

    def test_parsing_iw_dev_mon0_info(self):
        iw_dev_mon0_info = """
        Interface mon0
        ifindex 24
        wdev 0xd
        addr 70:cd:0d:bf:1f:08
        type monitor
        wiphy 0
        channel 36 (5180 MHz), width: 20 MHz, center1: 5180 MHz
        txpower 0.00 dBm
        """

        freq = Interface.get_frequency(iw_dev_mon0_info, "mon0")
        assert freq == 5180
        ch = Interface.get_channel(iw_dev_mon0_info, "mon0")
        assert ch == 36

    def test_parsing_iw_dev_6e_mon0_info(self):
        iw_dev_6e_mon0_info = """
        Interface mon0
        ifindex 25
        wdev 0xe
        addr 70:cd:0d:bf:1f:08
        type monitor
        wiphy 0
        channel 69 (6295 MHz), width: 20 MHz, center1: 6295 MHz
        txpower 0.00 dBm
        """

        freq = Interface.get_frequency(iw_dev_6e_mon0_info, "mon0")
        assert freq == 6295
        ch = Interface.get_channel(iw_dev_6e_mon0_info, "mon0")
        assert ch == 69

    def test_get_channels_status(self):
        iw_phy_ax210_channels = """Band 1:
                * 2412 MHz [1] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40+
                * 2417 MHz [2] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40+
                * 2422 MHz [3] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40+
                * 2427 MHz [4] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40+
                * 2432 MHz [5] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+
                * 2437 MHz [6] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+
                * 2442 MHz [7] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+
                * 2447 MHz [8] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+
                * 2452 MHz [9] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+
                * 2457 MHz [10] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40-
                * 2462 MHz [11] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40-
                * 2467 MHz [12] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40-
                * 2472 MHz [13] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40-
                * 2484 MHz [14] (disabled)
        Band 2:
                * 5180 MHz [36] 
                Maximum TX power: 22.0 dBm
                No IR
                Channel widths: 20MHz HT40+ VHT80 VHT160
                * 5200 MHz [40] 
                Maximum TX power: 22.0 dBm
                No IR
                Channel widths: 20MHz HT40- VHT80 VHT160
                * 5220 MHz [44] 
                Maximum TX power: 22.0 dBm
                No IR
                Channel widths: 20MHz HT40+ VHT80 VHT160
                * 5240 MHz [48] 
                Maximum TX power: 22.0 dBm
                No IR
                Channel widths: 20MHz HT40- VHT80 VHT160
                * 5260 MHz [52] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40+ VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5280 MHz [56] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40- VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5300 MHz [60] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40+ VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5320 MHz [64] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40- VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5340 MHz [68] (disabled)
                * 5360 MHz [72] (disabled)
                * 5380 MHz [76] (disabled)
                * 5400 MHz [80] (disabled)
                * 5420 MHz [84] (disabled)
                * 5440 MHz [88] (disabled)
                * 5460 MHz [92] (disabled)
                * 5480 MHz [96] (disabled)
                * 5500 MHz [100] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40+ VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5520 MHz [104] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40- VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5540 MHz [108] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40+ VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5560 MHz [112] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40- VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5580 MHz [116] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40+ VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5600 MHz [120] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40- VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5620 MHz [124] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40+ VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5640 MHz [128] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40- VHT80 VHT160
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5660 MHz [132] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40+ VHT80
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5680 MHz [136] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40- VHT80
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5700 MHz [140] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40+ VHT80
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5720 MHz [144] 
                Maximum TX power: 22.0 dBm
                No IR
                Radar detection
                Channel widths: 20MHz HT40- VHT80
                DFS state: usable (for 934 sec)
                DFS CAC time: 60000 ms
                * 5745 MHz [149] 
                Maximum TX power: 22.0 dBm
                No IR
                Channel widths: 20MHz HT40+ VHT80
                * 5765 MHz [153] 
                Maximum TX power: 22.0 dBm
                No IR
                Channel widths: 20MHz HT40- VHT80
                * 5785 MHz [157] 
                Maximum TX power: 22.0 dBm
                No IR
                Channel widths: 20MHz HT40+ VHT80
                * 5805 MHz [161] 
                Maximum TX power: 22.0 dBm
                No IR
                Channel widths: 20MHz HT40- VHT80
                * 5825 MHz [165] 
                Maximum TX power: 22.0 dBm
                No IR
                Channel widths: 20MHz
                * 5845 MHz [169] (disabled)
                * 5865 MHz [173] (disabled)
                * 5885 MHz [177] (disabled)
                * 5905 MHz [181] (disabled)
        Band 4:
                * 5955 MHz [1] (disabled)
                * 5975 MHz [5] (disabled)
                * 5995 MHz [9] (disabled)
                * 6015 MHz [13] (disabled)
                * 6035 MHz [17] (disabled)
                * 6055 MHz [21] (disabled)
                * 6075 MHz [25] (disabled)
                * 6095 MHz [29] (disabled)
                * 6115 MHz [33] (disabled)
                * 6135 MHz [37] (disabled)
                * 6155 MHz [41] (disabled)
                * 6175 MHz [45] (disabled)
                * 6195 MHz [49] (disabled)
                * 6215 MHz [53] (disabled)
                * 6235 MHz [57] (disabled)
                * 6255 MHz [61] (disabled)
                * 6275 MHz [65] (disabled)
                * 6295 MHz [69] (disabled)
                * 6315 MHz [73] (disabled)
                * 6335 MHz [77] (disabled)
                * 6355 MHz [81] (disabled)
                * 6375 MHz [85] (disabled)
                * 6395 MHz [89] (disabled)
                * 6415 MHz [93] (disabled)
                * 6435 MHz [97] (disabled)
                * 6455 MHz [101] (disabled)
                * 6475 MHz [105] (disabled)
                * 6495 MHz [109] (disabled)
                * 6515 MHz [113] (disabled)
                * 6535 MHz [117] (disabled)
                * 6555 MHz [121] (disabled)
                * 6575 MHz [125] (disabled)
                * 6595 MHz [129] (disabled)
                * 6615 MHz [133] (disabled)
                * 6635 MHz [137] (disabled)
                * 6655 MHz [141] (disabled)
                * 6675 MHz [145] (disabled)
                * 6695 MHz [149] (disabled)
                * 6715 MHz [153] (disabled)
                * 6735 MHz [157] (disabled)
                * 6755 MHz [161] (disabled)
                * 6775 MHz [165] (disabled)
                * 6795 MHz [169] (disabled)
                * 6815 MHz [173] (disabled)
                * 6835 MHz [177] (disabled)
                * 6855 MHz [181] (disabled)
                * 6875 MHz [185] (disabled)
                * 6895 MHz [189] (disabled)
                * 6915 MHz [193] (disabled)
                * 6935 MHz [197] (disabled)
                * 6955 MHz [201] (disabled)
                * 6975 MHz [205] (disabled)
                * 6995 MHz [209] (disabled)
                * 7015 MHz [213] (disabled)
                * 7035 MHz [217] (disabled)
                * 7055 MHz [221] (disabled)
                * 7075 MHz [225] (disabled)
                * 7095 MHz [229] (disabled)
                * 7115 MHz [233] (disabled)
        """

        iw_phy_mt76x2u_channels = """Band 1:
                * 2412 MHz [1] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40+
                * 2417 MHz [2] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40+
                * 2422 MHz [3] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40+
                * 2427 MHz [4] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40+
                * 2432 MHz [5] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40- HT40+
                * 2437 MHz [6] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40- HT40+
                * 2442 MHz [7] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40- HT40+
                * 2447 MHz [8] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40-
                * 2452 MHz [9] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40-
                * 2457 MHz [10] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40-
                * 2462 MHz [11] 
                Maximum TX power: 21.0 dBm
                Channel widths: 20MHz HT40-
                * 2467 MHz [12] (disabled)
                * 2472 MHz [13] (disabled)
                * 2484 MHz [14] (disabled)
        Band 2:
                * 5180 MHz [36] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40+ VHT80
                * 5200 MHz [40] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+ VHT80
                * 5220 MHz [44] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+ VHT80
                * 5240 MHz [48] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+ VHT80
                * 5260 MHz [52] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5280 MHz [56] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5300 MHz [60] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5320 MHz [64] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5500 MHz [100] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5520 MHz [104] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5540 MHz [108] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5560 MHz [112] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5580 MHz [116] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5600 MHz [120] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5620 MHz [124] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5640 MHz [128] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5660 MHz [132] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5680 MHz [136] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5700 MHz [140] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- HT40+ VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5720 MHz [144] 
                Maximum TX power: 22.0 dBm
                Radar detection
                Channel widths: 20MHz HT40- VHT80
                DFS state: usable (for 8743 sec)
                DFS CAC time: 60000 ms
                * 5745 MHz [149] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40+ VHT80
                * 5765 MHz [153] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+ VHT80
                * 5785 MHz [157] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+ VHT80
                * 5805 MHz [161] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- HT40+ VHT80
                * 5825 MHz [165] 
                Maximum TX power: 22.0 dBm
                Channel widths: 20MHz HT40- VHT80
                * 5845 MHz [169] (disabled)
                * 5865 MHz [173] (disabled)
        """

        channels = Interface.get_channels_status(iw_phy_ax210_channels)
        assert len(channels) == 3
        for _band, channels in channels.items():
            for channel in channels:
                if channel.freq == "6295":
                    assert True
                    assert channel.ch == "69"

        channels = Interface.get_channels_status(iw_phy_mt76x2u_channels)
        assert len(channels) == 2
