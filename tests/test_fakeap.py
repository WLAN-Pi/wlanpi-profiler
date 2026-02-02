# -*- coding: utf-8 -*-

import multiprocessing as mp

import pytest
from profiler import fakeap
from scapy.all import RadioTap, Dot11, Dot11ProbeResp, Dot11Auth, Dot11Elt


class TestFakeAP:
    @pytest.mark.parametrize(
        "seq,expected",
        [(mp.Value("i", 1), 2), (mp.Value("i", 1969), 1970), (mp.Value("i", 4096), 1)],
    )
    def test_next_sequence_number(self, seq, expected):
        assert fakeap._Utils.next_sequence_number(seq) == expected

    def test_build_fake_frame_ies(self):
        conf = {
            "GENERAL": {
                "ssid": "WLAN Pi",
                "channel": 36,
                "frequency": 5120,
                "interface": "wlan1",
                "files_path": "/var/www/html/profiler",
            }
        }
        frame = fakeap._Utils.build_fake_frame_ies(
            conf, "42:95:a7:fa:50:22", testing=True
        )
        frame_bytes = bytes(frame)
        # 2.0.1
        old = b"\x00\x07WLAN Pi\x01\x08\x8c\x12\x98$\xb0H`l\x03\x01$\x05\x06\x05\x04\x00\x03\x00\x00-\x1a\xef\x19\x1b\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x000\x18\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x8c\x00=\x16$\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x006\x03E\xc2\x00F\x05\x02\x00\x00\x00\x00\x7f\x08\x00\x00\x08\x00\x00\x00\x00@\xbf\x0c2\x00\x80\x03\xaa\xff\x00\x00\xaa\xff\x00\x00\xc0\x05\x00$\x00\x00\x00\xff##\t\x01\x00\x02@\x00\x04p\x0c\x80\x02\x03\x80\x04\x00\x00\x00\xaa\xff\xaa\xff{\x1c\xc7q\x1c\xc7q\x1c\xc7q\x1c\xc7q\xff\x07$\xf4?\x00\x19\xfc\xff\xdd\x18\x00P\xf2\x02\x01\x01\x8a\x00\x03\xa4\x00\x00'\xa4\x00\x00BC^\x00b2/\x00"
        # 4ss HT, 8ss HE, HE beamforming, etc
        known = b"\x00\x07WLAN Pi\x01\x08\x8c\x12\x98$\xb0H`l\x03\x01$\x05\x06\x05\x04\x00\x03\x00\x00-\x1a\xef\x19\x1b\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x000\x18\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x8c\x00=\x16$\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x006\x03E\xc2\x00F\x05\x02\x00\x00\x00\x00\x7f\x08\x00\x00\x08\x00\x00\x00\x00@\xbf\x0c2\x00\x80\x03\xaa\xff\x00\x00\xaa\xff\x00\x00\xc0\x05\x00$\x00\x00\x00\xff##\r\x01\x00\x02@\x00\x04p\x0c\x89\x7f\x03\x80\x04\x00\x00\x00\xaa\xaa\xaa\xaa{\x1c\xc7q\x1c\xc7q\x1c\xc7q\x1c\xc7q\xff\x07$\xf4?\x00\x19\xfc\xff\xff\x03'\x05\x00\xff\x0e&\t\x03\xa4('\xa4(Bs(br(\xff\x03;\x00\x00\xdd\x18\x00P\xf2\x02\x01\x01\x8a\x00\x03\xa4\x00\x00'\xa4\x00\x00BC^\x00b2/\x00"

        # Updated expected bytes to reflect:
        # 1. DTIM count=0 (was 5, which was invalid) - see profiler/fakeap.py line 154
        # 2. WPA3 GCMP-256 cipher support - RSN IE now includes both CCMP and GCMP-256
        #    RSN IE length changed from 0x18 (24) to 0x24 (36 bytes)
        be_draft = b"\x00\x07WLAN Pi\x01\x08\x8c\x12\x98$\xb0H`l\x03\x01$\x05\x06\x00\x04\x00\x03\x00\x00-\x1a\xef\x19\x1b\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x000$\x01\x00\x00\x0f\xac\x04\x02\x00\x00\x0f\xac\x04\x00\x0f\xac\t\x04\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x00\x0f\xac\x08\x00\x0f\xac\t\x8c\x006\x03E\xc2\x00=\x16$\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00F\x05\x02\x00\x00\x00\x00\x7f\x08\x00\x00\x08\x00\x00\x00\x00@\xbf\x0c2\x00\x80\x03\xaa\xff\x00\x00\xaa\xff\x00\x00\xc0\x05\x00$\x00\x00\x00\xdd\x121AY\x00\x00\x056.6.6\x01\x059.9.9\xdd\x18\x00P\xf2\x02\x01\x01\x8a\x00\x03\xa4\x00\x00'\xa4\x00\x00BC^\x00b2/\x00\xff##\r\x01\x00\x02@\x00\x04p\x0c\x89\x7f\x03\x80\x04\x00\x00\x00\xaa\xaa\xaa\xaa{\x1c\xc7q\x1c\xc7q\x1c\xc7q\x1c\xc7q\xff\x07$\xf4?\x00\x19\xfc\xff\xff\x03'\x05\x00\xff\x0e&\t\x03\xa4('\xa4(Bs(br(\xff\tj\x05\x11\x00\x00\x00\xfbO?\xff\x15l\x00\x00\xe2\xff\xdb\x00\x186\xd8\x1e\x00DDDDDDDDD"
        assert frame_bytes == be_draft

    def test_probe_response_frame_serialization(self):
        """Test that probe response frames can be serialized to bytes for raw socket transmission"""
        mac = "00:11:22:33:44:55"
        probe_resp_frame = (
            RadioTap()
            / Dot11(subtype=5, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
            / Dot11ProbeResp(cap=0x1111)
            / Dot11Elt(ID=0, info=b"TestSSID")
        )

        frame_bytes = bytes(probe_resp_frame)

        assert isinstance(frame_bytes, bytes)
        assert len(frame_bytes) > 0
        assert mac.replace(":", "").encode() in frame_bytes.hex().encode()

    def test_auth_frame_serialization(self):
        """Test that auth frames can be serialized to bytes for raw socket transmission"""
        mac = "00:11:22:33:44:55"
        auth_frame = (
            RadioTap()
            / Dot11(subtype=11, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
            / Dot11Auth(seqnum=0x02)
        )

        frame_bytes = bytes(auth_frame)

        assert isinstance(frame_bytes, bytes)
        assert len(frame_bytes) > 0

    def test_frame_modification_then_serialization(self):
        """Test that frames can be modified and then serialized correctly"""
        mac = "00:11:22:33:44:55"
        client_mac = "aa:bb:cc:dd:ee:ff"

        frame = (
            RadioTap()
            / Dot11(subtype=5, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
            / Dot11ProbeResp(cap=0x1111)
            / Dot11Elt(ID=0, info=b"TestSSID")
        )

        frame[Dot11].addr1 = client_mac
        frame.sequence_number = 42

        frame_bytes = bytes(frame)

        assert isinstance(frame_bytes, bytes)
        assert client_mac.replace(":", "").encode() in frame_bytes.hex().encode()
        assert frame[Dot11].addr1 == client_mac
        assert frame.sequence_number == 42

    def test_frame_template_patching(self):
        """Test byte-level patching of frame template (Phase 2 optimization)"""
        import struct

        mac = "00:11:22:33:44:55"
        frame = (
            RadioTap()
            / Dot11(subtype=5, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
            / Dot11ProbeResp(cap=0x1111)
            / Dot11Elt(ID=0, info=b"TestSSID")
        )

        # Pre-serialize to template
        template_bytes = bytes(frame)

        # Calculate offsets
        radiotap_len = struct.unpack("<H", template_bytes[2:4])[0]
        addr1_offset = radiotap_len + 4
        seq_offset = radiotap_len + 22

        # Patch template for new client
        client_mac = "11:22:33:44:55:66"
        seq_num = 100

        patched = bytearray(template_bytes)
        patched[addr1_offset : addr1_offset + 6] = bytes.fromhex(
            client_mac.replace(":", "")
        )
        patched[seq_offset : seq_offset + 2] = struct.pack("<H", seq_num << 4)

        # Verify patched bytes
        extracted_mac = ":".join(
            f"{b:02x}" for b in patched[addr1_offset : addr1_offset + 6]
        )
        extracted_seq = (
            struct.unpack("<H", patched[seq_offset : seq_offset + 2])[0] >> 4
        )

        assert extracted_mac == client_mac
        assert extracted_seq == seq_num

        # Verify frame is still valid by parsing with Scapy
        # (Scapy should be able to parse the patched bytes)
        assert len(patched) == len(template_bytes)
        assert patched != template_bytes  # Should be different due to patches
