# -*- coding: utf-8 -*-

import pytest
from scapy.all import rdpcap

from profiler2 import profiler


class TestProfiler:
    @staticmethod
    def get_dot11_elt_dict(frame, p):
        # strip radiotap
        ie_buffer = bytes(frame.payload)

        # strip dot11
        ie_buffer = ie_buffer[24:]

        # strip params
        ie_buffer = ie_buffer[4:]

        # strip fcs
        ie_buffer = ie_buffer[:-4]

        # convert buffer to ie dict
        dot11_elt_dict = p.process_information_elements(ie_buffer)
        return dot11_elt_dict

    @pytest.mark.parametrize(
        "expected,pcap",
        [
            (
                "apple",
                "./tests/pcaps/Apple_MXCU2LLA_PrivateMAC_76-32-e8-00-00-00_5.8GHz-anonymized.pcap",
            ),
            (
                "apple",
                "./tests/pcaps/Apple_MXCU2LLA_RealMAC_04-72-95-00-00-00_5.8GHz-anonymized.pcap",
            ),
            (
                "samsung",
                "./tests/pcaps/SM-G977U_Android10_PhoneMAC_d4-53-83-00-00-00_5.8GHz-anonymized.pcap",
            ),
            (
                "samsung",
                "./tests/pcaps/SM-G977U_Android10_RandomizedMAC_26-a0-e2-00-00-00_5.8GHz-anonymized.pcap",
            ),
        ],
    )
    def test_resolve_oui_manuf(self, expected, pcap):
        p = profiler.Profiler()

        cap = rdpcap(pcap)
        dot11_elt_dict = self.get_dot11_elt_dict(cap[0], p)
        assert dot11_elt_dict is not None
        manuf = p.resolve_oui_manuf(cap[0].addr2, dot11_elt_dict)
        assert expected in manuf.lower()
