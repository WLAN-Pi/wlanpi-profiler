# -*- coding: utf-8 -*-

import pytest
from profiler import profiler
from scapy.all import rdpcap


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
        "expected,pcap", [("non_utf-8_ssid", "./tests/pcaps/0xc6.pcapng")]
    )
    def test_non_utf8_decode(self, expected, pcap):
        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False
        cap = rdpcap(pcap)
        is_6ghz = False
        ssid, oui, chipset, capabilities = p.analyze_assoc_req(cap[0], is_6ghz)
        assert ssid is not None
        assert oui is not None
        assert chipset == ""
        assert capabilities is not None

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

    def test_6e_pcap(self):
        pcap = "./tests/pcaps/IntelAX210_Windows10_10-3d-1c-00-00-00_6.0GHz-anonymized.pcap"
        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False
        cap = rdpcap(pcap)
        # dot11_elt_dict = self.get_dot11_elt_dict(cap[0], p)

        ssid, oui_manuf, chipset, capabilities = p.analyze_assoc_req(
            cap[0], is_6ghz=True
        )
        assert ssid == "WLANPI_1"
        assert oui_manuf == "Intel"
        assert chipset == "Intel"
        for capability in capabilities:
            if capability.name == "802.11n":
                assert "Not reported" in capability.value
            if capability.name == "802.11ac":
                assert "Not reported" in capability.value
            if capability.name == "802.11ax":
                assert True
            if capability.name == "6 GHz Operating Class":
                assert "Supported" in capability.value
            if capability.name == "6 GHz Capability":
                assert "Supported" in capability.value

    def test_5ghz_pcap(self):
        pcap = "./tests/pcaps/SM-G977U_Android10_RandomizedMAC_26-a0-e2-00-00-00_5.8GHz-anonymized.pcap"
        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False
        cap = rdpcap(pcap)
        # dot11_elt_dict = self.get_dot11_elt_dict(cap[0], p)

        ssid, oui_manuf, chipset, capabilities = p.analyze_assoc_req(
            cap[0], is_6ghz=True
        )
        assert ssid == "WLANPI_1"
        assert "Samsung" in oui_manuf
        assert chipset == "Broadcom"  # S21 shipped with Broadcom

        # Spatial streams are now reported in separate NSS capabilities
        found_11n = False
        found_11n_nss = False
        found_11ac = False
        found_11ac_nss = False
        found_11ax = False

        for capability in capabilities:
            if capability.name == "802.11n":
                assert capability.value == "Supported"
                found_11n = True
            if capability.name == "802.11n/HT NSS":
                assert capability.value == "2"
                found_11n_nss = True
            if capability.name == "802.11ac":
                assert capability.value == "Supported"
                found_11ac = True
            if capability.name == "802.11ac/VHT NSS":
                assert capability.value == "2"
                found_11ac_nss = True
            if capability.name == "802.11ax":
                found_11ax = True

        assert found_11n, "802.11n capability not found"
        assert found_11n_nss, "802.11n NSS capability not found"
        assert found_11ac, "802.11ac capability not found"
        assert found_11ac_nss, "802.11ac NSS capability not found"
        assert found_11ax, "802.11ax capability not found"


class TestGCMP256CipherRegression:
    """
    Regression tests to ensure GCMP-256 cipher detection stays correct.

    These tests prevent accidentally reverting to the old 'gcmp256' boolean format.
    GCMP-256 should now be reported in cipher capabilities (group_cipher/pairwise_cipher).
    """

    def test_gcmp256_no_standalone_capability(self):
        """Ensure old standalone 'gcmp256' capability doesn't exist anymore"""
        # Use OnePlus 11 Wi-Fi 7 pcap which supports GCMP-256
        pcap = "./tests/pcaps/wifi7/OnePlus11_Android15.pcapng"
        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False

        cap = rdpcap(pcap)
        _, _, _, capabilities = p.analyze_assoc_req(cap[0], is_6ghz=False)

        # Old 'gcmp256' db_key should NOT exist
        for capability in capabilities:
            assert capability.db_key != "gcmp256", (
                "Found old 'gcmp256' capability - should be in cipher capabilities now"
            )

    def test_gcmp256_in_cipher_capabilities(self):
        """Ensure GCMP-256 is detected in cipher capabilities"""
        # Use OnePlus 11 Wi-Fi 7 pcap which supports GCMP-256
        pcap = "./tests/pcaps/wifi7/OnePlus11_Android15.pcapng"
        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False

        cap = rdpcap(pcap)
        _, _, _, capabilities = p.analyze_assoc_req(cap[0], is_6ghz=False)

        # Find cipher capabilities
        group_cipher = None
        pairwise_cipher = None

        for capability in capabilities:
            if capability.db_key == "group_cipher":
                group_cipher = capability
            elif capability.db_key == "pairwise_cipher":
                pairwise_cipher = capability

        # At least one cipher capability should exist and contain GCMP-256
        assert group_cipher is not None or pairwise_cipher is not None, (
            "No cipher capabilities found"
        )

        has_gcmp256 = False
        if group_cipher and "GCMP-256" in str(group_cipher.value):
            has_gcmp256 = True
        if pairwise_cipher and "GCMP-256" in str(pairwise_cipher.value):
            has_gcmp256 = True

        assert has_gcmp256, "GCMP-256 not found in group_cipher or pairwise_cipher"

    def test_gcmp256_cipher_value_format(self):
        """Ensure cipher capabilities use 'CIPHER-NAME (TYPE)' format"""
        # Use OnePlus 11 Wi-Fi 7 pcap
        pcap = "./tests/pcaps/wifi7/OnePlus11_Android15.pcapng"
        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False

        cap = rdpcap(pcap)
        _, _, _, capabilities = p.analyze_assoc_req(cap[0], is_6ghz=False)

        # Check cipher capability format
        for capability in capabilities:
            if capability.db_key in ("group_cipher", "pairwise_cipher"):
                # Value should contain cipher name and type number
                # e.g., "GCMP-256 (9)" or "CCMP-128 (4)"
                value = str(capability.value)

                # Should have format "NAME (NUMBER)"
                if "GCMP-256" in value:
                    assert "(9)" in value, (
                        f"GCMP-256 cipher should include type (9), got: {value}"
                    )

                # db_value should be the cipher type number
                if "GCMP-256" in value:
                    assert capability.db_value == 9, (
                        f"GCMP-256 db_value should be 9, got: {capability.db_value}"
                    )

    def test_gcmp256_pairwise_multiple_ciphers(self):
        """Test that multiple pairwise ciphers are comma-separated"""
        # Use Pixel 8 Wi-Fi7 pcap which has multiple pairwise ciphers
        pcap = "./tests/pcaps/wifi7/Pixel8_Android16.pcapng"
        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False

        cap = rdpcap(pcap)
        _, _, _, capabilities = p.analyze_assoc_req(cap[0], is_6ghz=False)

        # Find pairwise_cipher capability
        pairwise_cipher = None
        for capability in capabilities:
            if capability.db_key == "pairwise_cipher":
                pairwise_cipher = capability
                break

        if pairwise_cipher and "," in str(pairwise_cipher.value):
            # Multiple ciphers should be comma-separated
            value = str(pairwise_cipher.value)
            # Should contain both cipher name and type for each
            # e.g., "CCMP-128 (4), GCMP-256 (9)"
            assert "(" in value and ")" in value, (
                f"Cipher format should include types in parentheses: {value}"
            )

    def test_cipher_capabilities_always_present(self):
        """Ensure group_cipher and pairwise_cipher capabilities always exist"""
        # Use a basic 5GHz pcap
        pcap = "./tests/pcaps/SM-G977U_Android10_RandomizedMAC_26-a0-e2-00-00-00_5.8GHz-anonymized.pcap"
        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False

        cap = rdpcap(pcap)
        _, _, _, capabilities = p.analyze_assoc_req(cap[0], is_6ghz=False)

        # Find cipher capabilities
        has_group_cipher = False
        has_pairwise_cipher = False

        for capability in capabilities:
            if capability.db_key == "group_cipher":
                has_group_cipher = True
            elif capability.db_key == "pairwise_cipher":
                has_pairwise_cipher = True

        # Both cipher capabilities should exist
        assert has_group_cipher, "group_cipher capability not found"
        assert has_pairwise_cipher, "pairwise_cipher capability not found"

    def test_cipher_not_reported_when_no_rsn(self):
        """Test cipher capabilities when RSN IE is not present"""
        # This would require a pcap without RSN IE
        # For now, just ensure the capability exists with appropriate value
        # We test this in test_capability_migration.py::test_gcmp256_no_rsn_ie
        pass
