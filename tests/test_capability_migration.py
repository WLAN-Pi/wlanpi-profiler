"""
Tests for Wi-Fi 6E/7 capability detection migration from tshark-dc branch.

These tests validate the new capability detection features:
- Extended Capabilities: SCS (802.11aa), MSCS (QoS R1)
- EHT MAC Capabilities: EPCS, OM Control, R-TWT, SCS Traffic Description
- RSNX: SAE H2E support
- Future: MCS 14/15, GCMP-256, Multi-Link Element
"""

from profiler import profiler


class TestExtendedCapabilities:
    """Test Extended Capabilities IE parsing (Tag 127)"""

    def test_scs_support_detected(self):
        """Test SCS (Stream Classification Service) detection - Octet 7, Bit 6"""
        p = profiler.Profiler()

        mock_ie_dict = {127: [0x00] * 6 + [0x40] + [0x00] * 3}

        capabilities = p.analyze_extended_capabilities_ie(mock_ie_dict)

        scs_cap = next(
            (c for c in capabilities if c.db_key == "dot11aa_scs_support"), None
        )
        assert scs_cap is not None, "SCS capability not found"
        assert scs_cap.value == "Supported", (
            f"Expected 'Supported', got '{scs_cap.value}'"
        )
        assert scs_cap.db_value == 1, f"Expected db_value=1, got {scs_cap.db_value}"

    def test_scs_support_not_detected(self):
        """Test SCS not supported when bit is clear"""
        p = profiler.Profiler()

        mock_ie_dict = {127: [0x00] * 10}

        capabilities = p.analyze_extended_capabilities_ie(mock_ie_dict)

        scs_cap = next(
            (c for c in capabilities if c.db_key == "dot11aa_scs_support"), None
        )
        assert scs_cap is not None, "SCS capability not found"
        assert scs_cap.value == "Not supported", (
            f"Expected 'Not supported', got '{scs_cap.value}'"
        )
        assert scs_cap.db_value == 0, f"Expected db_value=0, got {scs_cap.db_value}"

    def test_mscs_support_detected(self):
        """Test MSCS (Mirrored Stream Classification Service) detection - Bit 85 = Byte 10 (0-indexed), Bit 5"""
        p = profiler.Profiler()

        mock_ie_dict = {127: [0x00] * 10 + [0x20]}

        capabilities = p.analyze_extended_capabilities_ie(mock_ie_dict)

        mscs_cap = next(
            (c for c in capabilities if c.db_key == "qos_r1_mscs_support"), None
        )
        assert mscs_cap is not None, "MSCS capability not found"
        assert mscs_cap.value == "Supported", (
            f"Expected 'Supported', got '{mscs_cap.value}'"
        )
        assert mscs_cap.db_value == 1, f"Expected db_value=1, got {mscs_cap.db_value}"

    def test_mscs_support_not_detected(self):
        """Test MSCS not supported when bit is clear"""
        p = profiler.Profiler()

        mock_ie_dict = {127: [0x00] * 11}

        capabilities = p.analyze_extended_capabilities_ie(mock_ie_dict)

        mscs_cap = next(
            (c for c in capabilities if c.db_key == "qos_r1_mscs_support"), None
        )
        assert mscs_cap is not None, "MSCS capability not found"
        assert mscs_cap.value == "Not supported", (
            f"Expected 'Not supported', got '{mscs_cap.value}'"
        )
        assert mscs_cap.db_value == 0, f"Expected db_value=0, got {mscs_cap.db_value}"

    def test_mscs_not_reported_when_ie_too_short(self):
        """Test MSCS returns 'Not reported' (-1) when IE is shorter than 11 bytes"""
        p = profiler.Profiler()

        mock_ie_dict = {127: [0x00] * 8}

        capabilities = p.analyze_extended_capabilities_ie(mock_ie_dict)

        mscs_cap = next(
            (c for c in capabilities if c.db_key == "qos_r1_mscs_support"), None
        )
        assert mscs_cap is not None, "MSCS capability not found"
        assert mscs_cap.value == "Not reported*", (
            f"Expected 'Not reported*', got '{mscs_cap.value}'"
        )
        assert mscs_cap.db_value == -1, f"Expected db_value=-1, got {mscs_cap.db_value}"

    def test_both_scs_and_mscs_supported(self):
        """Test both SCS and MSCS detected together"""
        p = profiler.Profiler()

        mock_ie_dict = {127: [0x00] * 6 + [0x40] + [0x00] * 3 + [0x20]}

        capabilities = p.analyze_extended_capabilities_ie(mock_ie_dict)

        scs_cap = next(
            (c for c in capabilities if c.db_key == "dot11aa_scs_support"), None
        )
        mscs_cap = next(
            (c for c in capabilities if c.db_key == "qos_r1_mscs_support"), None
        )

        assert scs_cap is not None
        assert scs_cap.value == "Supported"
        assert mscs_cap is not None
        assert mscs_cap.value == "Supported"


class TestEHTMACCapabilities:
    """Test EHT MAC Capabilities parsing (IE Extension Tag 108, bytes 1-2)"""

    def test_epcs_support_detected(self):
        """Test EPCS (Emergency Preparedness Communications Service) - bit 0"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {255: [bytes([108, 0x01, 0x00]) + bytes([0x00] * 15)]}

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        epcs_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_epcs_support"), None
        )
        assert epcs_cap is not None, "EPCS capability not found"
        assert epcs_cap.value == "Supported", (
            f"Expected 'Supported', got '{epcs_cap.value}'"
        )
        assert epcs_cap.db_value == 1, f"Expected db_value=1, got {epcs_cap.db_value}"

    def test_om_control_support_detected(self):
        """Test OM Control (Operating Mode Control) - bit 1"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {255: [bytes([108, 0x02, 0x00]) + bytes([0x00] * 15)]}

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        om_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_om_support"), None
        )
        assert om_cap is not None, "OM Control capability not found"
        assert om_cap.value == "Supported", (
            f"Expected 'Supported', got '{om_cap.value}'"
        )
        assert om_cap.db_value == 1, f"Expected db_value=1, got {om_cap.db_value}"

    def test_rtwt_support_detected(self):
        """Test R-TWT (Restricted Target Wake Time) - bit 4"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {255: [bytes([108, 0x10, 0x00]) + bytes([0x00] * 15)]}

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        rtwt_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_rtwt_support"), None
        )
        assert rtwt_cap is not None, "R-TWT capability not found"
        assert rtwt_cap.value == "Supported", (
            f"Expected 'Supported', got '{rtwt_cap.value}'"
        )
        assert rtwt_cap.db_value == 1, f"Expected db_value=1, got {rtwt_cap.db_value}"

    def test_scs_traffic_description_support_detected(self):
        """Test SCS Traffic Description - bit 5"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {255: [bytes([108, 0x20, 0x00]) + bytes([0x00] * 15)]}

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        scs_traffic_cap = next(
            (
                c
                for c in capabilities
                if c.db_key == "dot11be_scs_traffic_description_support"
            ),
            None,
        )
        assert scs_traffic_cap is not None, (
            "SCS Traffic Description capability not found"
        )
        assert scs_traffic_cap.value == "Supported", (
            f"Expected 'Supported', got '{scs_traffic_cap.value}'"
        )
        assert scs_traffic_cap.db_value == 1, (
            f"Expected db_value=1, got {scs_traffic_cap.db_value}"
        )

    def test_all_eht_mac_capabilities_detected(self):
        """Test all four EHT MAC capabilities simultaneously"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {255: [bytes([108, 0x33, 0x00]) + bytes([0x00] * 15)]}

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        epcs_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_epcs_support"), None
        )
        om_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_om_support"), None
        )
        rtwt_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_rtwt_support"), None
        )
        scs_traffic_cap = next(
            (
                c
                for c in capabilities
                if c.db_key == "dot11be_scs_traffic_description_support"
            ),
            None,
        )

        assert epcs_cap is not None
        assert epcs_cap.value == "Supported"
        assert om_cap is not None
        assert om_cap.value == "Supported"
        assert rtwt_cap is not None
        assert rtwt_cap.value == "Supported"
        assert scs_traffic_cap is not None
        assert scs_traffic_cap.value == "Supported"

    def test_eht_mac_capabilities_all_not_supported(self):
        """Test EHT MAC capabilities all return 'Not supported' when bits are clear"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {255: [bytes([108, 0x00, 0x00]) + bytes([0x00] * 15)]}

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        epcs_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_epcs_support"), None
        )
        om_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_om_support"), None
        )
        rtwt_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_rtwt_support"), None
        )
        scs_traffic_cap = next(
            (
                c
                for c in capabilities
                if c.db_key == "dot11be_scs_traffic_description_support"
            ),
            None,
        )

        assert epcs_cap is not None
        assert epcs_cap.value == "Not supported"
        assert om_cap is not None
        assert om_cap.value == "Not supported"
        assert rtwt_cap is not None
        assert rtwt_cap.value == "Not supported"
        assert scs_traffic_cap is not None
        assert scs_traffic_cap.value == "Not supported"


class TestEHTPHYCapabilities:
    """Test EHT PHY Capabilities parsing (MCS 14/15 support)"""

    def test_mcs15_support_detected(self):
        """Test MCS 15 support detection - PHY bits 40-63, mask 0x007800"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {
            255: [
                bytes([108, 0x00, 0x00])
                + bytes([0x00] * 5)
                + bytes([0x00, 0x08, 0x00])
                + bytes([0x00] * 7)
            ]
        }

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        mcs15_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mcs15_support"), None
        )
        assert mcs15_cap is not None, "MCS 15 capability not found"
        assert mcs15_cap.value == "Supported", (
            f"Expected 'Supported', got '{mcs15_cap.value}'"
        )
        assert mcs15_cap.db_value > 0, (
            f"Expected db_value > 0, got {mcs15_cap.db_value}"
        )

    def test_mcs15_support_not_detected(self):
        """Test MCS 15 not supported when bits are clear"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {255: [bytes([108, 0x00, 0x00]) + bytes([0x00] * 15)]}

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        mcs15_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mcs15_support"), None
        )
        assert mcs15_cap is not None, "MCS 15 capability not found"
        assert mcs15_cap.value == "Not supported", (
            f"Expected 'Not supported', got '{mcs15_cap.value}'"
        )
        assert mcs15_cap.db_value == 0, f"Expected db_value=0, got {mcs15_cap.db_value}"

    def test_eht_dup_mcs14_support_detected(self):
        """Test EHT DUP (MCS 14) in 6 GHz detection - PHY bits 40-63, mask 0x008000"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {
            255: [
                bytes(
                    [
                        108,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x80,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                    ]
                )
            ]
        }

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        mcs14_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mcs14_support"), None
        )
        assert mcs14_cap is not None, "EHT DUP (MCS 14) capability not found"
        assert mcs14_cap.value == "Supported", (
            f"Expected 'Supported', got '{mcs14_cap.value}'"
        )
        assert mcs14_cap.db_value == 1, f"Expected db_value=1, got {mcs14_cap.db_value}"

    def test_eht_dup_mcs14_support_not_detected(self):
        """Test EHT DUP (MCS 14) not supported when bit is clear"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {255: [bytes([108, 0x00, 0x00]) + bytes([0x00] * 15)]}

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        mcs14_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mcs14_support"), None
        )
        assert mcs14_cap is not None, "EHT DUP (MCS 14) capability not found"
        assert mcs14_cap.value == "Not supported", (
            f"Expected 'Not supported', got '{mcs14_cap.value}'"
        )
        assert mcs14_cap.db_value == 0, f"Expected db_value=0, got {mcs14_cap.db_value}"

    def test_mcs14_and_mcs15_both_supported(self):
        """Test both MCS 14 and MCS 15 detected together"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {
            255: [
                bytes(
                    [
                        108,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0xF8,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                    ]
                )
            ]
        }

        capabilities = p.analyze_extension_ies(
            mock_ie_dict, he_disabled=False, be_disabled=False
        )

        mcs15_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mcs15_support"), None
        )
        mcs14_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mcs14_support"), None
        )

        assert mcs15_cap is not None
        assert mcs15_cap.value == "Supported"
        assert mcs14_cap is not None
        assert mcs14_cap.value == "Supported"


class TestRSNXCapabilities:
    """Test RSNX IE parsing (Tag 244)"""

    def test_sae_h2e_support_detected(self):
        """Test SAE H2E (Hash-to-Element) detection - Octet 1, Bit 5"""
        p = profiler.Profiler()

        mock_ie_dict = {244: bytes([0x20])}

        capabilities = p.analyze_rsnx_ie(mock_ie_dict)

        sae_h2e_cap = next(
            (c for c in capabilities if c.db_key == "rsnx_sae_h2e"), None
        )
        assert sae_h2e_cap is not None, "SAE H2E capability not found"
        assert sae_h2e_cap.value == "Supported", (
            f"Expected 'Supported', got '{sae_h2e_cap.value}'"
        )
        assert sae_h2e_cap.db_value == 1, (
            f"Expected db_value=1, got {sae_h2e_cap.db_value}"
        )

    def test_sae_h2e_support_not_detected(self):
        """Test SAE H2E not supported when bit is clear"""
        p = profiler.Profiler()

        mock_ie_dict = {244: bytes([0x00])}

        capabilities = p.analyze_rsnx_ie(mock_ie_dict)

        sae_h2e_cap = next(
            (c for c in capabilities if c.db_key == "rsnx_sae_h2e"), None
        )
        assert sae_h2e_cap is not None, "SAE H2E capability not found"
        assert sae_h2e_cap.value == "Not supported", (
            f"Expected 'Not supported', got '{sae_h2e_cap.value}'"
        )
        assert sae_h2e_cap.db_value == 0, (
            f"Expected db_value=0, got {sae_h2e_cap.db_value}"
        )

    def test_sae_h2e_no_rsnx_ie(self):
        """Test SAE H2E returns 'Not reported' when RSNX IE is missing"""
        p = profiler.Profiler()

        mock_ie_dict = {}

        capabilities = p.analyze_rsnx_ie(mock_ie_dict)

        sae_h2e_cap = next(
            (c for c in capabilities if c.db_key == "rsnx_sae_h2e"), None
        )
        assert sae_h2e_cap is not None, "SAE H2E capability not found"
        assert sae_h2e_cap.value == "Not reported", (
            f"Expected 'Not reported', got '{sae_h2e_cap.value}'"
        )
        assert sae_h2e_cap.db_value == -1, (
            f"Expected db_value=-1 (not reported), got {sae_h2e_cap.db_value}"
        )


class TestGCMP256CipherSuite:
    """Test GCMP-256 cipher suite detection in RSN IE (Tag 48)"""

    def test_gcmp256_group_cipher_detected(self):
        """Test GCMP-256 as group cipher - OUI 00-0F-AC, Type 09"""
        p = profiler.Profiler()

        mock_ie_dict = {
            48: bytes(
                [
                    0x01,
                    0x00,
                    0x00,
                    0x0F,
                    0xAC,
                    0x09,
                    0x00,
                    0x00,
                ]
            )
        }

        capabilities = p.analyze_rsn_capabilities_ie(mock_ie_dict)

        group_cipher = next(
            (c for c in capabilities if c.db_key == "group_cipher"), None
        )
        assert group_cipher is not None, "group_cipher capability not found"
        assert "GCMP-256" in group_cipher.value, (
            f"Expected 'GCMP-256' in group_cipher, got '{group_cipher.value}'"
        )
        assert group_cipher.db_value == 9, (
            f"Expected db_value=9 (GCMP-256 type), got {group_cipher.db_value}"
        )

    def test_gcmp256_pairwise_cipher_detected(self):
        """Test GCMP-256 as pairwise cipher"""
        p = profiler.Profiler()

        mock_ie_dict = {
            48: bytes(
                [
                    0x01,
                    0x00,
                    0x00,
                    0x0F,
                    0xAC,
                    0x04,
                    0x01,
                    0x00,
                    0x00,
                    0x0F,
                    0xAC,
                    0x09,
                ]
            )
        }

        capabilities = p.analyze_rsn_capabilities_ie(mock_ie_dict)

        pairwise_cipher = next(
            (c for c in capabilities if c.db_key == "pairwise_cipher"), None
        )
        assert pairwise_cipher is not None, "pairwise_cipher capability not found"
        assert "GCMP-256" in pairwise_cipher.value, (
            f"Expected 'GCMP-256' in pairwise_cipher, got '{pairwise_cipher.value}'"
        )
        assert pairwise_cipher.db_value == 9, (
            f"Expected db_value=9 (GCMP-256 type), got {pairwise_cipher.db_value}"
        )

    def test_gcmp256_multiple_pairwise_ciphers(self):
        """Test GCMP-256 detected among multiple pairwise ciphers"""
        p = profiler.Profiler()

        mock_ie_dict = {
            48: bytes(
                [
                    0x01,
                    0x00,
                    0x00,
                    0x0F,
                    0xAC,
                    0x04,
                    0x02,
                    0x00,
                    0x00,
                    0x0F,
                    0xAC,
                    0x04,
                    0x00,
                    0x0F,
                    0xAC,
                    0x09,
                ]
            )
        }

        capabilities = p.analyze_rsn_capabilities_ie(mock_ie_dict)

        pairwise_cipher = next(
            (c for c in capabilities if c.db_key == "pairwise_cipher"), None
        )
        assert pairwise_cipher is not None, "pairwise_cipher capability not found"
        assert "GCMP-256" in pairwise_cipher.value, (
            f"Expected 'GCMP-256' in pairwise_cipher, got '{pairwise_cipher.value}'"
        )
        assert "CCMP-128" in pairwise_cipher.value, (
            f"Expected 'CCMP-128' in pairwise_cipher, got '{pairwise_cipher.value}'"
        )
        assert pairwise_cipher.db_value == 4, (
            f"Expected db_value=4 (first cipher), got {pairwise_cipher.db_value}"
        )

    def test_gcmp256_not_present(self):
        """Test GCMP-256 not supported when only AES-CCMP is present"""
        p = profiler.Profiler()

        mock_ie_dict = {
            48: bytes(
                [
                    0x01,
                    0x00,
                    0x00,
                    0x0F,
                    0xAC,
                    0x04,
                    0x01,
                    0x00,
                    0x00,
                    0x0F,
                    0xAC,
                    0x04,
                ]
            )
        }

        capabilities = p.analyze_rsn_capabilities_ie(mock_ie_dict)

        group_cipher = next(
            (c for c in capabilities if c.db_key == "group_cipher"), None
        )
        pairwise_cipher = next(
            (c for c in capabilities if c.db_key == "pairwise_cipher"), None
        )

        assert group_cipher is not None, "group_cipher capability not found"
        assert "GCMP-256" not in group_cipher.value, (
            f"Did not expect 'GCMP-256' in group_cipher, got '{group_cipher.value}'"
        )

        assert pairwise_cipher is not None, "pairwise_cipher capability not found"
        assert "GCMP-256" not in pairwise_cipher.value, (
            f"Did not expect 'GCMP-256' in pairwise_cipher, got '{pairwise_cipher.value}'"
        )

    def test_gcmp256_no_rsn_ie(self):
        """Test cipher capabilities return 'Not reported' when RSN IE is missing"""
        p = profiler.Profiler()

        mock_ie_dict = {}

        capabilities = p.analyze_rsn_capabilities_ie(mock_ie_dict)

        group_cipher = next(
            (c for c in capabilities if c.db_key == "group_cipher"), None
        )
        pairwise_cipher = next(
            (c for c in capabilities if c.db_key == "pairwise_cipher"), None
        )

        assert group_cipher is not None, "group_cipher capability not found"
        assert group_cipher.value == "Not reported", (
            f"Expected 'Not reported', got '{group_cipher.value}'"
        )
        assert group_cipher.db_value == 0, (
            f"Expected db_value=0, got {group_cipher.db_value}"
        )

        assert pairwise_cipher is not None, "pairwise_cipher capability not found"
        assert pairwise_cipher.value == "Not reported", (
            f"Expected 'Not reported', got '{pairwise_cipher.value}'"
        )
        assert pairwise_cipher.db_value == 0, (
            f"Expected db_value=0, got {pairwise_cipher.db_value}"
        )


class TestMLECapabilities:
    """Test Multi-Link Element (MLE) parsing (IE Extension Tag 107)"""

    def test_mle_basic_type0_detected(self):
        """Test MLE presence with Type 0 (Basic)"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {
            255: [
                bytes(
                    [
                        107,
                        0x00,
                        0x00,
                        0x11,
                        0x22,
                        0x33,
                        0x44,
                        0x55,
                        0x66,
                    ]
                )
            ]
        }

        capabilities = p.analyze_extension_ies(mock_ie_dict, False, False)

        mle_cap = next((c for c in capabilities if c.db_key == "dot11be_mle"), None)
        type_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mle_mlc_type"), None
        )

        assert mle_cap is not None, "MLE capability not found"
        assert mle_cap.db_value == 1, f"Expected MLE db_value=1, got {mle_cap.db_value}"
        assert type_cap is not None, "MLC Type capability not found"
        assert type_cap.db_value == 0, f"Expected Type=0, got {type_cap.db_value}"

    def test_mle_with_mld_capabilities(self):
        """Test MLE with MLD Capabilities present"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {
            255: [
                bytes(
                    [
                        107,
                        0x00,
                        0x01,
                        0x09,
                        0x11,
                        0x22,
                        0x33,
                        0x44,
                        0x55,
                        0x66,
                        0x21,
                        0x20,
                    ]
                )
            ]
        }

        capabilities = p.analyze_extension_ies(mock_ie_dict, False, False)

        max_links_cap = next(
            (
                c
                for c in capabilities
                if c.db_key == "dot11be_mle_max_simultaneous_links"
            ),
            None,
        )
        t2lm_cap = next(
            (
                c
                for c in capabilities
                if c.db_key == "dot11be_mle_t2lm_negotiation_support"
            ),
            None,
        )
        reconfig_cap = next(
            (
                c
                for c in capabilities
                if c.db_key == "dot11be_mle_link_reconfig_support"
            ),
            None,
        )

        assert max_links_cap is not None, "Max Simultaneous Links not found"
        assert max_links_cap.db_value == 1, (
            f"Expected Max Links=1, got {max_links_cap.db_value}"
        )
        assert t2lm_cap is not None, "T2LM Negotiation not found"
        assert t2lm_cap.db_value == 1, f"Expected T2LM=1, got {t2lm_cap.db_value}"
        assert reconfig_cap is not None, "Link Reconfig not found"
        assert reconfig_cap.db_value == 1, (
            f"Expected Reconfig=1, got {reconfig_cap.db_value}"
        )

    def test_mle_with_eml_capabilities(self):
        """Test MLE with EML Capabilities present"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {
            255: [
                bytes(
                    [
                        107,
                        0x80,
                        0x00,
                        0x09,
                        0x11,
                        0x22,
                        0x33,
                        0x44,
                        0x55,
                        0x66,
                        0xB5,
                        0x00,
                    ]
                )
            ]
        }

        capabilities = p.analyze_extension_ies(mock_ie_dict, False, False)

        emlsr_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mle_emlsr_support"), None
        )
        padding_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mle_emlsr_padding_delay"),
            None,
        )
        transition_cap = next(
            (
                c
                for c in capabilities
                if c.db_key == "dot11be_mle_emlsr_transition_delay"
            ),
            None,
        )
        emlmr_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mle_emlmr_support"), None
        )

        assert emlsr_cap is not None
        assert emlsr_cap.db_value == 1, "EMLSR should be 1"
        assert padding_cap is not None
        assert padding_cap.db_value == 2, (
            f"Padding should be 2, got {padding_cap.db_value}"
        )
        assert transition_cap is not None
        assert transition_cap.db_value == 3, (
            f"Transition should be 3, got {transition_cap.db_value}"
        )
        assert emlmr_cap is not None
        assert emlmr_cap.db_value == 1, "EMLMR should be 1"

    def test_mle_not_present(self):
        """Test MLE returns 'Not reported' when MLE IE is missing"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {255: [bytes([108, 0x00, 0x00]) + bytes([0x00] * 15)]}

        capabilities = p.analyze_extension_ies(mock_ie_dict, False, False)

        mle_cap = next((c for c in capabilities if c.db_key == "dot11be_mle"), None)
        assert mle_cap is not None, "MLE capability not found"
        assert mle_cap.db_value == -1, (
            f"Expected db_value=-1 (not reported), got {mle_cap.db_value}"
        )

    def test_mle_onePlus11_scenario(self):
        """Test MLE parsing matching OnePlus11 expected output"""
        p = profiler.Profiler()
        p.be_disabled = False

        mock_ie_dict = {
            255: [
                bytes(
                    [
                        107,
                        0x00,
                        0x01,
                        0x09,
                        0x30,
                        0xBB,
                        0x7D,
                        0x4E,
                        0xC1,
                        0x2B,
                        0x21,
                        0x00,
                    ]
                )
            ]
        }

        capabilities = p.analyze_extension_ies(mock_ie_dict, False, False)

        mle_cap = next((c for c in capabilities if c.db_key == "dot11be_mle"), None)
        type_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mle_mlc_type"), None
        )
        max_links_cap = next(
            (
                c
                for c in capabilities
                if c.db_key == "dot11be_mle_max_simultaneous_links"
            ),
            None,
        )
        t2lm_cap = next(
            (
                c
                for c in capabilities
                if c.db_key == "dot11be_mle_t2lm_negotiation_support"
            ),
            None,
        )
        reconfig_cap = next(
            (
                c
                for c in capabilities
                if c.db_key == "dot11be_mle_link_reconfig_support"
            ),
            None,
        )
        emlsr_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mle_emlsr_support"), None
        )

        assert mle_cap is not None
        assert mle_cap.db_value == 1
        assert type_cap is not None
        assert type_cap.db_value == 0
        assert max_links_cap is not None
        assert max_links_cap.db_value == 1
        assert t2lm_cap is not None
        assert t2lm_cap.db_value == 1
        assert reconfig_cap is not None
        assert reconfig_cap.db_value == 0
        assert emlsr_cap is not None
        assert emlsr_cap.db_value == -1


class TestMalformedExtensionIEs:
    """Malformed extension IEs must not crash the capture session (phase 0)."""

    def test_empty_extension_ie_does_not_raise(self):
        capabilities = profiler.Profiler.analyze_extension_ies(
            {255: [b""]}, he_disabled=False, be_disabled=False
        )
        assert isinstance(capabilities, list)

    def test_truncated_he_capabilities_ie_does_not_raise(self):
        capabilities = profiler.Profiler.analyze_extension_ies(
            {255: [bytes([35, 0, 0])]}, he_disabled=False, be_disabled=False
        )
        dot11ax = next(c for c in capabilities if c.db_key == "dot11ax")
        assert dot11ax.value != "Supported"

    def test_zero_length_entry_in_mixed_list_does_not_raise(self):
        capabilities = profiler.Profiler.analyze_extension_ies(
            {255: [bytes([35]) + bytes(19), b"", bytes([36, 0])]},
            he_disabled=False,
            be_disabled=False,
        )
        dot11ax = next(c for c in capabilities if c.db_key == "dot11ax")
        assert dot11ax.value == "Supported"
