# -*- coding: utf-8 -*-
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

        # Create mock Extended Capabilities IE with SCS bit set
        # Octet 7 (index 6), Bit 6 = 0x40
        mock_ie_dict = {
            127: [0x00] * 6 + [0x40] + [0x00] * 3  # 10 octets, SCS bit set
        }

        capabilities = p.analyze_extended_capabilities_ie(mock_ie_dict)

        # Find SCS capability
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

        # Create mock Extended Capabilities IE with SCS bit clear
        mock_ie_dict = {
            127: [0x00] * 10  # All bits clear
        }

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

        # Create mock Extended Capabilities IE with MSCS bit set
        # Bit 85 = Byte index 10 (0-indexed), Bit 5 = 0x20
        mock_ie_dict = {
            127: [0x00] * 10 + [0x20]  # 11 bytes total, MSCS bit at byte 10
        }

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

        mock_ie_dict = {
            127: [0x00] * 11  # All bits clear, byte 10 exists (11 bytes total)
        }

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

        mock_ie_dict = {
            127: [0x00] * 8  # Only 8 bytes, byte 10 doesn't exist (need 11 bytes)
        }

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

        # Set both bits: Byte 6 Bit 6 (0x40) for SCS and Byte 10 Bit 5 (0x20) for MSCS
        mock_ie_dict = {
            127: [0x00] * 6 + [0x40] + [0x00] * 3 + [0x20]  # 11 bytes total
        }

        capabilities = p.analyze_extended_capabilities_ie(mock_ie_dict)

        scs_cap = next(
            (c for c in capabilities if c.db_key == "dot11aa_scs_support"), None
        )
        mscs_cap = next(
            (c for c in capabilities if c.db_key == "qos_r1_mscs_support"), None
        )

        assert scs_cap is not None and scs_cap.value == "Supported"
        assert mscs_cap is not None and mscs_cap.value == "Supported"


class TestEHTMACCapabilities:
    """Test EHT MAC Capabilities parsing (IE Extension Tag 108, bytes 1-2)"""

    def test_epcs_support_detected(self):
        """Test EPCS (Emergency Preparedness Communications Service) - bit 0"""
        p = profiler.Profiler()
        p.be_disabled = False

        # EHT Capabilities: Extension ID 108 as first byte, then MAC caps bytes with EPCS bit set
        # Bit 0 = 0x0001 in little-endian 16-bit value
        # Need at least 18 bytes total (1 ext ID + 2 MAC + 15 PHY minimum)
        mock_ie_dict = {
            255: [
                bytes([108, 0x01, 0x00])
                + bytes([0x00] * 15)  # Ext ID 108, EPCS bit set, rest zeros
            ]
        }

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

        # Bit 1 = 0x0002 in little-endian 16-bit value
        # Need at least 18 bytes total (1 ext ID + 2 MAC + 15 PHY minimum)
        mock_ie_dict = {
            255: [
                bytes([108, 0x02, 0x00])
                + bytes([0x00] * 15)  # Ext ID 108, OM Control bit set
            ]
        }

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

        # Bit 4 = 0x0010 in little-endian 16-bit value
        # Need at least 18 bytes total (1 ext ID + 2 MAC + 15 PHY minimum)
        mock_ie_dict = {
            255: [
                bytes([108, 0x10, 0x00])
                + bytes([0x00] * 15)  # Ext ID 108, R-TWT bit set
            ]
        }

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

        # Bit 5 = 0x0020 in little-endian 16-bit value
        # Need at least 18 bytes total (1 ext ID + 2 MAC + 15 PHY minimum)
        mock_ie_dict = {
            255: [
                bytes([108, 0x20, 0x00])
                + bytes([0x00] * 15)  # Ext ID 108, SCS Traffic bit set
            ]
        }

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

        # Set all bits: EPCS(0x01) | OM(0x02) | R-TWT(0x10) | SCS(0x20) = 0x0033
        # Need at least 18 bytes total (1 ext ID + 2 MAC + 15 PHY minimum)
        mock_ie_dict = {
            255: [
                bytes([108, 0x33, 0x00])
                + bytes([0x00] * 15)  # Ext ID 108, all 4 bits set
            ]
        }

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

        assert epcs_cap is not None and epcs_cap.value == "Supported"
        assert om_cap is not None and om_cap.value == "Supported"
        assert rtwt_cap is not None and rtwt_cap.value == "Supported"
        assert scs_traffic_cap is not None and scs_traffic_cap.value == "Supported"

    def test_eht_mac_capabilities_all_not_supported(self):
        """Test EHT MAC capabilities all return 'Not supported' when bits are clear"""
        p = profiler.Profiler()
        p.be_disabled = False

        # All bits clear
        # Need at least 18 bytes total (1 ext ID + 2 MAC + 15 PHY minimum)
        mock_ie_dict = {
            255: [
                bytes([108, 0x00, 0x00])
                + bytes([0x00] * 15)  # Ext ID 108, all bits clear
            ]
        }

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

        assert epcs_cap is not None and epcs_cap.value == "Not supported"
        assert om_cap is not None and om_cap.value == "Not supported"
        assert rtwt_cap is not None and rtwt_cap.value == "Not supported"
        assert scs_traffic_cap is not None and scs_traffic_cap.value == "Not supported"


class TestEHTPHYCapabilities:
    """Test EHT PHY Capabilities parsing (MCS 14/15 support)"""

    def test_mcs15_support_detected(self):
        """Test MCS 15 support detection - PHY bits 40-63, mask 0x007800"""
        p = profiler.Profiler()
        p.be_disabled = False

        # MCS 15 is in PHY bits 40-63 (bytes 8-10 of element_data, which is PHY bytes 5-7)
        # mask 0x007800, which is bits 11-14 of the 24-bit value
        # In little-endian: byte 0=bits 0-7, byte 1=bits 8-15, byte 2=bits 16-23
        # Mask 0x007800 = 0x00 0x78 0x00 in little-endian (bit 11 is in byte 1)
        mock_ie_dict = {
            255: [
                # Ext ID 108, 2 MAC bytes, then PHY bytes
                bytes([108, 0x00, 0x00])  # MAC caps
                + bytes([0x00] * 5)  # PHY bytes 0-4
                + bytes([0x00, 0x08, 0x00])  # PHY bytes 5-7: set bit 11 (0x0800 in LE)
                + bytes([0x00] * 7)  # Rest of PHY
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

        mock_ie_dict = {
            255: [
                bytes([108, 0x00, 0x00]) + bytes([0x00] * 15)  # All zeros
            ]
        }

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

        # EHT DUP is bit 15 of the 24-bit value (mask 0x008000)
        # In little-endian: 0x008000 = 0x00 0x80 0x00 (bit 15 is in byte 1, high bit)
        # Bytes: 0=Ext ID, 1-2=EHT MAC, 3-17=EHT PHY (need at least 18 bytes total)
        # MCS 14 is in PHY bytes 5-7 (element_data indices 8-10)
        mock_ie_dict = {
            255: [
                bytes(
                    [
                        108,  # Ext ID
                        0x00,
                        0x00,  # EHT MAC Caps
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,  # EHT PHY bytes 0-4
                        0x00,
                        0x80,
                        0x00,  # EHT PHY bytes 5-7 (bits 40-63): MCS 14 set
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                    ]
                )  # Padding to byte 17
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

        mock_ie_dict = {
            255: [
                bytes([108, 0x00, 0x00]) + bytes([0x00] * 15)  # All zeros
            ]
        }

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

        # Set both: MCS 15 bits (0x7800) and EHT DUP bit (0x8000) = 0xF800
        # In little-endian: 0xF800 = 0x00 0xF8 0x00
        # Bytes: 0=Ext ID, 1-2=EHT MAC, 3-17=EHT PHY (need at least 18 bytes total)
        # MCS 14/15 are in PHY bytes 5-7 (element_data indices 8-10)
        mock_ie_dict = {
            255: [
                bytes(
                    [
                        108,  # Ext ID
                        0x00,
                        0x00,  # EHT MAC Caps
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,  # EHT PHY bytes 0-4
                        0x00,
                        0xF8,
                        0x00,  # EHT PHY bytes 5-7 (bits 40-63): MCS 14+15 set
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                    ]
                )  # Padding to byte 17
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

        assert mcs15_cap is not None and mcs15_cap.value == "Supported"
        assert mcs14_cap is not None and mcs14_cap.value == "Supported"


class TestRSNXCapabilities:
    """Test RSNX IE parsing (Tag 244)"""

    def test_sae_h2e_support_detected(self):
        """Test SAE H2E (Hash-to-Element) detection - Octet 1, Bit 5"""
        p = profiler.Profiler()

        # RSNX byte with bit 5 set = 0x20
        mock_ie_dict = {
            244: bytes([0x20])  # SAE H2E bit set
        }

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

        # RSNX byte with bit 5 clear
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

        # Empty IE dict (no RSNX tag)
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

        # RSN IE structure: Version(2) + Group Cipher(4) + Pairwise Count(2)
        # Version: 0x0100 (little-endian = 1)
        # Group Cipher: 00-0F-AC-09 (GCMP-256)
        # Pairwise Count: 0x0000
        mock_ie_dict = {
            48: bytes(
                [
                    0x01,
                    0x00,  # Version
                    0x00,
                    0x0F,
                    0xAC,
                    0x09,  # Group cipher: GCMP-256
                    0x00,
                    0x00,
                ]
            )  # Pairwise count
        }

        capabilities = p.analyze_rsn_capabilities_ie(mock_ie_dict)

        # Check group_cipher capability contains GCMP-256
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

        # RSN IE: Version + Group Cipher(AES-CCMP) + Pairwise Count(1) + Pairwise(GCMP-256)
        mock_ie_dict = {
            48: bytes(
                [
                    0x01,
                    0x00,  # Version
                    0x00,
                    0x0F,
                    0xAC,
                    0x04,  # Group cipher: AES-CCMP
                    0x01,
                    0x00,  # Pairwise count: 1
                    0x00,
                    0x0F,
                    0xAC,
                    0x09,
                ]
            )  # Pairwise cipher: GCMP-256
        }

        capabilities = p.analyze_rsn_capabilities_ie(mock_ie_dict)

        # Check pairwise_cipher capability contains GCMP-256
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

        # RSN IE with 2 pairwise ciphers: AES-CCMP and GCMP-256
        mock_ie_dict = {
            48: bytes(
                [
                    0x01,
                    0x00,  # Version
                    0x00,
                    0x0F,
                    0xAC,
                    0x04,  # Group cipher: AES-CCMP
                    0x02,
                    0x00,  # Pairwise count: 2
                    0x00,
                    0x0F,
                    0xAC,
                    0x04,  # Pairwise 1: AES-CCMP
                    0x00,
                    0x0F,
                    0xAC,
                    0x09,
                ]
            )  # Pairwise 2: GCMP-256
        }

        capabilities = p.analyze_rsn_capabilities_ie(mock_ie_dict)

        # Check pairwise_cipher contains both CCMP-128 and GCMP-256
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
        # db_value should be the first cipher (CCMP-128 = 4)
        assert pairwise_cipher.db_value == 4, (
            f"Expected db_value=4 (first cipher), got {pairwise_cipher.db_value}"
        )

    def test_gcmp256_not_present(self):
        """Test GCMP-256 not supported when only AES-CCMP is present"""
        p = profiler.Profiler()

        # RSN IE with AES-CCMP only
        mock_ie_dict = {
            48: bytes(
                [
                    0x01,
                    0x00,  # Version
                    0x00,
                    0x0F,
                    0xAC,
                    0x04,  # Group cipher: AES-CCMP
                    0x01,
                    0x00,  # Pairwise count: 1
                    0x00,
                    0x0F,
                    0xAC,
                    0x04,
                ]
            )  # Pairwise: AES-CCMP
        }

        capabilities = p.analyze_rsn_capabilities_ie(mock_ie_dict)

        # Check that neither group nor pairwise cipher contains GCMP-256
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

        # Check that group_cipher and pairwise_cipher show "Not reported" (RSN IE not present)
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

        # MLE with Type 0, no optional fields except MLD MAC
        mock_ie_dict = {
            255: [
                bytes(
                    [
                        107,  # Ext ID: MLE
                        0x00,
                        0x00,  # MLC Control: Type 0, no optional fields
                        0x11,
                        0x22,
                        0x33,
                        0x44,
                        0x55,
                        0x66,
                    ]
                )  # MLD MAC (6 bytes)
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

        # MLE Type 0 with MLD Capabilities
        # Control: Type 0, MLD Capa present (bit 8) = 0x0100
        # MLD Caps: Max Links=1 (0x0001), T2LM=1 (bits 5-6 = 0x0020), Link Reconfig=1 (bit 13 = 0x2000)
        # Combined: 0x0001 | 0x0020 | 0x2000 = 0x2021
        mock_ie_dict = {
            255: [
                bytes(
                    [
                        107,  # Ext ID
                        0x00,
                        0x01,  # MLC Control: Type 0, MLD Capa present
                        0x09,  # Common Info Length (9 bytes)
                        0x11,
                        0x22,
                        0x33,
                        0x44,
                        0x55,
                        0x66,  # MLD MAC
                        0x21,
                        0x20,
                    ]
                )  # MLD Caps: Max Links=1, T2LM=1, Reconfig=1
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

        # MLE Type 0 with EML Capabilities
        # Control: Type 0 (bits 0-2), EML present (bit 7) = 0x0080
        # EML Caps: EMLSR=1 (bit 0), Padding=2 (bits 1-3 = 0x0004), Trans=3 (bits 4-6 = 0x0030), EMLMR=1 (bit 7 = 0x0080)
        # Combined: 0x0001 | 0x0004 | 0x0030 | 0x0080 = 0x00B5
        mock_ie_dict = {
            255: [
                bytes(
                    [
                        107,  # Ext ID
                        0x80,
                        0x00,  # MLC Control: Type 0, EML Capa present
                        0x09,  # Common Info Length (9 bytes)
                        0x11,
                        0x22,
                        0x33,
                        0x44,
                        0x55,
                        0x66,  # MLD MAC
                        0xB5,
                        0x00,
                    ]
                )  # EML Caps: EMLSR=1, Padding=2, Trans=3, EMLMR=1
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

        assert emlsr_cap is not None and emlsr_cap.db_value == 1, "EMLSR should be 1"
        assert padding_cap is not None and padding_cap.db_value == 2, (
            f"Padding should be 2, got {padding_cap.db_value}"
        )
        assert transition_cap is not None and transition_cap.db_value == 3, (
            f"Transition should be 3, got {transition_cap.db_value}"
        )
        assert emlmr_cap is not None and emlmr_cap.db_value == 1, "EMLMR should be 1"

    def test_mle_not_present(self):
        """Test MLE returns 'Not reported' when MLE IE is missing"""
        p = profiler.Profiler()
        p.be_disabled = False

        # No MLE in IE dict
        mock_ie_dict = {
            255: [
                bytes([108, 0x00, 0x00]) + bytes([0x00] * 15)  # EHT, not MLE
            ]
        }

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

        # OnePlus11: Type 0, MLD Capa present, Max Links=1, T2LM=1, Reconfig=0
        # MLD Caps: Max Links=1 (0x0001), T2LM=1 (bit 5 set = 0x0020), Reconfig=0
        # Combined: 0x0021
        mock_ie_dict = {
            255: [
                bytes(
                    [
                        107,  # Ext ID
                        0x00,
                        0x01,  # MLC Control: Type 0, MLD Capa present (bit 8)
                        0x09,  # Common Info Length (9 bytes)
                        0x30,
                        0xBB,
                        0x7D,
                        0x4E,
                        0xC1,
                        0x2B,  # MLD MAC
                        0x21,
                        0x00,
                    ]
                )  # MLD Caps: Max Links=1, T2LM=1, Reconfig=0
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

        # MLE present
        assert mle_cap is not None and mle_cap.db_value == 1
        # Type 0
        assert type_cap is not None and type_cap.db_value == 0
        # Max Links = 1
        assert max_links_cap is not None and max_links_cap.db_value == 1
        # T2LM = 1
        assert t2lm_cap is not None and t2lm_cap.db_value == 1
        # Reconfig = 0
        assert reconfig_cap is not None and reconfig_cap.db_value == 0
        # EMLSR not reported (EML Caps not present)
        assert emlsr_cap is not None and emlsr_cap.db_value == -1
