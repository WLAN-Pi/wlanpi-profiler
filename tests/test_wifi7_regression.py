#!/usr/bin/env python3
"""
Wi-Fi 7 regression tests - pcap validation

This test suite validates our Wi-Fi 6E/7 capability detection against real
device pcap files. If the implementation changes, these tests will catch
any regressions.
"""

import pytest
from pathlib import Path
from scapy.all import rdpcap
from profiler import profiler


# Expected capabilities for each Wi-Fi 7 device
# These are the ACTUAL values detected from real device pcaps.

WIFI7_DEVICE_EXPECTED_CAPS = {
    "OnePlus11_Android15": {
        "chipset": "Qualcomm",
        "is_6ghz": False,
        "capabilities": {
            # Extended Capabilities
            "dot11aa_scs_support": 0,
            "qos_r1_mscs_support": -1,  # Not reported - ExtCap IE is only 10 bytes, need 11 for MSCS
            # EHT MAC
            "dot11be_epcs_support": 1,
            "dot11be_om_support": 1,
            "dot11be_rtwt_support": 0,
            "dot11be_scs_traffic_description_support": 0,
            # EHT PHY
            "dot11be_mcs15_support": 1,
            "dot11be_mcs14_support": 1,
            # RSNX
            "rsnx_sae_h2e": 1,
            # MLE
            "dot11be_mle": 1,
            "dot11be_mle_mlc_type": 0,
            "dot11be_mle_emlsr_support": -1,  # Not present
            "dot11be_mle_emlsr_padding_delay": -1,
            "dot11be_mle_emlsr_transition_delay": -1,
            "dot11be_mle_emlmr_support": -1,
            "dot11be_mle_max_simultaneous_links": 1,
            "dot11be_mle_t2lm_negotiation_support": 1,
            "dot11be_mle_link_reconfig_support": 0,
        },
    },
    "Pixel8_Android16": {
        "chipset": "Broadcom",
        "is_6ghz": False,
        "capabilities": {
            # Early Wi-Fi 7 device - has basic 11be but not all advanced features
            "dot11aa_scs_support": 0,
            "qos_r1_mscs_support": -1,  # Not reported - ExtCap IE is only 10 bytes, need 11 for MSCS
            "dot11be_epcs_support": 0,  # Not supported
            "dot11be_om_support": 1,
            "dot11be_rtwt_support": 0,
            "dot11be_scs_traffic_description_support": 0,
            "dot11be_mcs15_support": 0,  # Not supported
            "dot11be_mcs14_support": 0,  # Not supported
            "rsnx_sae_h2e": 1,
            "dot11be_mle": -1,  # No MLE support
            "dot11be_mle_mlc_type": -1,
            "dot11be_mle_emlsr_support": -1,
            "dot11be_mle_emlsr_padding_delay": -1,
            "dot11be_mle_emlsr_transition_delay": -1,
            "dot11be_mle_emlmr_support": -1,
            "dot11be_mle_max_simultaneous_links": -1,
            "dot11be_mle_t2lm_negotiation_support": -1,
            "dot11be_mle_link_reconfig_support": -1,
        },
    },
    "Surface_Laptop_7_ARM64_QCA_FC_7800": {
        "chipset": "Qualcomm",
        "is_6ghz": False,
        "capabilities": {
            "dot11aa_scs_support": 0,
            "qos_r1_mscs_support": 1,
            "dot11be_epcs_support": 1,
            "dot11be_om_support": 1,
            "dot11be_rtwt_support": 1,
            "dot11be_scs_traffic_description_support": 0,
            "dot11be_mcs15_support": 0,  # Not advertised in this frame
            "dot11be_mcs14_support": 1,
            "rsnx_sae_h2e": 1,
            "dot11be_mle": 1,
            "dot11be_mle_mlc_type": 0,
            "dot11be_mle_emlsr_support": -1,
            "dot11be_mle_emlsr_padding_delay": -1,
            "dot11be_mle_emlsr_transition_delay": -1,
            "dot11be_mle_emlmr_support": -1,
            "dot11be_mle_max_simultaneous_links": 1,
            "dot11be_mle_t2lm_negotiation_support": 1,
            "dot11be_mle_link_reconfig_support": 0,
        },
    },
    "Win11_AMD64_QCA_FC_7800": {
        "chipset": "Qualcomm",
        "is_6ghz": False,
        "capabilities": {
            "dot11aa_scs_support": 0,
            "qos_r1_mscs_support": 1,
            "dot11be_epcs_support": 1,
            "dot11be_om_support": 1,
            "dot11be_rtwt_support": 1,
            "dot11be_scs_traffic_description_support": 0,
            "dot11be_mcs15_support": 0,  # Not advertised in this frame
            "dot11be_mcs14_support": 1,
            "rsnx_sae_h2e": 1,
            "dot11be_mle": 1,
            "dot11be_mle_mlc_type": 0,
            "dot11be_mle_emlsr_support": -1,
            "dot11be_mle_emlsr_padding_delay": -1,
            "dot11be_mle_emlsr_transition_delay": -1,
            "dot11be_mle_emlmr_support": -1,
            "dot11be_mle_max_simultaneous_links": 1,
            "dot11be_mle_t2lm_negotiation_support": 1,
            "dot11be_mle_link_reconfig_support": 0,
        },
    },
    "Win11_Netgear_A9000_USB": {
        "chipset": "Mediatek",
        "is_6ghz": False,
        "capabilities": {
            # This device correctly reports the 4-bit MCS 15 MRU support value
            # per IEEE 802.11be-2024 spec (not just a boolean)
            "dot11aa_scs_support": 0,
            "qos_r1_mscs_support": 1,
            "dot11be_epcs_support": 0,
            "dot11be_om_support": 1,
            "dot11be_rtwt_support": 0,
            "dot11be_scs_traffic_description_support": 0,
            # Per IEEE 802.11be-2024 Table 9-417r:
            # Value 7 = 0b0111 means MCS 15 supported in:
            #   B0=1: 52+26 and 106+26-tone MRUs
            #   B1=1: 484+242-tone MRU (80 MHz)
            #   B2=1: 996+484+242-tone MRU (160 MHz)
            #   B3=0: NOT in 3×996-tone MRU (320 MHz)
            "dot11be_mcs15_support": 7,
            "dot11be_mcs14_support": 1,
            "rsnx_sae_h2e": 1,
            "dot11be_mle": -1,  # No MLE support
            "dot11be_mle_mlc_type": -1,
            "dot11be_mle_emlsr_support": -1,
            "dot11be_mle_emlsr_padding_delay": -1,
            "dot11be_mle_emlsr_transition_delay": -1,
            "dot11be_mle_emlmr_support": -1,
            "dot11be_mle_max_simultaneous_links": -1,
            "dot11be_mle_t2lm_negotiation_support": -1,
            "dot11be_mle_link_reconfig_support": -1,
        },
    },
}


class TestWiFi7DeviceRegression:
    """Regression tests using real Wi-Fi 7 device pcap files"""

    @pytest.mark.parametrize(
        "device_name",
        WIFI7_DEVICE_EXPECTED_CAPS.keys(),
        ids=lambda x: x.replace("_", " "),
    )
    def test_wifi7_device_capabilities(self, device_name):
        """
        Test capability detection against real Wi-Fi 7 device pcap.

        This is a regression test - if our implementation changes and breaks
        capability detection, this test will fail.

        Args:
            device_name: Name of the Wi-Fi 7 device (matches pcap filename)
        """
        pcap_path = Path(__file__).parent / "pcaps" / "wifi7" / f"{device_name}.pcapng"

        if not pcap_path.exists():
            pytest.skip(f"Pcap file not found: {pcap_path}")

        # Load expected values
        expected = WIFI7_DEVICE_EXPECTED_CAPS[device_name]

        # Run profiler
        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False

        # Note: analyze_assoc_req expects Profiler to have these attributes set
        # They are normally set during __init__ but we set them manually for testing

        cap = rdpcap(str(pcap_path))
        _, _, _, capabilities = p.analyze_assoc_req(cap[0], expected["is_6ghz"])

        # Convert to dict
        cap_dict = {c.db_key: c.db_value for c in capabilities if c.db_key}

        # Validate each expected capability
        failures = []
        for cap_key, expected_val in expected["capabilities"].items():
            actual_val = cap_dict.get(cap_key)

            if actual_val is None:
                failures.append(f"  ❌ {cap_key}: MISSING (expected {expected_val})")
            elif actual_val != expected_val:
                # Special case: MCS 15 can have different values (1, 7, 15, etc.)
                # as long as it's non-zero when expected non-zero
                if (
                    cap_key == "dot11be_mcs15_support"
                    and expected_val > 0
                    and actual_val > 0
                ):
                    continue  # Accept any non-zero value

                failures.append(
                    f"  ❌ {cap_key}: expected {expected_val}, got {actual_val}"
                )

        # Validate GCMP-256 support (now in cipher capabilities, not standalone)
        # All Wi-Fi 7 devices in our test suite support GCMP-256
        group_cipher_cap = next(
            (c for c in capabilities if c.db_key == "group_cipher"), None
        )
        pairwise_cipher_cap = next(
            (c for c in capabilities if c.db_key == "pairwise_cipher"), None
        )

        has_gcmp256 = False
        if group_cipher_cap and "GCMP-256" in str(group_cipher_cap.value):
            has_gcmp256 = True
        if pairwise_cipher_cap and "GCMP-256" in str(pairwise_cipher_cap.value):
            has_gcmp256 = True

        if not has_gcmp256:
            failures.append(
                "  ❌ GCMP-256: Not found in group_cipher or pairwise_cipher capabilities"
            )

        # Report results
        if failures:
            pytest.fail(
                f"\n{device_name} ({expected['chipset']}) - Capability mismatches:\n"
                + "\n".join(failures)
            )

        print(f"\n✅ {device_name} ({expected['chipset']}) - All capabilities match!")

    def test_netgear_a9000_mcs15_spec_value(self):
        """
        Validate Netgear A9000 MCS 15 value matches IEEE 802.11be-2024 spec.

        Per IEEE 802.11be-2024 Table 9-417r, page 262-263:
        Field: "Support Of EHT-MCS 15 In MRU"
        Bits: B51-B54 (4 bits)
        Mask: 0x007800

        Value 7 (0b0111) means:
        - B0=1: MCS 15 in 52+26 and 106+26-tone MRUs
        - B1=1: MCS 15 in 484+242-tone MRU (80 MHz)
        - B2=1: MCS 15 in 996+484+242-tone MRU (160 MHz)
        - B3=0: NOT in 3×996-tone MRU (320 MHz)

        This test ensures we extract the full 4-bit value, not just a boolean.
        """
        pcap_path = (
            Path(__file__).parent / "pcaps" / "wifi7" / "Win11_Netgear_A9000_USB.pcapng"
        )

        if not pcap_path.exists():
            pytest.skip("Netgear A9000 pcap not found")

        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False

        cap = rdpcap(str(pcap_path))
        _, _, _, capabilities = p.analyze_assoc_req(cap[0], False)

        mcs15_cap = next(
            (c for c in capabilities if c.db_key == "dot11be_mcs15_support"), None
        )

        assert mcs15_cap is not None, "MCS 15 capability not found"
        assert mcs15_cap.db_value == 7, (
            f"IEEE 802.11be-2024 spec requires value 7 for Netgear A9000, "
            f"got {mcs15_cap.db_value}"
        )

    def test_mle_common_info_length_parsing(self):
        """
        Validate MLE Common Info Length field is correctly parsed.

        Per IEEE 802.11be-2024 Figure 9-1074p, page 233:
        - Byte 0: Extension ID (107)
        - Bytes 1-2: Multi-Link Control
        - Byte 3: Common Info Length (includes itself)
        - Bytes 4+: Common Info fields (MLD MAC, etc.)

        This test ensures byte 3 is recognized as the length field.
        """
        pcap_path = (
            Path(__file__).parent / "pcaps" / "wifi7" / "OnePlus11_Android15.pcapng"
        )

        if not pcap_path.exists():
            pytest.skip("OnePlus 11 pcap not found")

        p = profiler.Profiler()
        p.ft_disabled = False
        p.he_disabled = False
        p.be_disabled = False

        cap = rdpcap(str(pcap_path))
        _, _, _, capabilities = p.analyze_assoc_req(cap[0], False)

        # If Common Info Length is incorrect, MLC Type parsing will fail
        mle_cap = next((c for c in capabilities if c.db_key == "dot11be_mle"), None)
        mlc_type = next(
            (c for c in capabilities if c.db_key == "dot11be_mle_mlc_type"), None
        )

        assert mle_cap is not None and mle_cap.db_value == 1, "MLE not detected"
        assert mlc_type is not None and mlc_type.db_value == 0, (
            "MLC Type should be 0 (Basic) if Common Info Length is correctly parsed"
        )

    def test_all_17_capabilities_detected(self):
        """
        Verify all 17 Wi-Fi 6E/7 capabilities are detected in at least one device.

        This ensures complete implementation coverage.

        Note: GCMP-256 is now part of cipher capabilities (group_cipher/pairwise_cipher)
        rather than a standalone capability, so it's validated separately.
        """
        all_caps = {
            "dot11aa_scs_support",
            "qos_r1_mscs_support",
            "dot11be_epcs_support",
            "dot11be_om_support",
            "dot11be_rtwt_support",
            "dot11be_scs_traffic_description_support",
            "dot11be_mcs15_support",
            "dot11be_mcs14_support",
            "rsnx_sae_h2e",
            "dot11be_mle",
            "dot11be_mle_mlc_type",
            "dot11be_mle_emlsr_support",
            "dot11be_mle_emlsr_padding_delay",
            "dot11be_mle_emlsr_transition_delay",
            "dot11be_mle_emlmr_support",
            "dot11be_mle_max_simultaneous_links",
            "dot11be_mle_t2lm_negotiation_support",
            "dot11be_mle_link_reconfig_support",
        }

        detected_caps = set()
        gcmp256_detected = False

        for device_name in WIFI7_DEVICE_EXPECTED_CAPS:
            pcap_path = (
                Path(__file__).parent / "pcaps" / "wifi7" / f"{device_name}.pcapng"
            )

            if not pcap_path.exists():
                continue

            p = profiler.Profiler()
            p.ft_disabled = False
            p.he_disabled = False
            p.be_disabled = False

            cap = rdpcap(str(pcap_path))
            _, _, _, capabilities = p.analyze_assoc_req(cap[0], False)

            for c in capabilities:
                if c.db_key and c.db_key in all_caps:
                    detected_caps.add(c.db_key)
                # Check for GCMP-256 in cipher capabilities
                if c.db_key in ("group_cipher", "pairwise_cipher"):
                    if "GCMP-256" in str(c.value):
                        gcmp256_detected = True

        missing = all_caps - detected_caps

        if missing:
            pytest.fail(
                "Some capabilities never detected in test devices:\n"
                + "\n".join(f"  - {cap}" for cap in sorted(missing))
            )

        if not gcmp256_detected:
            pytest.fail("GCMP-256 cipher not detected in any test device")

        print("\n✅ All 17 Wi-Fi 6E/7 capabilities detected across test devices")
        print("✅ GCMP-256 cipher capability detected")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
