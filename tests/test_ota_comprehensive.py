# -*- coding: utf-8 -*-

"""
Comprehensive OTA Test Suite - Consolidated tests for all modes and CLI arguments

This test suite consolidates OTA testing to minimize execution time while
providing comprehensive coverage of all profiler modes and CLI arguments.

Instead of running separate tests for each feature, we combine multiple
validations per beacon capture to reduce the ~25-second overhead per test.
"""

import os
import subprocess
import pytest
from scapy.layers.dot11 import Dot11Elt

# Import helpers from existing test file
import sys

sys.path.insert(0, os.path.dirname(__file__))
from test_ota_beacons import BeaconCapture, RemoteProfilerRunner

pytestmark = pytest.mark.skipif(
    os.getenv("PROFILER_OTA_TESTS") != "1",
    reason="OTA tests disabled (set PROFILER_OTA_TESTS=1 to enable)",
)


@pytest.fixture
def ota_interface():
    """Get local OTA test interface from environment"""
    iface = os.getenv("PROFILER_OTA_INTERFACE", "wlu1u3")
    channel = int(os.getenv("PROFILER_REMOTE_CHANNEL", "36"))

    try:
        result = subprocess.run(
            ["iw", "dev", iface, "info"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        pytest.skip(f"Interface {iface} not found on localhost")

    try:
        subprocess.run(
            ["sudo", "ip", "link", "set", iface, "down"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "iw", "dev", iface, "set", "type", "monitor"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", iface, "up"], check=True, capture_output=True
        )
        subprocess.run(
            ["sudo", "iw", "dev", iface, "set", "channel", str(channel)],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        pytest.skip(f"Failed to configure {iface} for monitor mode: {e}")

    return iface


@pytest.fixture
def remote_host():
    """Get remote WLAN Pi SSH target from environment"""
    return os.getenv("PROFILER_REMOTE_HOST", "wlanpi@198.18.42.1")


@pytest.fixture
def test_channel():
    """Get test channel from environment"""
    return int(os.getenv("PROFILER_REMOTE_CHANNEL", "36"))


class TestComprehensiveModeAndArgs:
    """
    Consolidated tests covering all modes and CLI arguments

    Each test validates MULTIPLE features in a single beacon capture to
    minimize the overhead of starting/stopping profiler (~25s per test).
    """

    @pytest.mark.parametrize(
        "mode,security,expect_eht,expect_ft,passphrase",
        [
            # AP mode security tests
            ("ap", "wpa2", False, False, "profiler"),
            ("ap", "ft-wpa2", False, True, "profiler"),
            ("ap", "wpa3-mixed", True, False, "Custom123"),
            ("ap", "ft-wpa3-mixed", True, True, "Test@Pass1"),
            # FakeAP mode security tests
            ("fakeap", "wpa2", False, False, "profiler"),
            ("fakeap", "ft-wpa2", False, True, "profiler"),
            ("fakeap", "wpa3-mixed", True, False, "EightChr"),
            ("fakeap", "ft-wpa3-mixed", True, True, "a" * 63),  # Max length
        ],
    )
    def test_mode_security_passphrase_vendor_ie(
        self,
        ota_interface,
        remote_host,
        test_channel,
        mode,
        security,
        expect_eht,
        expect_ft,
        passphrase,
    ):
        """
        Comprehensive test validating in single beacon capture:
        - Mode (AP vs FakeAP)
        - Security mode (WPA2/FT/WPA3)
        - Passphrase (custom passphrases work)
        - Vendor IE (present by default)
        - PHY capabilities (HT/VHT/HE/EHT based on security)
        - FT Mobility Domain IE
        - Cipher suites
        """
        ssid = f"OTA-{mode[:2]}-{security[:4]}"  # Keep under 32 chars
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(
                security_mode=security,
                fakeap=is_fakeap,
                extra_args=["--passphrase", passphrase],
            )
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for {mode}/{security}"
            beacon = beacons[0]

            # Validate: Custom passphrase works (profiler started successfully)
            # We can't verify passphrase OTA, but successful beacon = passphrase accepted

            # Validate: Security mode AKMs
            if security == "wpa2":
                assert BeaconCapture.verify_rsn_akm(beacon, ["PSK"])
            elif security == "ft-wpa2":
                assert BeaconCapture.verify_rsn_akm(beacon, ["PSK", "FT-PSK"])
            elif security == "wpa3-mixed":
                assert BeaconCapture.verify_rsn_akm(beacon, ["PSK", "SAE"])
            elif security == "ft-wpa3-mixed":
                assert BeaconCapture.verify_rsn_akm(
                    beacon, ["PSK", "FT-PSK", "SAE", "FT-SAE"]
                )

            # Validate: Ciphers
            if "wpa3" in security:
                assert BeaconCapture.verify_rsn_ciphers(beacon, ["CCMP", "GCMP-256"])
            else:
                assert BeaconCapture.verify_rsn_ciphers(beacon, ["CCMP"])

            # Validate: FT/Mobility Domain
            assert BeaconCapture.has_mobility_domain(beacon) == expect_ft

            # Validate: PHY capabilities
            assert BeaconCapture.has_ht_capabilities(beacon), "Missing HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Missing VHT"
            assert BeaconCapture.has_he_capabilities(beacon), "Missing HE"
            assert BeaconCapture.has_eht_capabilities(beacon) == expect_eht

            # Validate: Vendor IE present by default
            assert BeaconCapture.has_profiler_vendor_ie(beacon), "Missing vendor IE"
            assert BeaconCapture.verify_profiler_vendor_ie_content(beacon), (
                "Invalid vendor IE"
            )

        except Exception:
            log_output = runner.stop()
            print(f"\nRemote profiler log:\n{log_output}")
            raise
        finally:
            try:
                runner.stop()
            except Exception:
                pass

    @pytest.mark.parametrize(
        "mode,phy_flags,expect_he,expect_eht",
        [
            ("ap", [], True, True),  # Default: all enabled
            ("ap", ["--no11ax"], False, False),  # --no11ax disables both HE and EHT
            ("ap", ["--no11be"], True, False),  # --no11be disables only EHT
            ("fakeap", [], True, True),  # Default: all enabled
            ("fakeap", ["--no11ax"], False, False),
            ("fakeap", ["--no11be"], True, False),
        ],
    )
    def test_mode_phy_flags_noprofilertlv(
        self,
        ota_interface,
        remote_host,
        test_channel,
        mode,
        phy_flags,
        expect_he,
        expect_eht,
    ):
        """
        Comprehensive test validating in single beacon capture:
        - PHY flags (--no11ax, --no11be)
        - --noprofilertlv flag (vendor IE absent)
        - IE structure validation
        """
        ssid = f"OTA-{mode[:2]}-PHY"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        extra_args = phy_flags + ["--noprofilertlv"]

        try:
            runner.start(
                security_mode="ft-wpa3-mixed",
                fakeap=is_fakeap,
                extra_args=extra_args,
            )
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, "No beacons captured"
            beacon = beacons[0]

            # Validate: PHY capabilities based on flags
            assert BeaconCapture.has_ht_capabilities(beacon), "Missing HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Missing VHT"
            assert BeaconCapture.has_he_capabilities(beacon) == expect_he
            assert BeaconCapture.has_eht_capabilities(beacon) == expect_eht

            # Validate: Vendor IE absent due to --noprofilertlv
            assert not BeaconCapture.has_profiler_vendor_ie(beacon), (
                "Vendor IE should be absent"
            )

            # Validate: All IEs parse correctly
            elt = beacon.getlayer(Dot11Elt)
            ie_count = 0
            while elt:
                ie_count += 1
                assert hasattr(elt, "ID"), f"IE {ie_count} missing ID"
                assert hasattr(elt, "len"), f"IE {ie_count} missing len"
                assert hasattr(elt, "info"), f"IE {ie_count} missing info"
                elt = elt.payload.getlayer(Dot11Elt)

        except Exception:
            log_output = runner.stop()
            print(f"\nRemote profiler log:\n{log_output}")
            raise
        finally:
            try:
                runner.stop()
            except Exception:
                pass

    @pytest.mark.parametrize("mode", ["ap", "fakeap"])
    def test_mode_hostname_ssid(
        self,
        ota_interface,
        remote_host,
        test_channel,
        mode,
    ):
        """
        Test --hostname_ssid flag in both modes

        Validates:
        - --hostname_ssid uses hostname as SSID
        - Profiler starts and beacons successfully
        """
        # Get remote hostname
        hostname_cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            remote_host,
            "hostname",
        ]
        result = subprocess.run(
            hostname_cmd, capture_output=True, text=True, timeout=10
        )
        expected_ssid = result.stdout.strip()

        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid="IGNORED"
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(
                security_mode="wpa2",
                fakeap=is_fakeap,
                extra_args=["--hostname_ssid"],
            )

            # Capture beacons with hostname as SSID
            beacons = capture.capture(ssid=expected_ssid, count=3)

            assert len(beacons) >= 1, f"No beacons with hostname SSID '{expected_ssid}'"

        except Exception:
            log_output = runner.stop()
            print(f"\nRemote profiler log:\n{log_output}")
            raise
        finally:
            try:
                runner.stop()
            except Exception:
                pass

    @pytest.mark.parametrize("mode", ["ap", "fakeap"])
    def test_mode_wpa2_11be_override(
        self,
        ota_interface,
        remote_host,
        test_channel,
        mode,
    ):
        """
        Test --11be override with WPA2 (non-standard configuration)

        Validates:
        - --11be flag overrides auto-disable for WPA2
        - All PHY features present (HT/VHT/HE/EHT)
        - Warning logged about non-standard config
        """
        ssid = f"OTA-{mode[:2]}-11be"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(
                security_mode="wpa2",
                fakeap=is_fakeap,
                extra_args=["--11be"],
            )
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, "No beacons captured"
            beacon = beacons[0]

            # Validate: All PHY present with override
            assert BeaconCapture.has_ht_capabilities(beacon)
            assert BeaconCapture.has_vht_capabilities(beacon)
            assert BeaconCapture.has_he_capabilities(beacon)
            assert BeaconCapture.has_eht_capabilities(beacon), "--11be override failed"

            # Validate: Warning logged
            log_output = runner.stop()
            assert "Enabling 802.11be with security_mode 'wpa2'" in log_output

        finally:
            try:
                runner.stop()
            except Exception:
                pass

    @pytest.mark.parametrize("mode", ["ap", "fakeap"])
    def test_mode_ie_structures(
        self,
        ota_interface,
        remote_host,
        test_channel,
        mode,
    ):
        """
        Comprehensive IE structure validation in single beacon capture

        Validates:
        - HT Capabilities (26 bytes fixed)
        - VHT Capabilities (12 bytes fixed)
        - HE Capabilities (>= 22 bytes)
        - HE Operation (>= 7 bytes)
        - EHT Capabilities (>= 12 bytes)
        - RSN IE (>= 20 bytes)
        - All IE length fields match actual data
        """
        ssid = f"OTA-{mode[:2]}-IE"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(security_mode="ft-wpa3-mixed", fakeap=is_fakeap)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, "No beacons captured"
            beacon = beacons[0]

            # Validate HT Capabilities
            ht_cap = BeaconCapture.get_ie(beacon, 0x2D)
            assert ht_cap is not None, "HT Capabilities missing"
            assert len(ht_cap.info) == 26, (
                f"HT Capabilities wrong length: {len(ht_cap.info)}"
            )

            # Validate VHT Capabilities
            vht_cap = BeaconCapture.get_ie(beacon, 0xBF)
            assert vht_cap is not None, "VHT Capabilities missing"
            assert len(vht_cap.info) == 12, (
                f"VHT Capabilities wrong length: {len(vht_cap.info)}"
            )

            # Validate HE Capabilities
            he_cap = None
            elt = beacon.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0xFF and len(elt.info) > 0 and elt.info[0] == 0x23:
                    he_cap = elt
                    break
                elt = elt.payload.getlayer(Dot11Elt)
            assert he_cap is not None, "HE Capabilities missing"
            assert len(he_cap.info) >= 22, (
                f"HE Capabilities too short: {len(he_cap.info)}"
            )

            # Validate HE Operation
            he_op = None
            elt = beacon.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0xFF and len(elt.info) > 0 and elt.info[0] == 0x24:
                    he_op = elt
                    break
                elt = elt.payload.getlayer(Dot11Elt)
            assert he_op is not None, "HE Operation missing"
            assert len(he_op.info) >= 7, f"HE Operation too short: {len(he_op.info)}"

            # Validate EHT Capabilities
            eht_cap = None
            elt = beacon.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0xFF and len(elt.info) > 0 and elt.info[0] == 0x6C:
                    eht_cap = elt
                    break
                elt = elt.payload.getlayer(Dot11Elt)
            assert eht_cap is not None, "EHT Capabilities missing"
            assert len(eht_cap.info) >= 12, (
                f"EHT Capabilities too short: {len(eht_cap.info)}"
            )

            # Validate RSN IE
            rsn = BeaconCapture.get_ie(beacon, 0x30)
            assert rsn is not None, "RSN IE missing"
            assert len(rsn.info) >= 20, f"RSN IE too short: {len(rsn.info)}"

        except Exception:
            log_output = runner.stop()
            print(f"\nRemote profiler log:\n{log_output}")
            raise
        finally:
            try:
                runner.stop()
            except Exception:
                pass


class TestRSNXIE:
    """Test RSNX IE (WPA3 SAE H2E support signaling)"""

    def test_rsnx_wpa3_only(self, ota_interface, remote_host, test_channel):
        """
        RSNX IE must be present for WPA3

        Note: Modern hostapd may also include RSNX in WPA2 mode, which is not
        strictly incorrect. This test only validates WPA3 has RSNX.
        """
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        # Test WPA3 has RSNX
        ssid_wpa3 = "OTA-RSNX-WPA3"
        runner_wpa3 = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid_wpa3
        )

        try:
            runner_wpa3.start(security_mode="wpa3-mixed")
            beacons_wpa3 = capture.capture(ssid=ssid_wpa3, count=3)
            assert len(beacons_wpa3) >= 1
            assert BeaconCapture.has_rsnx_ie(beacons_wpa3[0]), "RSNX missing in WPA3"
        finally:
            runner_wpa3.stop()
