# -*- coding: utf-8 -*-

"""
OTA Beacon Verification Tests for 4 SS and 160 MHz Advertising

These tests verify that the profiler correctly advertises:
- 4 spatial streams across all technologies (HT/VHT/HE/EHT)
- 160 MHz capability in VHT and HE
- While operating at 80 MHz on channel 36

Architecture:
- Localhost (verification device): Captures beacons using monitor mode interface
- Remote WLAN Pi (test device): Runs profiler in AP mode
- SSH used to control remote profiler instance

Requirements:
- Localhost: Wi-Fi adapter in monitor mode (e.g., wlu1u3)
- Remote WLAN Pi: SSH access to wlanpi@198.18.42.1
- Set PROFILER_OTA_TESTS=1 environment variable to enable

Usage:
    PROFILER_OTA_TESTS=1 PROFILER_OTA_INTERFACE=wlu1u3 \
    PROFILER_REMOTE_HOST=wlanpi@198.18.42.1 \
    PROFILER_REMOTE_CHANNEL=36 \
    pytest tests/test_ota_4ss_160mhz.py -v

Environment Variables:
    PROFILER_OTA_TESTS=1                    Enable OTA tests
    PROFILER_OTA_INTERFACE=wlu1u3           Local monitor interface (default: wlu1u3)
    PROFILER_REMOTE_HOST=wlanpi@198.18.42.1 Remote SSH target (default: wlanpi@198.18.42.1)
    PROFILER_REMOTE_CHANNEL=36              Channel to test on (default: 36 for 5GHz)
"""

import os
import subprocess
import time
from typing import Dict, List, Optional

import pytest
from scapy.all import Dot11Beacon, Dot11Elt, sniff

# Skip all tests in this file unless OTA testing is explicitly enabled
pytestmark = pytest.mark.skipif(
    os.getenv("PROFILER_OTA_TESTS") != "1",
    reason="OTA tests disabled (set PROFILER_OTA_TESTS=1 to enable)",
)


class BeaconAnalyzer:
    """Utility for capturing and analyzing 802.11 beacons for 4 SS and 160 MHz"""

    def __init__(self, interface: str, timeout: int = 10):
        """
        Initialize beacon analyzer

        Args:
            interface: Monitor mode interface to capture on (e.g., 'wlu1u3')
            timeout: Maximum time to capture in seconds
        """
        self.interface = interface
        self.timeout = timeout
        self.beacons: List[Dot11Beacon] = []

    def capture_beacon(self, ssid: str, count: int = 3) -> Optional[Dot11Beacon]:
        """
        Capture beacon for specified SSID

        Args:
            ssid: SSID to filter for
            count: Number of beacons to capture

        Returns:
            First captured beacon frame or None
        """
        self.beacons = []
        filter_str = "type mgt subtype beacon"

        def ssid_filter(pkt):
            if pkt.haslayer(Dot11Beacon):
                try:
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 0:  # SSID element
                            if elt.info.decode("utf-8", errors="ignore") == ssid:
                                self.beacons.append(pkt)
                                if len(self.beacons) >= count:
                                    return True  # Stop capture
                        elt = elt.payload.getlayer(Dot11Elt)
                except Exception:
                    pass
            return False

        try:
            sniff(
                iface=self.interface,
                prn=ssid_filter,
                filter=filter_str,
                timeout=self.timeout,
                store=False,
            )
        except Exception as e:
            pytest.fail(f"Failed to capture on {self.interface}: {e}")

        return self.beacons[0] if self.beacons else None

    @staticmethod
    def get_ie(beacon: Dot11Beacon, ie_id: int) -> Optional[bytes]:
        """
        Extract Information Element from beacon by ID

        Args:
            beacon: Beacon frame
            ie_id: IE identifier (e.g., 0x2D for HT Capabilities)

        Returns:
            IE info bytes if found, None otherwise
        """
        elt = beacon.getlayer(Dot11Elt)
        while elt:
            if elt.ID == ie_id:
                return bytes(elt.info)
            elt = elt.payload.getlayer(Dot11Elt)
        return None

    @staticmethod
    def get_extension_ie(beacon: Dot11Beacon, ext_id: int) -> Optional[bytes]:
        """
        Extract Extension IE from beacon by extension ID

        Args:
            beacon: Beacon frame
            ext_id: Extension IE identifier (e.g., 0x23 for HE, 0x6C for EHT)

        Returns:
            Extension IE info bytes if found, None otherwise
        """
        elt = beacon.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 255 and len(elt.info) > 0:  # Extension IE
                if elt.info[0] == ext_id:
                    return bytes(elt.info)
            elt = elt.payload.getlayer(Dot11Elt)
        return None

    @staticmethod
    def verify_ht_4ss(beacon: Dot11Beacon) -> Dict[str, any]:
        """
        Verify HT (802.11n) advertises 4 spatial streams

        Args:
            beacon: Beacon frame

        Returns:
            Dict with verification results
        """
        ht_cap = BeaconAnalyzer.get_ie(beacon, 0x2D)  # HT Capabilities IE
        if not ht_cap or len(ht_cap) < 26:
            return {
                "present": False,
                "error": "HT Capabilities IE not found or too short",
            }

        # MCS Set is at offset 3-18 (16 bytes)
        mcs_set = ht_cap[3:19]

        # For 4 SS, bytes 0-3 should be 0xff (MCS 0-31)
        ss1_mcs = mcs_set[0]  # MCS 0-7 (SS1)
        ss2_mcs = mcs_set[1]  # MCS 8-15 (SS2)
        ss3_mcs = mcs_set[2]  # MCS 16-23 (SS3)
        ss4_mcs = mcs_set[3]  # MCS 24-31 (SS4)

        return {
            "present": True,
            "ss1_mcs": ss1_mcs == 0xFF,
            "ss2_mcs": ss2_mcs == 0xFF,
            "ss3_mcs": ss3_mcs == 0xFF,
            "ss4_mcs": ss4_mcs == 0xFF,
            "advertises_4ss": all(
                [
                    ss1_mcs == 0xFF,
                    ss2_mcs == 0xFF,
                    ss3_mcs == 0xFF,
                    ss4_mcs == 0xFF,
                ]
            ),
        }

    @staticmethod
    def verify_vht_4ss_and_160mhz(beacon: Dot11Beacon) -> Dict[str, any]:
        """
        Verify VHT (802.11ac) advertises 4 SS and 160 MHz capability

        Args:
            beacon: Beacon frame

        Returns:
            Dict with verification results
        """
        vht_cap = BeaconAnalyzer.get_ie(beacon, 0xBF)  # VHT Capabilities IE
        if not vht_cap or len(vht_cap) < 12:
            return {
                "present": False,
                "error": "VHT Capabilities IE not found or too short",
            }

        # VHT Capabilities Info (4 bytes)
        vht_cap_info = int.from_bytes(vht_cap[0:4], "little")

        # Supported Channel Width Set (bits 2-3)
        # 0 = No 160 MHz or 80+80 MHz support
        # 1 = 160 MHz support
        # 2 = 160 MHz and 80+80 MHz support
        chan_width_set = (vht_cap_info >> 2) & 0x3
        supports_160mhz = chan_width_set in [1, 2]

        # VHT Supported MCS Set (8 bytes starting at offset 4)
        rx_mcs_map = int.from_bytes(vht_cap[4:6], "little")
        tx_mcs_map = int.from_bytes(vht_cap[6:8], "little")

        # Each 2 bits represents one SS (0b10 = MCS 0-9, 0b11 = Not supported)
        # For 4 SS: 0xffaa (SS 1-4: 0b10, SS 5-8: 0b11)
        def check_ss_support(mcs_map):
            ss_support = []
            for i in range(8):
                ss_bits = (mcs_map >> (i * 2)) & 0x3
                ss_support.append(
                    {
                        "ss": i + 1,
                        "supported": ss_bits != 0x3,
                        "mcs_range": "0-9"
                        if ss_bits == 0x2
                        else "0-7"
                        if ss_bits == 0x1
                        else "none",
                    }
                )
            return ss_support

        rx_ss = check_ss_support(rx_mcs_map)
        advertises_4ss = all(ss["supported"] for ss in rx_ss[:4]) and all(
            not ss["supported"] for ss in rx_ss[4:]
        )

        return {
            "present": True,
            "supports_160mhz": supports_160mhz,
            "chan_width_set": chan_width_set,
            "rx_mcs_map": f"0x{rx_mcs_map:04x}",
            "tx_mcs_map": f"0x{tx_mcs_map:04x}",
            "rx_ss_support": rx_ss,
            "advertises_4ss": advertises_4ss,
        }

    @staticmethod
    def verify_he_4ss_and_160mhz(beacon: Dot11Beacon) -> Dict[str, any]:
        """
        Verify HE (802.11ax) advertises 4 SS and 160 MHz capability

        Args:
            beacon: Beacon frame

        Returns:
            Dict with verification results
        """
        he_cap = BeaconAnalyzer.get_extension_ie(
            beacon, 0x23
        )  # HE Capabilities extension IE
        if not he_cap or len(he_cap) < 22:
            return {
                "present": False,
                "error": "HE Capabilities IE not found or too short",
            }

        # Skip extension ID (1 byte), MAC caps (6 bytes), PHY caps (11 bytes minimum)
        # Channel Width Set is in PHY capabilities byte 0 (offset 7)
        phy_cap_0 = he_cap[7]

        # Bits 1-2 are channel width set
        # Bit 1: 40 MHz in 2.4 GHz
        # Bit 2: 40 & 80 MHz in 5 GHz
        # Bit 3: 160 MHz in 5 GHz
        supports_160mhz = (phy_cap_0 & 0x08) != 0

        # HE MCS/NSS maps start after MAC caps (6 bytes) + PHY caps (11 bytes) = offset 18
        # For <= 80 MHz: 4 bytes (Rx 2 bytes, Tx 2 bytes)
        # For 160 MHz: 4 bytes (if supported)

        if len(he_cap) < 22:
            return {
                "present": True,
                "supports_160mhz": supports_160mhz,
                "error": "HE Capabilities too short for MCS maps",
            }

        rx_mcs_80 = int.from_bytes(he_cap[18:20], "little")
        tx_mcs_80 = int.from_bytes(he_cap[20:22], "little")

        # Each 2 bits represents one SS (0b10 = MCS 0-11, 0b11 = Not supported)
        # For 4 SS: 0xffaa (SS 1-4: 0b10, SS 5-8: 0b11)
        def check_ss_support(mcs_map):
            ss_support = []
            for i in range(8):
                ss_bits = (mcs_map >> (i * 2)) & 0x3
                ss_support.append(
                    {
                        "ss": i + 1,
                        "supported": ss_bits != 0x3,
                        "mcs_range": "0-11"
                        if ss_bits == 0x2
                        else "0-7"
                        if ss_bits == 0x1
                        else "none",
                    }
                )
            return ss_support

        rx_ss_80 = check_ss_support(rx_mcs_80)
        advertises_4ss_80 = all(ss["supported"] for ss in rx_ss_80[:4]) and all(
            not ss["supported"] for ss in rx_ss_80[4:]
        )

        result = {
            "present": True,
            "supports_160mhz": supports_160mhz,
            "rx_mcs_80": f"0x{rx_mcs_80:04x}",
            "tx_mcs_80": f"0x{tx_mcs_80:04x}",
            "rx_ss_80_support": rx_ss_80,
            "advertises_4ss_80": advertises_4ss_80,
        }

        # Check 160 MHz MCS map if present
        if len(he_cap) >= 26 and supports_160mhz:
            rx_mcs_160 = int.from_bytes(he_cap[22:24], "little")
            tx_mcs_160 = int.from_bytes(he_cap[24:26], "little")
            rx_ss_160 = check_ss_support(rx_mcs_160)
            advertises_4ss_160 = all(ss["supported"] for ss in rx_ss_160[:4]) and all(
                not ss["supported"] for ss in rx_ss_160[4:]
            )

            result.update(
                {
                    "rx_mcs_160": f"0x{rx_mcs_160:04x}",
                    "tx_mcs_160": f"0x{tx_mcs_160:04x}",
                    "rx_ss_160_support": rx_ss_160,
                    "advertises_4ss_160": advertises_4ss_160,
                }
            )

        return result

    @staticmethod
    def verify_eht_4ss(beacon: Dot11Beacon) -> Dict[str, any]:
        """
        Verify EHT (802.11be) advertises 4 spatial streams

        Args:
            beacon: Beacon frame

        Returns:
            Dict with verification results
        """
        eht_cap = BeaconAnalyzer.get_extension_ie(
            beacon, 0x6C
        )  # EHT Capabilities extension IE
        if not eht_cap or len(eht_cap) < 10:
            return {
                "present": False,
                "error": "EHT Capabilities IE not found or too short",
            }

        # EHT MCS/NSS map format is more complex
        # After extension ID (1 byte) + MAC caps (2 bytes) + PHY caps (9 bytes) = offset 12
        # MCS map: 3 bytes per bandwidth
        # Each nibble (4 bits) represents max NSS-1 for specific MCS range

        if len(eht_cap) < 15:
            return {
                "present": True,
                "error": "EHT Capabilities too short for MCS maps",
            }

        # BW <= 80 MHz MCS map (3 bytes starting at offset 12)
        mcs_map_80 = int.from_bytes(eht_cap[12:15], "little")

        # Extract NSS values (each 4 bits, value is NSS-1)
        # Byte 0: Rx MCS 0-9 (lower nibble), Tx MCS 0-9 (upper nibble)
        # Byte 1: Rx MCS 10-11 (lower nibble), Tx MCS 10-11 (upper nibble)
        # Byte 2: Rx MCS 12-13 (lower nibble), Tx MCS 12-13 (upper nibble)

        rx_nss_0_9 = (mcs_map_80 & 0xF) + 1 if (mcs_map_80 & 0xF) != 0xF else 0
        tx_nss_0_9 = (
            ((mcs_map_80 >> 4) & 0xF) + 1 if ((mcs_map_80 >> 4) & 0xF) != 0xF else 0
        )
        rx_nss_10_11 = (
            ((mcs_map_80 >> 8) & 0xF) + 1 if ((mcs_map_80 >> 8) & 0xF) != 0xF else 0
        )
        tx_nss_10_11 = (
            ((mcs_map_80 >> 12) & 0xF) + 1 if ((mcs_map_80 >> 12) & 0xF) != 0xF else 0
        )

        advertises_4ss = (
            rx_nss_0_9 == 4
            and tx_nss_0_9 == 4
            and rx_nss_10_11 == 4
            and tx_nss_10_11 == 4
        )

        return {
            "present": True,
            "mcs_map_80": f"0x{mcs_map_80:06x}",
            "rx_nss_mcs_0_9": rx_nss_0_9,
            "tx_nss_mcs_0_9": tx_nss_0_9,
            "rx_nss_mcs_10_11": rx_nss_10_11,
            "tx_nss_mcs_10_11": tx_nss_10_11,
            "advertises_4ss": advertises_4ss,
        }


class RemoteProfilerController:
    """Control profiler on remote WLAN Pi via SSH"""

    def __init__(self, remote_host: str = "wlanpi@198.18.42.1"):
        self.remote_host = remote_host
        self.pid: Optional[int] = None

    def start(
        self,
        ssid: str,
        channel: int = 36,
        passphrase: str = "WLAN PiProfiler",
        security_mode: str = "ft-wpa3-mixed",
    ) -> None:
        """Start profiler on remote"""
        # Kill any existing instances
        subprocess.run(
            ["ssh", self.remote_host, "sudo pkill -9 profiler; sudo pkill -9 hostapd"],
            capture_output=True,
        )
        time.sleep(2)

        # Build profiler command
        cmd = (
            f"sudo profiler --ap-mode -c {channel} -s {ssid} "
            f"--security-mode {security_mode} --passphrase {passphrase} "
            f"--debug > /tmp/profiler_test_4ss.log 2>&1 &"
        )

        # Start profiler
        result = subprocess.run(
            ["ssh", self.remote_host, cmd],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            pytest.fail(f"Failed to start profiler: {result.stderr}")

        # Wait for startup
        time.sleep(6)

        # Verify it's running
        check = subprocess.run(
            ["ssh", self.remote_host, "pgrep -f 'profiler --ap-mode'"],
            capture_output=True,
            text=True,
        )

        if not check.stdout.strip():
            log = self._get_log()
            pytest.fail(f"Profiler failed to start. Log:\n{log}")

    def stop(self) -> str:
        """Stop profiler and return log"""
        subprocess.run(
            ["ssh", self.remote_host, "sudo pkill -9 profiler; sudo pkill -9 hostapd"],
            capture_output=True,
        )
        time.sleep(1)
        return self._get_log()

    def _get_log(self) -> str:
        """Get profiler log"""
        result = subprocess.run(
            ["ssh", self.remote_host, "cat /tmp/profiler_test_4ss.log 2>&1"],
            capture_output=True,
            text=True,
        )
        return result.stdout


@pytest.fixture
def ota_interface():
    """Setup and verify local monitor interface"""
    iface = os.getenv("PROFILER_OTA_INTERFACE", "wlu1u3")
    channel = int(os.getenv("PROFILER_REMOTE_CHANNEL", "36"))

    # Verify interface exists
    try:
        subprocess.run(
            ["iw", "dev", iface, "info"],
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        pytest.skip(f"Interface {iface} not found")

    # Configure monitor mode
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
        pytest.skip(f"Failed to configure {iface}: {e}")

    return iface


@pytest.fixture
def remote_host():
    """Get and verify remote WLAN Pi SSH target"""
    host = os.getenv("PROFILER_REMOTE_HOST", "wlanpi@198.18.42.1")

    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", host, "echo connected"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        if "connected" not in result.stdout:
            pytest.skip(f"Cannot connect to {host}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pytest.skip(f"Cannot reach {host}")

    return host


class TestBeacon4SS160MHz:
    """Test beacon advertising of 4 SS and 160 MHz across all technologies"""

    def test_ht_advertises_4ss(self, ota_interface, remote_host):
        """
        Test HT (802.11n) advertises 4 spatial streams

        Expected:
        - HT Capabilities IE present
        - MCS Set bytes 0-3 are 0xFF (MCS 0-31, supporting SS 1-4)
        """
        ssid = "TEST-HT-4SS"
        controller = RemoteProfilerController(remote_host)
        analyzer = BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = BeaconAnalyzer.verify_ht_4ss(beacon)

            assert result["present"], "HT Capabilities IE not found"
            assert result["advertises_4ss"], (
                f"HT does not advertise 4 SS. "
                f"SS1: {result['ss1_mcs']}, SS2: {result['ss2_mcs']}, "
                f"SS3: {result['ss3_mcs']}, SS4: {result['ss4_mcs']}"
            )

        finally:
            controller.stop()

    def test_vht_advertises_4ss_and_160mhz(self, ota_interface, remote_host):
        """
        Test VHT (802.11ac) advertises 4 SS and 160 MHz capability

        Expected:
        - VHT Capabilities IE present
        - Channel Width Set indicates 160 MHz support
        - MCS Map shows SS 1-4 supported, SS 5-8 not supported (0xffaa)
        """
        ssid = "TEST-VHT-4SS-160"
        controller = RemoteProfilerController(remote_host)
        analyzer = BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = BeaconAnalyzer.verify_vht_4ss_and_160mhz(beacon)

            assert result["present"], "VHT Capabilities IE not found"
            assert result["supports_160mhz"], (
                f"VHT does not advertise 160 MHz support. "
                f"Channel Width Set: {result['chan_width_set']}"
            )
            assert result["advertises_4ss"], (
                f"VHT does not advertise 4 SS. RX MCS Map: {result['rx_mcs_map']}"
            )

        finally:
            controller.stop()

    def test_he_advertises_4ss_and_160mhz(self, ota_interface, remote_host):
        """
        Test HE (802.11ax) advertises 4 SS and 160 MHz capability

        Expected:
        - HE Capabilities extension IE present
        - PHY capabilities indicate 160 MHz support
        - 80 MHz MCS Map shows SS 1-4 supported, SS 5-8 not supported (0xffaa)
        - 160 MHz MCS Map shows SS 1-4 supported, SS 5-8 not supported (0xffaa)
        """
        ssid = "TEST-HE-4SS-160"
        controller = RemoteProfilerController(remote_host)
        analyzer = BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = BeaconAnalyzer.verify_he_4ss_and_160mhz(beacon)

            assert result["present"], "HE Capabilities IE not found"
            assert result["supports_160mhz"], (
                "HE does not advertise 160 MHz support in PHY capabilities"
            )
            assert result["advertises_4ss_80"], (
                f"HE does not advertise 4 SS for 80 MHz. "
                f"RX MCS 80: {result['rx_mcs_80']}"
            )

            if "advertises_4ss_160" in result:
                assert result["advertises_4ss_160"], (
                    f"HE does not advertise 4 SS for 160 MHz. "
                    f"RX MCS 160: {result['rx_mcs_160']}"
                )

        finally:
            controller.stop()

    def test_eht_advertises_4ss(self, ota_interface, remote_host):
        """
        Test EHT (802.11be) advertises 4 spatial streams

        Expected:
        - EHT Capabilities extension IE present
        - NSS values for MCS 0-9 and 10-11 indicate 4 SS (value 3, meaning 3+1=4)
        """
        ssid = "TEST-EHT-4SS"
        controller = RemoteProfilerController(remote_host)
        analyzer = BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = BeaconAnalyzer.verify_eht_4ss(beacon)

            assert result["present"], "EHT Capabilities IE not found"
            assert result["advertises_4ss"], (
                f"EHT does not advertise 4 SS. "
                f"RX NSS MCS 0-9: {result['rx_nss_mcs_0_9']}, "
                f"TX NSS MCS 0-9: {result['tx_nss_mcs_0_9']}, "
                f"RX NSS MCS 10-11: {result['rx_nss_mcs_10_11']}, "
                f"TX NSS MCS 10-11: {result['tx_nss_mcs_10_11']}"
            )

        finally:
            controller.stop()

    def test_all_technologies_comprehensive(self, ota_interface, remote_host):
        """
        Comprehensive test verifying all technologies advertise correctly in single beacon

        This test captures one beacon and verifies:
        - HT: 4 SS
        - VHT: 4 SS + 160 MHz
        - HE: 4 SS + 160 MHz
        - EHT: 4 SS
        """
        ssid = "TEST-ALL-4SS-160"
        controller = RemoteProfilerController(remote_host)
        analyzer = BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            # Verify all technologies
            ht = BeaconAnalyzer.verify_ht_4ss(beacon)
            vht = BeaconAnalyzer.verify_vht_4ss_and_160mhz(beacon)
            he = BeaconAnalyzer.verify_he_4ss_and_160mhz(beacon)
            eht = BeaconAnalyzer.verify_eht_4ss(beacon)

            # Collect all failures
            failures = []

            if not ht.get("advertises_4ss"):
                failures.append("HT: Does not advertise 4 SS")

            if not vht.get("supports_160mhz"):
                failures.append("VHT: Does not advertise 160 MHz")
            if not vht.get("advertises_4ss"):
                failures.append(
                    f"VHT: Does not advertise 4 SS (Map: {vht.get('rx_mcs_map')})"
                )

            if not he.get("supports_160mhz"):
                failures.append("HE: Does not advertise 160 MHz capability")
            if not he.get("advertises_4ss_80"):
                failures.append(
                    f"HE: Does not advertise 4 SS for 80 MHz (Map: {he.get('rx_mcs_80')})"
                )
            if "advertises_4ss_160" in he and not he["advertises_4ss_160"]:
                failures.append(
                    f"HE: Does not advertise 4 SS for 160 MHz (Map: {he.get('rx_mcs_160')})"
                )

            if not eht.get("advertises_4ss"):
                failures.append(
                    f"EHT: Does not advertise 4 SS "
                    f"(RX MCS 0-9: {eht.get('rx_nss_mcs_0_9')}, "
                    f"TX MCS 0-9: {eht.get('tx_nss_mcs_0_9')})"
                )

            if failures:
                pytest.fail(
                    "Beacon verification failed:\n"
                    + "\n".join(f"  - {f}" for f in failures)
                )

        finally:
            controller.stop()
