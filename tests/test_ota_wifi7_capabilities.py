# -*- coding: utf-8 -*-

"""
OTA Beacon Verification Tests for Wi-Fi 7 (802.11be) Capability Fixes

These tests verify the specific Wi-Fi 7 capabilities that were fixed:
1. HE PHY Channel Width: 160 MHz and 80+80 MHz support
2. EHT PHY MCS-15 Support: All MCS-15 variants (bits 40-55)
3. EHT PHY MU Beamformer: 80/160/320 MHz support
4. EHT-MCS NSS Set: NSS=4 for MCS 12-13
5. EHT Operation Basic MCS/NSS: NSS=4 for all MCS ranges
6. MLD Maximum Simultaneous Links: Should be 2
7. VHT Beamformee STS and Sounding Dimensions: Maximum values

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
    pytest tests/test_ota_wifi7_capabilities.py -v

Environment Variables:
    PROFILER_OTA_TESTS=1                    Enable OTA tests
    PROFILER_OTA_INTERFACE=wlu1u3           Local monitor interface (default: wlu1u3)
    PROFILER_REMOTE_HOST=wlanpi@198.18.42.1 Remote SSH target (default: wlanpi@198.18.42.1)
    PROFILER_REMOTE_CHANNEL=36              Channel to test on (default: 36 for 5GHz)
"""

import os
import subprocess
import time
from typing import Dict, Optional

import pytest
from scapy.all import Dot11Beacon, Dot11Elt, sniff

# Skip all tests in this file unless OTA testing is explicitly enabled
pytestmark = pytest.mark.skipif(
    os.getenv("PROFILER_OTA_TESTS") != "1",
    reason="OTA tests disabled (set PROFILER_OTA_TESTS=1 to enable)",
)


class WiFi7BeaconAnalyzer:
    """Utility for capturing and analyzing 802.11be beacons for Wi-Fi 7 capabilities"""

    def __init__(self, interface: str, timeout: int = 10):
        self.interface = interface
        self.timeout = timeout
        self.beacons = []

    def capture_beacon(self, ssid: str, count: int = 3) -> Optional[Dot11Beacon]:
        """Capture beacon for specified SSID"""
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
    def get_extension_ie(beacon: Dot11Beacon, ext_id: int) -> Optional[bytes]:
        """Extract Extension IE from beacon by extension ID"""
        elt = beacon.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 255 and len(elt.info) > 0:  # Extension IE
                if elt.info[0] == ext_id:
                    return bytes(elt.info)
            elt = elt.payload.getlayer(Dot11Elt)
        return None

    @staticmethod
    def get_ie(beacon: Dot11Beacon, ie_id: int) -> Optional[bytes]:
        """Extract Information Element from beacon by ID"""
        elt = beacon.getlayer(Dot11Elt)
        while elt:
            if elt.ID == ie_id:
                return bytes(elt.info)
            elt = elt.payload.getlayer(Dot11Elt)
        return None

    @staticmethod
    def verify_he_160_8080_support(beacon: Dot11Beacon) -> Dict:
        """
        Verify HE PHY Channel Width supports 160 MHz and 80+80 MHz

        Issue #1: HE PHY capabilities should advertise 160 MHz and 80+80 MHz support
        Original: Only 40/80 MHz (0x06)
        Fixed: 160/80+80 MHz enabled (0x1E)
        """
        he_cap = WiFi7BeaconAnalyzer.get_extension_ie(beacon, 0x23)
        if not he_cap or len(he_cap) < 8:
            return {"present": False, "error": "HE Capabilities IE not found"}

        # PHY capabilities byte 0 is at offset 7 (after ext_id + MAC caps)
        phy_cap_0 = he_cap[7]

        # Bits 1-4 are channel width indicators
        # Bit 1: 40 MHz in 2.4 GHz
        # Bit 2: 40 & 80 MHz in 5 GHz
        # Bit 3: 160 MHz in 5 GHz
        # Bit 4: 160 MHz & 80+80 MHz in 5 GHz
        supports_40_80 = (phy_cap_0 & 0x02) != 0
        supports_160 = (phy_cap_0 & 0x04) != 0
        supports_160_8080 = (phy_cap_0 & 0x08) != 0

        return {
            "present": True,
            "phy_cap_0": f"0x{phy_cap_0:02x}",
            "supports_40_80": supports_40_80,
            "supports_160": supports_160,
            "supports_160_8080": supports_160_8080,
            "correct": supports_160 and supports_160_8080,
        }

    @staticmethod
    def verify_eht_mcs15_support(beacon: Dot11Beacon) -> Dict:
        """
        Verify EHT PHY MCS-15 support across all variants

        Issue #2: EHT PHY capabilities should enable ALL MCS-15 support bits
        Bits 40-55 (bytes 5-6) should be 0xFF 0xFF
        """
        eht_cap = WiFi7BeaconAnalyzer.get_extension_ie(beacon, 0x6C)
        if not eht_cap or len(eht_cap) < 12:
            return {"present": False, "error": "EHT Capabilities IE not found"}

        # PHY capabilities start at offset 3 (after ext_id + MAC caps)
        # Byte 5 (offset 8) = bits 40-47
        # Byte 6 (offset 9) = bits 48-55
        if len(eht_cap) < 10:
            return {"present": True, "error": "EHT Capabilities too short for MCS-15"}

        phy_cap_5 = eht_cap[8]
        phy_cap_6 = eht_cap[9]

        return {
            "present": True,
            "phy_cap_5": f"0x{phy_cap_5:02x}",
            "phy_cap_6": f"0x{phy_cap_6:02x}",
            "all_mcs15_enabled": phy_cap_5 == 0xFF and phy_cap_6 == 0xFF,
        }

    @staticmethod
    def verify_eht_mu_beamformer(beacon: Dot11Beacon) -> Dict:
        """
        Verify EHT PHY MU Beamformer support for 80/160/320 MHz

        Issue #3: EHT PHY capabilities should advertise MU beamformer for all bandwidths
        Bit 60: MU Beamformer 80 MHz
        Bit 61: MU Beamformer 160 MHz
        Bit 62: MU Beamformer 320 MHz
        """
        eht_cap = WiFi7BeaconAnalyzer.get_extension_ie(beacon, 0x6C)
        if not eht_cap or len(eht_cap) < 12:
            return {"present": False, "error": "EHT Capabilities IE not found"}

        # Byte 7 (offset 10) contains bits 56-63
        # Bits 60-62 are at bit positions 4-6 of byte 7
        if len(eht_cap) < 11:
            return {"present": True, "error": "EHT Capabilities too short"}

        phy_cap_7 = eht_cap[10]

        mu_bf_80 = (phy_cap_7 & (1 << 4)) != 0  # Bit 60
        mu_bf_160 = (phy_cap_7 & (1 << 5)) != 0  # Bit 61
        mu_bf_320 = (phy_cap_7 & (1 << 6)) != 0  # Bit 62

        return {
            "present": True,
            "phy_cap_7": f"0x{phy_cap_7:02x}",
            "mu_beamformer_80mhz": mu_bf_80,
            "mu_beamformer_160mhz": mu_bf_160,
            "mu_beamformer_320mhz": mu_bf_320,
            "all_bandwidths": mu_bf_80 and mu_bf_160 and mu_bf_320,
        }

    @staticmethod
    def verify_eht_mcs_nss_4ss(beacon: Dot11Beacon) -> Dict:
        """
        Verify EHT-MCS NSS Set advertises NSS=4 for all MCS ranges

        Issue #4: EHT-MCS NSS set should show NSS=4 for MCS 12-13
        Each nibble (4 bits) represents max NSS-1
        Value 0x3 = NSS 4 (3+1)
        Expected: 0x33 for all MCS ranges
        """
        eht_cap = WiFi7BeaconAnalyzer.get_extension_ie(beacon, 0x6C)
        if not eht_cap or len(eht_cap) < 15:
            return {"present": False, "error": "EHT Capabilities IE not found"}

        # MCS/NSS map starts at offset 12 (after ext_id + MAC + PHY)
        # BW <= 80 MHz: 3 bytes
        mcs_map_80 = int.from_bytes(eht_cap[12:15], "little")

        # Extract NSS values (nibbles, value is NSS-1)
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
        rx_nss_12_13 = (
            ((mcs_map_80 >> 16) & 0xF) + 1 if ((mcs_map_80 >> 16) & 0xF) != 0xF else 0
        )
        tx_nss_12_13 = (
            ((mcs_map_80 >> 20) & 0xF) + 1 if ((mcs_map_80 >> 20) & 0xF) != 0xF else 0
        )

        return {
            "present": True,
            "mcs_map_80": f"0x{mcs_map_80:06x}",
            "rx_nss_mcs_0_9": rx_nss_0_9,
            "tx_nss_mcs_0_9": tx_nss_0_9,
            "rx_nss_mcs_10_11": rx_nss_10_11,
            "tx_nss_mcs_10_11": tx_nss_10_11,
            "rx_nss_mcs_12_13": rx_nss_12_13,
            "tx_nss_mcs_12_13": tx_nss_12_13,
            "all_4ss": all(
                [
                    rx_nss_0_9 == 4,
                    tx_nss_0_9 == 4,
                    rx_nss_10_11 == 4,
                    tx_nss_10_11 == 4,
                    rx_nss_12_13 == 4,
                    tx_nss_12_13 == 4,
                ]
            ),
        }

    @staticmethod
    def verify_eht_operation_basic_mcs_nss(beacon: Dot11Beacon) -> Dict:
        """
        Verify EHT Operation Basic MCS/NSS Set

        Issue #5: EHT Operation IE should advertise NSS=4 for all basic MCS ranges
        Expected: All 4 bytes should be 0x33 (NSS=4)
        """
        eht_oper = WiFi7BeaconAnalyzer.get_extension_ie(beacon, 0x6D)
        if not eht_oper or len(eht_oper) < 8:
            return {"present": False, "error": "EHT Operation IE not found"}

        # Basic EHT-MCS NSS Set is 4 bytes, starting at offset 4
        if len(eht_oper) < 8:
            return {"present": True, "error": "EHT Operation IE too short"}

        basic_mcs_nss = eht_oper[4:8]

        # Decode NSS values (each nibble represents NSS-1 for a MCS range)
        def decode_nss(byte_val):
            rx = (byte_val & 0xF) + 1 if (byte_val & 0xF) != 0xF else 0
            tx = ((byte_val >> 4) & 0xF) + 1 if ((byte_val >> 4) & 0xF) != 0xF else 0
            return rx, tx

        nss_0_7 = decode_nss(basic_mcs_nss[0])
        nss_8_9 = decode_nss(basic_mcs_nss[1])
        nss_10_11 = decode_nss(basic_mcs_nss[2])
        nss_12_13 = decode_nss(basic_mcs_nss[3])

        return {
            "present": True,
            "basic_mcs_nss_bytes": " ".join(f"0x{b:02x}" for b in basic_mcs_nss),
            "mcs_0_7_rx_nss": nss_0_7[0],
            "mcs_0_7_tx_nss": nss_0_7[1],
            "mcs_8_9_rx_nss": nss_8_9[0],
            "mcs_8_9_tx_nss": nss_8_9[1],
            "mcs_10_11_rx_nss": nss_10_11[0],
            "mcs_10_11_tx_nss": nss_10_11[1],
            "mcs_12_13_rx_nss": nss_12_13[0],
            "mcs_12_13_tx_nss": nss_12_13[1],
            "all_4ss": all(
                [
                    nss_0_7[0] == 4,
                    nss_0_7[1] == 4,
                    nss_8_9[0] == 4,
                    nss_8_9[1] == 4,
                    nss_10_11[0] == 4,
                    nss_10_11[1] == 4,
                    nss_12_13[0] == 4,
                    nss_12_13[1] == 4,
                ]
            ),
        }

    @staticmethod
    def verify_mld_max_simul_links(beacon: Dot11Beacon) -> Dict:
        """
        Verify MLD Maximum Simultaneous Links

        Issue #6: MLD IE should advertise max simultaneous links = 2
        This is in the MLD Capabilities and Operations field (bits 0-3)
        """
        # Multi-Link element is extension IE 0x6B
        mld_ie = WiFi7BeaconAnalyzer.get_extension_ie(beacon, 0x6B)
        if not mld_ie or len(mld_ie) < 10:
            return {"present": False, "error": "Multi-Link IE not found"}

        # Control field (2 bytes) at offset 1-2
        # Common Info Length at offset 3
        # MLD Capabilities at Common Info offset depends on presence bits

        # For basic ML element:
        # Control (2) + Common Info Length (1) + MLD Address (6) + Link ID (1) +
        # BSS Param Change Count (1) + EML Capabilities (2) + MLD Capabilities (2)

        # MLD Capabilities is the last 2 bytes of common info
        common_info_len = mld_ie[3]
        if len(mld_ie) < 4 + common_info_len:
            return {"present": True, "error": "Multi-Link IE too short"}

        # MLD Capabilities is 2 bytes before end of common info
        mld_cap_offset = 4 + common_info_len - 2
        mld_cap = int.from_bytes(mld_ie[mld_cap_offset : mld_cap_offset + 2], "little")

        # Bits 0-3 (mask 0x000F) are Maximum Number of Simultaneous Links
        max_simul_links = mld_cap & 0x000F

        return {
            "present": True,
            "mld_capabilities": f"0x{mld_cap:04x}",
            "max_simultaneous_links": max_simul_links,
            "correct": max_simul_links == 2,
        }

    @staticmethod
    def verify_vht_beamformee_sts_sounding(beacon: Dot11Beacon) -> Dict:
        """
        Verify VHT Beamformee STS and Sounding Dimensions

        Issue #7: VHT capabilities should advertise maximum beamformee STS and sounding dimensions
        Bits 13-15: Beamformee STS Capability (should be 7 for 8 STS)
        Bits 16-18: Sounding Dimensions (should be 7 for 8 dimensions)
        """
        vht_cap = WiFi7BeaconAnalyzer.get_ie(beacon, 0xBF)
        if not vht_cap or len(vht_cap) < 12:
            return {"present": False, "error": "VHT Capabilities IE not found"}

        # VHT Capabilities Info (4 bytes)
        vht_cap_info = int.from_bytes(vht_cap[0:4], "little")

        # Beamformee STS Capability (bits 13-15)
        beamformee_sts = (vht_cap_info >> 13) & 0x7

        # Sounding Dimensions (bits 16-18)
        sounding_dim = (vht_cap_info >> 16) & 0x7

        return {
            "present": True,
            "vht_cap_info": f"0x{vht_cap_info:08x}",
            "beamformee_sts": beamformee_sts,
            "beamformee_sts_count": beamformee_sts + 1,  # Value is NSS-1
            "sounding_dimensions": sounding_dim,
            "sounding_dimensions_count": sounding_dim + 1,
            "beamformee_sts_max": beamformee_sts == 7,
            "sounding_dimensions_max": sounding_dim == 7,
            "both_max": beamformee_sts == 7 and sounding_dim == 7,
        }


class RemoteProfilerController:
    """Control profiler on remote WLAN Pi via SSH"""

    def __init__(self, remote_host: str = "wlanpi@198.18.42.1"):
        self.remote_host = remote_host

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
            f"--debug > /tmp/profiler_test_wifi7.log 2>&1 &"
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
            ["ssh", self.remote_host, "cat /tmp/profiler_test_wifi7.log 2>&1"],
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


class TestWiFi7Capabilities:
    """Test Wi-Fi 7 capability fixes"""

    def test_he_160_8080_support(self, ota_interface, remote_host):
        """
        Test Issue #1: HE PHY Channel Width supports 160 MHz and 80+80 MHz

        Expected:
        - HE PHY capabilities byte 0 should have bits 2-4 set (0x1E pattern)
        - Advertises 160 MHz and 80+80 MHz support
        """
        ssid = "TEST-HE-160-8080"
        controller = RemoteProfilerController(remote_host)
        analyzer = WiFi7BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = WiFi7BeaconAnalyzer.verify_he_160_8080_support(beacon)

            assert result["present"], "HE Capabilities IE not found"
            assert result["correct"], (
                f"HE does not advertise 160 MHz and 80+80 MHz support. "
                f"PHY Cap 0: {result['phy_cap_0']}, "
                f"160 MHz: {result['supports_160']}, "
                f"160/80+80 MHz: {result['supports_160_8080']}"
            )

        finally:
            controller.stop()

    def test_eht_mcs15_support(self, ota_interface, remote_host):
        """
        Test Issue #2: EHT PHY MCS-15 support enabled for all variants

        Expected:
        - EHT PHY capabilities bytes 5-6 should be 0xFF 0xFF
        """
        ssid = "TEST-EHT-MCS15"
        controller = RemoteProfilerController(remote_host)
        analyzer = WiFi7BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = WiFi7BeaconAnalyzer.verify_eht_mcs15_support(beacon)

            assert result["present"], "EHT Capabilities IE not found"
            assert result["all_mcs15_enabled"], (
                f"EHT does not enable all MCS-15 variants. "
                f"Byte 5: {result['phy_cap_5']}, Byte 6: {result['phy_cap_6']} "
                f"(expected: 0xFF 0xFF)"
            )

        finally:
            controller.stop()

    def test_eht_mu_beamformer(self, ota_interface, remote_host):
        """
        Test Issue #3: EHT PHY MU Beamformer for 80/160/320 MHz

        Expected:
        - Bits 60, 61, 62 should all be set (MU beamformer for all bandwidths)
        """
        ssid = "TEST-EHT-MU-BF"
        controller = RemoteProfilerController(remote_host)
        analyzer = WiFi7BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = WiFi7BeaconAnalyzer.verify_eht_mu_beamformer(beacon)

            assert result["present"], "EHT Capabilities IE not found"
            assert result["all_bandwidths"], (
                f"EHT does not advertise MU beamformer for all bandwidths. "
                f"80 MHz: {result['mu_beamformer_80mhz']}, "
                f"160 MHz: {result['mu_beamformer_160mhz']}, "
                f"320 MHz: {result['mu_beamformer_320mhz']}"
            )

        finally:
            controller.stop()

    def test_eht_mcs_nss_4ss(self, ota_interface, remote_host):
        """
        Test Issue #4: EHT-MCS NSS Set advertises NSS=4 for all MCS ranges

        Expected:
        - All MCS ranges (0-9, 10-11, 12-13) should show NSS=4
        """
        ssid = "TEST-EHT-NSS4"
        controller = RemoteProfilerController(remote_host)
        analyzer = WiFi7BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = WiFi7BeaconAnalyzer.verify_eht_mcs_nss_4ss(beacon)

            assert result["present"], "EHT Capabilities IE not found"
            assert result["all_4ss"], (
                f"EHT does not advertise NSS=4 for all MCS ranges. "
                f"MCS 0-9: RX={result['rx_nss_mcs_0_9']}, TX={result['tx_nss_mcs_0_9']}, "
                f"MCS 10-11: RX={result['rx_nss_mcs_10_11']}, TX={result['tx_nss_mcs_10_11']}, "
                f"MCS 12-13: RX={result['rx_nss_mcs_12_13']}, TX={result['tx_nss_mcs_12_13']}"
            )

        finally:
            controller.stop()

    def test_eht_operation_basic_mcs_nss(self, ota_interface, remote_host):
        """
        Test Issue #5: EHT Operation Basic MCS/NSS Set

        Expected:
        - All 4 bytes should be 0x33 (NSS=4 for all MCS ranges)
        """
        ssid = "TEST-EHT-OPER-NSS"
        controller = RemoteProfilerController(remote_host)
        analyzer = WiFi7BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = WiFi7BeaconAnalyzer.verify_eht_operation_basic_mcs_nss(beacon)

            assert result["present"], "EHT Operation IE not found"
            assert result["all_4ss"], (
                f"EHT Operation does not advertise NSS=4 for all basic MCS ranges. "
                f"Bytes: {result['basic_mcs_nss_bytes']}"
            )

        finally:
            controller.stop()

    def test_mld_max_simul_links(self, ota_interface, remote_host):
        """
        Test Issue #6: MLD Maximum Simultaneous Links

        Expected:
        - MLD Capabilities should advertise max simultaneous links = 2
        """
        ssid = "TEST-MLD-LINKS"
        controller = RemoteProfilerController(remote_host)
        analyzer = WiFi7BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = WiFi7BeaconAnalyzer.verify_mld_max_simul_links(beacon)

            assert result["present"], "Multi-Link IE not found"
            assert result["correct"], (
                f"MLD does not advertise max simultaneous links = 2. "
                f"Advertised: {result['max_simultaneous_links']}"
            )

        finally:
            controller.stop()

    def test_vht_beamformee_sts_sounding(self, ota_interface, remote_host):
        """
        Test Issue #7: VHT Beamformee STS and Sounding Dimensions

        Expected:
        - Beamformee STS = 7 (supports 8 STS)
        - Sounding Dimensions = 7 (supports 8 dimensions)
        """
        ssid = "TEST-VHT-BF-STS"
        controller = RemoteProfilerController(remote_host)
        analyzer = WiFi7BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            result = WiFi7BeaconAnalyzer.verify_vht_beamformee_sts_sounding(beacon)

            assert result["present"], "VHT Capabilities IE not found"
            assert result["both_max"], (
                f"VHT does not advertise maximum beamformee capabilities. "
                f"Beamformee STS: {result['beamformee_sts']} (count: {result['beamformee_sts_count']}), "
                f"Sounding Dimensions: {result['sounding_dimensions']} (count: {result['sounding_dimensions_count']})"
            )

        finally:
            controller.stop()

    def test_all_wifi7_capabilities(self, ota_interface, remote_host):
        """
        Comprehensive test verifying all Wi-Fi 7 capability fixes in a single beacon

        This test captures one beacon and verifies all 7 issues are fixed.
        """
        ssid = "TEST-WIFI7-ALL"
        controller = RemoteProfilerController(remote_host)
        analyzer = WiFi7BeaconAnalyzer(ota_interface, timeout=15)

        try:
            controller.start(ssid=ssid)
            beacon = analyzer.capture_beacon(ssid=ssid, count=3)

            assert beacon is not None, f"No beacons captured for SSID {ssid}"

            # Verify all capabilities
            he_160 = WiFi7BeaconAnalyzer.verify_he_160_8080_support(beacon)
            eht_mcs15 = WiFi7BeaconAnalyzer.verify_eht_mcs15_support(beacon)
            eht_mu_bf = WiFi7BeaconAnalyzer.verify_eht_mu_beamformer(beacon)
            eht_nss = WiFi7BeaconAnalyzer.verify_eht_mcs_nss_4ss(beacon)
            eht_oper = WiFi7BeaconAnalyzer.verify_eht_operation_basic_mcs_nss(beacon)
            mld_links = WiFi7BeaconAnalyzer.verify_mld_max_simul_links(beacon)
            vht_bf = WiFi7BeaconAnalyzer.verify_vht_beamformee_sts_sounding(beacon)

            # Collect failures
            failures = []

            if not he_160.get("correct"):
                failures.append("Issue #1: HE 160/80+80 MHz not advertised")

            if not eht_mcs15.get("all_mcs15_enabled"):
                failures.append(
                    f"Issue #2: EHT MCS-15 not fully enabled "
                    f"({eht_mcs15.get('phy_cap_5')} {eht_mcs15.get('phy_cap_6')})"
                )

            if not eht_mu_bf.get("all_bandwidths"):
                failures.append("Issue #3: EHT MU beamformer not enabled for all BWs")

            if not eht_nss.get("all_4ss"):
                failures.append("Issue #4: EHT-MCS NSS not 4 for all MCS ranges")

            if not eht_oper.get("all_4ss"):
                failures.append("Issue #5: EHT Operation basic MCS/NSS not 4")

            if not mld_links.get("correct"):
                failures.append(
                    f"Issue #6: MLD max simul links = {mld_links.get('max_simultaneous_links')} (expected 2)"
                )

            if not vht_bf.get("both_max"):
                failures.append("Issue #7: VHT beamformee capabilities not maximum")

            if failures:
                pytest.fail(
                    "Wi-Fi 7 capability verification failed:\n"
                    + "\n".join(f"  - {f}" for f in failures)
                )

        finally:
            controller.stop()
