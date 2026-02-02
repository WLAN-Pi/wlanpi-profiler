# -*- coding: utf-8 -*-

"""
OTA Patch Regression Tests

These tests verify that each individual hostapd patch is working correctly
to prevent regressions. Tests capture a single beacon and validate all patches
efficiently.

Patches tested:
1. hostapd_ht_txbf.patch - HT TxBF capabilities + 4 SS (merged)
2. vht_advertise_4ss.patch - VHT 4 spatial stream advertising  
3. hostapd_he_caps.patch - HE capabilities (MAC, PHY, 160 MHz, 4 SS) (merged)
4. hostapd_eht_caps.patch - EHT capabilities (MAC, PHY, 4 SS, 160 MHz) (merged)
5. capability_validation_bypass.patch - Capability validation bypass
6. ext_cap_profiler.patch - Extended capabilities (SCS, TWT, FILS)

Requirements:
- Localhost: Wi-Fi adapter in monitor mode (e.g., wlu1u3)
- Remote WLAN Pi: SSH access to wlanpi@198.18.42.1
- Set PROFILER_OTA_TESTS=1 environment variable to enable

Usage:
    PROFILER_OTA_TESTS=1 PROFILER_OTA_INTERFACE=wlu1u3 \
    PROFILER_REMOTE_HOST=wlanpi@198.18.42.1 \
    PROFILER_REMOTE_CHANNEL=36 \
    pytest tests/test_ota_patch_regression.py -v
"""

import os
import subprocess
import time
from typing import Dict, Optional, Tuple

import pytest
from scapy.all import Dot11Beacon, Dot11Elt, sniff

# Skip all tests unless OTA testing is explicitly enabled
pytestmark = pytest.mark.skipif(
    os.getenv("PROFILER_OTA_TESTS") != "1",
    reason="OTA tests disabled (set PROFILER_OTA_TESTS=1 to enable)",
)


def get_ie(beacon: Dot11Beacon, ie_id: int) -> Optional[bytes]:
    """Extract Information Element from beacon by ID"""
    elt = beacon.getlayer(Dot11Elt)
    while elt:
        if elt.ID == ie_id:
            return bytes(elt.info)
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def get_extension_ie(beacon: Dot11Beacon, ext_id: int) -> Optional[bytes]:
    """Extract Extension IE from beacon by extension ID"""
    elt = beacon.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 255 and len(elt.info) > 0:
            if elt.info[0] == ext_id:
                return bytes(elt.info)
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def parse_ht_nss_and_caps(ht_cap: bytes) -> Dict:
    """Parse HT capabilities for NSS and TxBF"""
    if not ht_cap or len(ht_cap) < 26:
        return {"present": False}

    # MCS Set at bytes 3-18
    mcs_set = ht_cap[3:19]

    # Count spatial streams based on MCS set
    nss = 0
    for i in range(4):  # Check SS 1-4
        if mcs_set[i] == 0xFF:
            nss = i + 1

    # TxBF Capabilities at bytes 21-24
    txbf_cap = int.from_bytes(ht_cap[21:25], "little")

    return {
        "present": True,
        "nss": nss,
        "mcs_bytes": [f"0x{b:02x}" for b in mcs_set[0:4]],
        "txbf_cap": txbf_cap,
        "txbf_enabled": txbf_cap == 0x1FFFFFFF,
    }


def parse_vht_nss_and_width(vht_cap: bytes) -> Dict:
    """Parse VHT capabilities for NSS and channel width"""
    if not vht_cap or len(vht_cap) < 12:
        return {"present": False}

    # VHT Capabilities Info (4 bytes)
    vht_cap_info = int.from_bytes(vht_cap[0:4], "little")
    chan_width_set = (vht_cap_info >> 2) & 0x3

    # Channel width interpretation
    width_map = {
        0: "No 160MHz/80+80MHz",
        1: "160MHz",
        2: "160MHz and 80+80MHz",
    }

    # Rx/Tx MCS Maps
    rx_mcs_map = int.from_bytes(vht_cap[4:6], "little")
    tx_mcs_map = int.from_bytes(vht_cap[6:8], "little")

    # Count NSS based on Rx MCS map
    nss = 0
    for i in range(8):
        ss_bits = (rx_mcs_map >> (i * 2)) & 0x3
        if ss_bits != 0x3:  # Not "not supported"
            nss = i + 1

    return {
        "present": True,
        "chan_width_set": chan_width_set,
        "chan_width_desc": width_map.get(chan_width_set, "Unknown"),
        "supports_160mhz": chan_width_set in [1, 2],
        "nss": nss,
        "rx_mcs_map": f"0x{rx_mcs_map:04x}",
        "tx_mcs_map": f"0x{tx_mcs_map:04x}",
    }


def parse_he_nss_and_width(he_cap: bytes) -> Dict:
    """Parse HE capabilities for NSS and channel width"""
    if not he_cap or len(he_cap) < 22:
        return {"present": False}

    # PHY Capabilities byte 0 at offset 7
    phy_cap_0 = he_cap[7]
    supports_160mhz = (phy_cap_0 & 0x08) != 0

    # MCS maps at offset 18
    rx_mcs_80 = int.from_bytes(he_cap[18:20], "little")
    tx_mcs_80 = int.from_bytes(he_cap[20:22], "little")

    # Count NSS for 80 MHz
    nss_80 = 0
    for i in range(8):
        ss_bits = (rx_mcs_80 >> (i * 2)) & 0x3
        if ss_bits != 0x3:
            nss_80 = i + 1

    result = {
        "present": True,
        "supports_160mhz": supports_160mhz,
        "phy_cap_byte_0": f"0x{phy_cap_0:02x}",
        "nss_80mhz": nss_80,
        "rx_mcs_80": f"0x{rx_mcs_80:04x}",
        "tx_mcs_80": f"0x{tx_mcs_80:04x}",
    }

    # Check 160 MHz maps if present
    if len(he_cap) >= 26:
        rx_mcs_160 = int.from_bytes(he_cap[22:24], "little")
        tx_mcs_160 = int.from_bytes(he_cap[24:26], "little")

        nss_160 = 0
        for i in range(8):
            ss_bits = (rx_mcs_160 >> (i * 2)) & 0x3
            if ss_bits != 0x3:
                nss_160 = i + 1

        result.update(
            {
                "nss_160mhz": nss_160,
                "rx_mcs_160": f"0x{rx_mcs_160:04x}",
                "tx_mcs_160": f"0x{tx_mcs_160:04x}",
            }
        )

    return result


def parse_eht_nss(eht_cap: bytes) -> Dict:
    """Parse EHT capabilities for NSS"""
    if not eht_cap or len(eht_cap) < 15:
        return {"present": False}

    # MAC Capabilities at bytes 1-2
    eht_mac_cap = int.from_bytes(eht_cap[1:3], "little")

    # PHY Capabilities at bytes 3-11 (9 bytes)
    eht_phy_cap_val = int.from_bytes(eht_cap[3:12], "little")

    # MCS Map BW <= 80 MHz at offset 12 (3 bytes)
    mcs_map_80 = int.from_bytes(eht_cap[12:15], "little")

    # Extract NSS values (each 4 bits, value is NSS-1)
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

    return {
        "present": True,
        "mac_cap": eht_mac_cap,
        "phy_cap_nonzero": eht_phy_cap_val != 0,
        "mcs_map_80": mcs_map_80,
        "rx_nss_mcs_0_9": rx_nss_0_9,
        "tx_nss_mcs_0_9": tx_nss_0_9,
        "rx_nss_mcs_10_11": rx_nss_10_11,
        "tx_nss_mcs_10_11": tx_nss_10_11,
    }


@pytest.fixture(scope="module")
def ota_interface():
    """Setup local monitor interface (module-scoped)"""
    iface = os.getenv("PROFILER_OTA_INTERFACE", "wlu1u3")
    channel = int(os.getenv("PROFILER_REMOTE_CHANNEL", "36"))

    try:
        subprocess.run(["iw", "dev", iface, "info"], capture_output=True, check=True)
    except subprocess.CalledProcessError:
        pytest.skip(f"Interface {iface} not found")

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

    yield iface


@pytest.fixture(scope="module")
def remote_host():
    """Get remote WLAN Pi SSH target (module-scoped)"""
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

    yield host


def start_profiler_and_capture(
    iface: str, host: str, ssid: str, channel: int = 36
) -> Tuple[Optional[Dot11Beacon], str]:
    """Start profiler and capture beacon (helper function)"""
    # Stop any existing instances
    subprocess.run(
        ["ssh", host, "sudo pkill -9 profiler; sudo pkill -9 hostapd"],
        capture_output=True,
    )
    time.sleep(2)

    # Start profiler
    cmd = (
        f"sudo profiler --ap-mode -c {channel} -s {ssid} "
        f"--security-mode ft-wpa3-mixed --passphrase WLAN PiProfiler "
        f"--debug > /tmp/profiler_regression_{channel}.log 2>&1 &"
    )

    result = subprocess.run(
        ["ssh", host, cmd],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        pytest.fail(f"Failed to start profiler: {result.stderr}")

    time.sleep(6)

    # Verify running
    check = subprocess.run(
        ["ssh", host, "pgrep -f 'profiler --ap-mode'"],
        capture_output=True,
        text=True,
    )

    if not check.stdout.strip():
        log_result = subprocess.run(
            ["ssh", host, f"cat /tmp/profiler_regression_{channel}.log 2>&1"],
            capture_output=True,
            text=True,
        )
        pytest.fail(f"Profiler failed to start. Log:\n{log_result.stdout}")

    # Capture beacon
    beacons = []
    filter_str = "type mgt subtype beacon"

    def ssid_filter(pkt):
        if pkt.haslayer(Dot11Beacon):
            try:
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 0:
                        if elt.info.decode("utf-8", errors="ignore") == ssid:
                            beacons.append(pkt)
                            if len(beacons) >= 3:
                                return True
                    elt = elt.payload.getlayer(Dot11Elt)
            except Exception:
                pass
        return False

    try:
        sniff(
            iface=iface,
            prn=ssid_filter,
            filter=filter_str,
            timeout=15,
            store=False,
        )
    except Exception as e:
        pytest.fail(f"Failed to capture beacon: {e}")

    # Get log
    log_result = subprocess.run(
        ["ssh", host, f"cat /tmp/profiler_regression_{channel}.log 2>&1"],
        capture_output=True,
        text=True,
    )

    beacon = beacons[0] if beacons else None
    return beacon, log_result.stdout


@pytest.fixture(scope="module")
def profiler_log_5ghz(remote_host):
    """Start profiler on 5 GHz and return log (for log-only tests)"""
    ssid = "REGRESSION-LOG-5GHZ"
    channel = 36

    # Cleanup any existing profiler instances
    subprocess.run(
        ["ssh", remote_host, "sudo pkill -9 profiler; sudo pkill -9 hostapd"],
        capture_output=True,
    )
    time.sleep(1)

    # Start profiler
    cmd = (
        f"sudo profiler --ap-mode -c {channel} -s {ssid} "
        f"--security-mode ft-wpa3-mixed --passphrase WLAN PiProfiler "
        f"--debug > /tmp/profiler_regression_{channel}.log 2>&1 &"
    )

    result = subprocess.run(
        ["ssh", remote_host, cmd],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        pytest.fail(f"Failed to start profiler: {result.stderr}")

    time.sleep(6)  # Wait for profiler to start

    # Get the log
    log_result = subprocess.run(
        ["ssh", remote_host, f"cat /tmp/profiler_regression_{channel}.log 2>&1"],
        capture_output=True,
        text=True,
    )

    yield {"log": log_result.stdout, "host": remote_host}

    # Cleanup
    subprocess.run(
        ["ssh", remote_host, "sudo pkill -9 profiler; sudo pkill -9 hostapd"],
        capture_output=True,
    )


@pytest.fixture(scope="module")
def beacon_5ghz(ota_interface, remote_host):
    """Capture 5 GHz beacon (module-scoped)"""
    ssid = "REGRESSION-5GHZ"
    beacon, log = start_profiler_and_capture(
        ota_interface, remote_host, ssid, channel=36
    )

    if not beacon:
        pytest.fail(f"No beacons captured for {ssid}")

    yield {"beacon": beacon, "log": log, "host": remote_host}

    # Cleanup
    subprocess.run(
        ["ssh", remote_host, "sudo pkill -9 profiler; sudo pkill -9 hostapd"],
        capture_output=True,
    )


@pytest.fixture(scope="module")
def beacon_2ghz(ota_interface, remote_host):
    """Capture 2.4 GHz beacon on channel 6 (module-scoped)"""
    # Reconfigure monitor interface for 2.4 GHz channel 6
    # Note: Channel 6 is used instead of channel 1 because it works better with HT40
    try:
        subprocess.run(
            ["sudo", "iw", "dev", ota_interface, "set", "channel", "6"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        pytest.skip(f"Failed to set 2.4 GHz channel 6: {e}")

    ssid = "REGRESSION-24GHZ"
    beacon, log = start_profiler_and_capture(
        ota_interface, remote_host, ssid, channel=6
    )

    if not beacon:
        pytest.skip("No beacons captured for 2.4 GHz test on channel 6")

    yield {"beacon": beacon, "log": log, "host": remote_host}

    # Cleanup
    subprocess.run(
        ["ssh", remote_host, "sudo pkill -9 profiler; sudo pkill -9 hostapd"],
        capture_output=True,
    )


class Test5GHzPatches:
    """Test all patches on 5 GHz band"""

    def test_5ghz_nss_across_all_technologies(self, beacon_5ghz):
        """
        Test: Verify 4 spatial streams advertised across HT, VHT, HE, and EHT

        Expected:
        - HT: 4 SS (MCS bytes 0-3 = 0xFF)
        - VHT: 4 SS (MCS Map = 0xffaa)
        - HE: 4 SS for both 80 MHz and 160 MHz (MCS Maps = 0xffaa)
        - EHT: 4 SS (NSS values = 3, meaning 4 SS)
        """
        beacon = beacon_5ghz["beacon"]

        # Parse all capabilities
        ht = parse_ht_nss_and_caps(get_ie(beacon, 0x2D))
        vht = parse_vht_nss_and_width(get_ie(beacon, 0xBF))
        he = parse_he_nss_and_width(get_extension_ie(beacon, 0x23))
        eht = parse_eht_nss(get_extension_ie(beacon, 0x6C))

        failures = []

        # HT NSS
        if not ht.get("present"):
            failures.append("HT Capabilities missing")
        elif ht["nss"] != 4:
            failures.append(
                f"HT NSS: {ht['nss']} (expected 4). MCS bytes: {ht['mcs_bytes']}"
            )

        # VHT NSS
        if not vht.get("present"):
            failures.append("VHT Capabilities missing")
        elif vht["nss"] != 4:
            failures.append(
                f"VHT NSS: {vht['nss']} (expected 4). Rx MCS Map: {vht['rx_mcs_map']}"
            )

        # HE NSS
        if not he.get("present"):
            failures.append("HE Capabilities missing")
        else:
            if he.get("nss_80mhz") != 4:
                failures.append(
                    f"HE 80MHz NSS: {he.get('nss_80mhz')} (expected 4). Rx MCS: {he.get('rx_mcs_80')}"
                )
            if "nss_160mhz" in he and he["nss_160mhz"] != 4:
                failures.append(
                    f"HE 160MHz NSS: {he['nss_160mhz']} (expected 4). Rx MCS: {he.get('rx_mcs_160')}"
                )

        # EHT NSS
        if not eht.get("present"):
            failures.append("EHT Capabilities missing")
        else:
            if eht["rx_nss_mcs_0_9"] != 4:
                failures.append(
                    f"EHT Rx NSS MCS 0-9: {eht['rx_nss_mcs_0_9']} (expected 4)"
                )
            if eht["tx_nss_mcs_0_9"] != 4:
                failures.append(
                    f"EHT Tx NSS MCS 0-9: {eht['tx_nss_mcs_0_9']} (expected 4)"
                )
            if eht["rx_nss_mcs_10_11"] != 4:
                failures.append(
                    f"EHT Rx NSS MCS 10-11: {eht['rx_nss_mcs_10_11']} (expected 4)"
                )
            if eht["tx_nss_mcs_10_11"] != 4:
                failures.append(
                    f"EHT Tx NSS MCS 10-11: {eht['tx_nss_mcs_10_11']} (expected 4)"
                )

        if failures:
            pytest.fail(
                "5 GHz NSS verification failed:\n"
                + "\n".join(f"  - {f}" for f in failures)
            )

    def test_5ghz_channel_width_across_technologies(self, beacon_5ghz):
        """
        Test: Verify 160 MHz capability advertised in VHT and HE

        Expected:
        - VHT: Supports 160 MHz (Channel Width Set = 1 or 2)
        - HE: Supports 160 MHz (PHY Cap byte 0, bit 3 = 1)
        - HE: 160 MHz MCS maps present
        """
        beacon = beacon_5ghz["beacon"]

        vht = parse_vht_nss_and_width(get_ie(beacon, 0xBF))
        he = parse_he_nss_and_width(get_extension_ie(beacon, 0x23))

        failures = []

        # VHT 160 MHz
        if not vht.get("present"):
            failures.append("VHT Capabilities missing")
        elif not vht["supports_160mhz"]:
            failures.append(
                f"VHT does not advertise 160 MHz. "
                f"Chan Width Set: {vht['chan_width_set']} ({vht['chan_width_desc']})"
            )

        # HE 160 MHz
        if not he.get("present"):
            failures.append("HE Capabilities missing")
        else:
            if not he["supports_160mhz"]:
                failures.append(
                    f"HE does not advertise 160 MHz in PHY caps. "
                    f"PHY Cap byte 0: {he['phy_cap_byte_0']}"
                )
            if "rx_mcs_160" not in he:
                failures.append("HE 160 MHz MCS maps not present in beacon")

        if failures:
            pytest.fail(
                "5 GHz channel width verification failed:\n"
                + "\n".join(f"  - {f}" for f in failures)
            )

    def test_5ghz_ht_txbf_capabilities(self, beacon_5ghz):
        """
        Test: Verify HT TxBF capabilities set to 0x1fffffff

        Patch: hostapd_ht_txbf.patch
        """
        beacon = beacon_5ghz["beacon"]
        ht = parse_ht_nss_and_caps(get_ie(beacon, 0x2D))

        assert ht.get("present"), "HT Capabilities missing"
        assert ht["txbf_enabled"], (
            f"HT TxBF not enabled. TxBF Cap: {ht['txbf_cap']} (expected 0x1fffffff)"
        )

    def test_5ghz_eht_mac_capabilities(self, beacon_5ghz):
        """
        Test: Verify EHT MAC capabilities set to 0x00b3

        Patch: hostapd_eht_mac_caps.patch
        """
        beacon = beacon_5ghz["beacon"]
        eht = parse_eht_nss(get_extension_ie(beacon, 0x6C))

        assert eht.get("present"), "EHT Capabilities missing"
        assert eht["mac_cap"] == 0x00B3, (
            f"EHT MAC capabilities incorrect. Got: 0x{eht['mac_cap']:04x}, Expected: 0x00b3"
        )

    def test_5ghz_eht_phy_capabilities(self, beacon_5ghz):
        """
        Test: Verify EHT PHY capabilities are enhanced (non-zero)

        Patch: hostapd_eht_phy_caps.patch
        """
        beacon = beacon_5ghz["beacon"]
        eht = parse_eht_nss(get_extension_ie(beacon, 0x6C))

        assert eht.get("present"), "EHT Capabilities missing"
        assert eht["phy_cap_nonzero"], (
            "EHT PHY capabilities are zero (patch not applied)"
        )

    def test_5ghz_system_patches_logged(self, beacon_5ghz):
        """
        Test: Verify system patches (capability validation bypass) are logged

        Patches: capability_validation_bypass.patch
        """
        log = beacon_5ghz["log"]

        required_messages = [
            "PROFILER: Bypassing HT/VHT/HE/EHT capability validation",
        ]

        missing = []
        for msg in required_messages:
            if msg not in log:
                missing.append(msg)

        if missing:
            pytest.fail(
                "Missing system patch log messages:\n"
                + "\n".join(f"  - {m}" for m in missing)
            )

    def test_5ghz_all_patch_log_messages(self, profiler_log_5ghz):
        """
        Test: Verify all patch log messages are present

        This confirms all patches are active
        (Log-only test - no OTA capture required)
        """
        log = profiler_log_5ghz["log"]

        required_messages = [
            "PROFILER: Advertising HT 4 SS support",
            "PROFILER: Enabled HT TxBF capabilities: 0x1fffffff",
            "PROFILER: Advertising VHT 4 SS support",
            "PROFILER: Advertising HE 160 MHz capability",
            "PROFILER: Advertising HE 4 SS support",
            "PROFILER: Advertising EHT 4 SS support",
            "PROFILER: Override EHT MAC caps to 0x00b3",
            "PROFILER: Enhanced EHT PHY caps",
            "PROFILER: Enabled Extended Capability - SCS (Stream Classification Service)",
            "PROFILER: Enabled Extended Capability - TWT Responder",
            "PROFILER: Enabled Extended Capability - FILS",
        ]

        missing = []
        for msg in required_messages:
            if msg not in log:
                missing.append(msg)

        if missing:
            pytest.fail(
                "Missing patch log messages:\n" + "\n".join(f"  - {m}" for m in missing)
            )


class Test24GHzPatches:
    """Test patches on 2.4 GHz band (channel 6, HT20 only)"""

    def test_24ghz_nss_across_technologies(self, beacon_2ghz):
        """
        Test: Verify 4 spatial streams advertised across HT/HE/EHT on 2.4 GHz

        Requirements:
        - Channel 1 (2.4 GHz)
        - HT: 4 SS (MCS bytes 0-3 = 0xFF)
        - VHT: Not present (2.4 GHz doesn't support VHT)
        - HE: 4 SS (no 160 MHz support)
        - EHT: 4 SS
        """
        beacon = beacon_2ghz["beacon"]

        ht = parse_ht_nss_and_caps(get_ie(beacon, 0x2D))
        vht = parse_vht_nss_and_width(get_ie(beacon, 0xBF))
        he = parse_he_nss_and_width(get_extension_ie(beacon, 0x23))
        eht = parse_eht_nss(get_extension_ie(beacon, 0x6C))

        failures = []

        # HT NSS (should be 4)
        if not ht.get("present"):
            failures.append("HT Capabilities missing")
        elif ht["nss"] != 4:
            failures.append(
                f"HT NSS: {ht['nss']} (expected 4). MCS bytes: {ht['mcs_bytes']}"
            )

        # VHT should NOT be present in 2.4 GHz
        if vht.get("present"):
            failures.append("VHT Capabilities present in 2.4 GHz (should not be)")

        # HE should be present with 4 SS but no 160 MHz
        if not he.get("present"):
            failures.append("HE Capabilities missing in 2.4 GHz")
        else:
            if he.get("supports_160mhz"):
                failures.append("HE advertises 160 MHz in 2.4 GHz (should not)")
            he_nss = he.get("nss_80mhz", 0)
            if he_nss != 4:
                failures.append(f"HE NSS: {he_nss} (expected 4)")

        # EHT should be present with 4 SS
        if not eht.get("present"):
            failures.append("EHT Capabilities missing in 2.4 GHz")
        elif eht["rx_nss_mcs_0_9"] != 4:
            failures.append(f"EHT NSS: {eht['rx_nss_mcs_0_9']} (expected 4)")

        if failures:
            pytest.fail(
                "2.4 GHz NSS verification failed:\n"
                + "\n".join(f"  - {f}" for f in failures)
            )

    def test_24ghz_channel_width_20mhz(self, beacon_2ghz):
        """
        Test: Verify 20 MHz channel width in 2.4 GHz (HT20 only, no HT40)

        Requirements:
        - HT: Present (20 MHz, no 40 MHz due to hardware limitations)
        - VHT: Not present
        - HE: Present but no 160 MHz
        - Operating on channel 6
        """
        beacon = beacon_2ghz["beacon"]

        ht = parse_ht_nss_and_caps(get_ie(beacon, 0x2D))
        vht = parse_vht_nss_and_width(get_ie(beacon, 0xBF))
        he = parse_he_nss_and_width(get_extension_ie(beacon, 0x23))

        failures = []

        # HT should be present (20 MHz operation)
        if not ht.get("present"):
            failures.append("HT Capabilities missing")

        # VHT should NOT be present in 2.4 GHz
        if vht.get("present"):
            failures.append("VHT present in 2.4 GHz (should not be)")

        # HE should be present but no 160 MHz
        if he.get("present") and he.get("supports_160mhz"):
            failures.append(
                f"HE advertises 160 MHz in 2.4 GHz. "
                f"PHY Cap byte 0: {he.get('phy_cap_byte_0')}"
            )

        if failures:
            pytest.fail(
                "2.4 GHz channel width verification failed:\n"
                + "\n".join(f"  - {f}" for f in failures)
            )

    def test_24ghz_ht_txbf_capabilities(self, beacon_2ghz):
        """
        Test: Verify HT TxBF capabilities in 2.4 GHz

        Requirements:
        - HT TxBF: 0x1fffffff (all capabilities enabled)
        - Same as 5 GHz
        """
        beacon = beacon_2ghz["beacon"]
        log = beacon_2ghz["log"]

        ht = parse_ht_nss_and_caps(get_ie(beacon, 0x2D))

        failures = []

        if not ht.get("present"):
            failures.append("HT Capabilities missing")
        elif ht["txbf_cap"] != 0x1FFFFFFF:
            failures.append(f"HT TxBF: 0x{ht['txbf_cap']:08x} (expected 0x1fffffff)")

        # Verify log message
        if "PROFILER: Enabled HT TxBF capabilities: 0x1fffffff" not in log:
            failures.append("HT TxBF log message missing")

        if failures:
            pytest.fail(
                "2.4 GHz HT TxBF verification failed:\n"
                + "\n".join(f"  - {f}" for f in failures)
            )

    def test_24ghz_eht_mac_capabilities(self, beacon_2ghz):
        """
        Test: Verify EHT MAC capabilities in 2.4 GHz

        Requirements:
        - EHT MAC: 0x00b3 (EPCS, OM, R-TWT, SCS)
        - Same as 5 GHz
        """
        beacon = beacon_2ghz["beacon"]
        log = beacon_2ghz["log"]

        eht = parse_eht_nss(get_extension_ie(beacon, 0x6C))

        failures = []

        if not eht.get("present"):
            failures.append("EHT Capabilities missing")
        elif eht.get("mac_cap") != 0x00B3:
            failures.append(f"EHT MAC: 0x{eht.get('mac_cap'):04x} (expected 0x00b3)")

        # Verify log message
        if "PROFILER: Override EHT MAC caps to 0x00b3" not in log:
            failures.append("EHT MAC caps log message missing")

        if failures:
            pytest.fail(
                "2.4 GHz EHT MAC verification failed:\n"
                + "\n".join(f"  - {f}" for f in failures)
            )

    def test_24ghz_eht_phy_capabilities(self, beacon_2ghz):
        """
        Test: Verify EHT PHY capabilities in 2.4 GHz

        Requirements:
        - Enhanced EHT PHY caps (same as 5 GHz)
        - SU/MU Beamforming, PSR, Power Boost, MCS 14/15, 20MHz caps
        """
        beacon = beacon_2ghz["beacon"]
        log = beacon_2ghz["log"]

        eht_ie = get_extension_ie(beacon, 0x6C)

        failures = []

        if not eht_ie:
            failures.append("EHT Capabilities IE missing")
        else:
            # Verify log message indicating enhanced PHY caps
            if "PROFILER: Enhanced EHT PHY caps" not in log:
                failures.append("EHT PHY caps log message missing")

        if failures:
            pytest.fail(
                "2.4 GHz EHT PHY verification failed:\n"
                + "\n".join(f"  - {f}" for f in failures)
            )
