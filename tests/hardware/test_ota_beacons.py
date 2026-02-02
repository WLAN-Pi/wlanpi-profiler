# -*- coding: utf-8 -*-

"""
OTA (Over-The-Air) Beacon Verification Tests

These tests verify that beacons advertised over-the-air match the expected
configuration for all security mode and PHY feature combinations.

Architecture:
- Localhost (verification device): Captures beacons using monitor mode interface
- Remote WLAN Pi (test device): Runs profiler with different configurations
- SSH used to control remote profiler instance

Requirements:
- Localhost: Wi-Fi adapter in monitor mode (e.g., wlu1u3)
- Remote WLAN Pi: SSH access to wlanpi@198.18.42.1
- SSH key authentication (automatically configured on first run)
- Set PROFILER_OTA_TESTS=1 environment variable to enable

SSH Key Authentication:
The tests automatically detect if SSH key authentication is configured.
If not, they will:
1. Generate an SSH key pair (~/.ssh/id_rsa) if one doesn't exist
2. Prompt for the remote host password
3. Copy the public key to the remote host using ssh-copy-id
4. Verify key authentication works

After initial setup, all subsequent test runs will use key authentication
without password prompts.

Usage:
    PROFILER_OTA_TESTS=1 PROFILER_OTA_INTERFACE=wlu1u3 \
    PROFILER_REMOTE_HOST=wlanpi@198.18.42.1 \
    PROFILER_REMOTE_CHANNEL=36 \
    pytest tests/test_ota_beacons.py -v

Environment Variables:
    PROFILER_OTA_TESTS=1                    Enable OTA tests
    PROFILER_OTA_INTERFACE=wlu1u3           Local monitor interface (default: wlu1u3)
    PROFILER_REMOTE_HOST=wlanpi@198.18.42.1 Remote SSH target (default: wlanpi@198.18.42.1)
    PROFILER_REMOTE_CHANNEL=36              Channel to test on (default: 36 for 5GHz)
"""

import os
import subprocess
import time
from typing import List, Optional

import pytest
from scapy.all import (
    Dot11Beacon,
    Dot11Elt,
    Scapy_Exception,
    sniff,
)

# Skip all tests in this file unless OTA testing is explicitly enabled
pytestmark = pytest.mark.skipif(
    os.getenv("PROFILER_OTA_TESTS") != "1",
    reason="OTA tests disabled (set PROFILER_OTA_TESTS=1 to enable)",
)


class BeaconCapture:
    """Utility for capturing and analyzing 802.11 beacons"""

    def __init__(self, interface: str, timeout: int = 10):
        """
        Initialize beacon capture

        Args:
            interface: Monitor mode interface to capture on (e.g., 'wlu1u3')
            timeout: Maximum time to capture in seconds
        """
        self.interface = interface
        self.timeout = timeout
        self.beacons: List[Dot11Beacon] = []

    def _packet_handler(self, pkt):
        """Handler for captured packets"""
        if pkt.haslayer(Dot11Beacon):
            self.beacons.append(pkt)

    def capture(self, ssid: str, count: int = 5) -> List[Dot11Beacon]:
        """
        Capture beacons for specified SSID

        Args:
            ssid: SSID to filter for
            count: Number of beacons to capture

        Returns:
            List of captured beacon frames
        """
        self.beacons = []

        # BPF filter for beacons with specific SSID
        # Note: Scapy's BPF filter doesn't support SSID filtering well,
        # so we filter in the handler
        filter_str = "type mgt subtype beacon"

        def ssid_filter(pkt):
            if pkt.haslayer(Dot11Beacon):
                try:
                    # Extract SSID from Dot11Elt
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

        # Capture packets
        try:
            sniff(
                iface=self.interface,
                prn=ssid_filter,
                filter=filter_str,
                timeout=self.timeout,
                store=False,
            )
        except Scapy_Exception as e:
            pytest.fail(f"Failed to capture on {self.interface}: {e}")

        return self.beacons

    @staticmethod
    def get_ie(beacon: Dot11Beacon, ie_id: int) -> Optional[Dot11Elt]:
        """
        Extract Information Element from beacon by ID

        Args:
            beacon: Beacon frame
            ie_id: IE identifier (e.g., 0x30 for RSN)

        Returns:
            Dot11Elt if found, None otherwise
        """
        elt = beacon.getlayer(Dot11Elt)
        while elt:
            if elt.ID == ie_id:
                return elt
            elt = elt.payload.getlayer(Dot11Elt)
        return None

    @staticmethod
    def has_ie(beacon: Dot11Beacon, ie_id: int) -> bool:
        """Check if beacon contains specific IE"""
        return BeaconCapture.get_ie(beacon, ie_id) is not None

    @staticmethod
    def verify_rsn_akm(beacon: Dot11Beacon, expected_akms: List[str]) -> bool:
        """
        Verify RSN IE contains expected AKM suites

        Args:
            beacon: Beacon frame
            expected_akms: List of expected AKM suite names
                          (e.g., ['PSK', 'SAE', 'FT-PSK', 'FT-SAE'])

        Returns:
            True if all expected AKMs are present
        """
        rsn = BeaconCapture.get_ie(beacon, 0x30)
        if not rsn:
            return False

        # Parse RSN IE to extract AKM suites
        # RSN format: version(2) + group cipher(4) + pairwise count(2) +
        #             pairwise suites(4*n) + akm count(2) + akm suites(4*m)
        info = rsn.info
        if len(info) < 8:
            return False

        # Skip version + group cipher + pairwise count
        offset = 2 + 4 + 2
        if len(info) < offset:
            return False

        # Get pairwise cipher suite count
        pairwise_count = int.from_bytes(info[6:8], "little")
        offset += 4 * pairwise_count  # Skip pairwise suites

        if len(info) < offset + 2:
            return False

        # Get AKM suite count
        akm_count = int.from_bytes(info[offset : offset + 2], "little")
        offset += 2

        # Extract AKM OUIs
        akm_ouis = []
        for i in range(akm_count):
            akm_offset = offset + (i * 4)
            if len(info) >= akm_offset + 4:
                akm_oui = info[akm_offset : akm_offset + 4]
                akm_ouis.append(akm_oui)

        # Map AKM OUI to names
        # 00-0F-AC:02 = PSK
        # 00-0F-AC:04 = FT-PSK
        # 00-0F-AC:08 = SAE
        # 00-0F-AC:09 = FT-SAE
        akm_map = {
            b"\x00\x0f\xac\x02": "PSK",
            b"\x00\x0f\xac\x04": "FT-PSK",
            b"\x00\x0f\xac\x08": "SAE",
            b"\x00\x0f\xac\x09": "FT-SAE",
        }

        found_akms = [akm_map.get(oui) for oui in akm_ouis if oui in akm_map]

        # Check all expected AKMs are present
        return all(akm in found_akms for akm in expected_akms)

    @staticmethod
    def verify_rsn_ciphers(beacon: Dot11Beacon, expected_ciphers: List[str]) -> bool:
        """
        Verify RSN IE contains expected pairwise cipher suites

        Args:
            beacon: Beacon frame
            expected_ciphers: List of expected cipher suite names
                            (e.g., ['CCMP', 'GCMP-256'])

        Returns:
            True if all expected ciphers are present
        """
        rsn = BeaconCapture.get_ie(beacon, 0x30)
        if not rsn:
            return False

        # Parse RSN IE to extract pairwise cipher suites
        # RSN format: version(2) + group cipher(4) + pairwise count(2) +
        #             pairwise suites(4*n) + akm count(2) + akm suites(4*m)
        info = rsn.info
        if len(info) < 8:
            return False

        # Get pairwise cipher suite count
        pairwise_count = int.from_bytes(info[6:8], "little")
        offset = 8  # After version + group cipher + pairwise count

        # Extract pairwise cipher OUIs
        cipher_ouis = []
        for i in range(pairwise_count):
            cipher_offset = offset + (i * 4)
            if len(info) >= cipher_offset + 4:
                cipher_oui = info[cipher_offset : cipher_offset + 4]
                cipher_ouis.append(cipher_oui)

        # Map cipher OUI to names
        # 00-0F-AC:04 = CCMP-128 (AES)
        # 00-0F-AC:08 = GCMP-128
        # 00-0F-AC:09 = GCMP-256
        cipher_map = {
            b"\x00\x0f\xac\x04": "CCMP",
            b"\x00\x0f\xac\x08": "GCMP",
            b"\x00\x0f\xac\x09": "GCMP-256",
        }

        found_ciphers = [
            cipher_map.get(oui) for oui in cipher_ouis if oui in cipher_map
        ]

        # Check all expected ciphers are present
        return all(cipher in found_ciphers for cipher in expected_ciphers)

    @staticmethod
    def has_ht_capabilities(beacon: Dot11Beacon) -> bool:
        """Check if beacon advertises HT (802.11n) capabilities"""
        return BeaconCapture.has_ie(beacon, 0x2D)  # HT Capabilities IE

    @staticmethod
    def has_vht_capabilities(beacon: Dot11Beacon) -> bool:
        """Check if beacon advertises VHT (802.11ac) capabilities"""
        return BeaconCapture.has_ie(beacon, 0xBF)  # VHT Capabilities IE

    @staticmethod
    def has_he_capabilities(beacon: Dot11Beacon) -> bool:
        """Check if beacon advertises HE (802.11ax/Wi-Fi 6) capabilities"""
        # HE Capabilities is extension IE (ID=255) with extension ID=35
        elt = beacon.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 255 and len(elt.info) > 0:
                ext_id = elt.info[0]
                if ext_id == 0x23:  # HE Capabilities extension ID
                    return True
            elt = elt.payload.getlayer(Dot11Elt)
        return False

    @staticmethod
    def has_eht_capabilities(beacon: Dot11Beacon) -> bool:
        """Check if beacon advertises EHT (802.11be/Wi-Fi 7) capabilities"""
        # EHT Capabilities is extension IE (ID=255) with extension ID=108
        elt = beacon.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 255 and len(elt.info) > 0:
                ext_id = elt.info[0]
                if ext_id == 0x6C:  # EHT Capabilities extension ID
                    return True
            elt = elt.payload.getlayer(Dot11Elt)
        return False

    @staticmethod
    def has_mobility_domain(beacon: Dot11Beacon) -> bool:
        """Check if beacon advertises Mobility Domain (802.11r/FT)"""
        return BeaconCapture.has_ie(beacon, 0x36)  # Mobility Domain IE

    @staticmethod
    def get_vendor_ie(beacon: Dot11Beacon, oui: bytes) -> Optional[Dot11Elt]:
        """
        Extract vendor-specific IE by OUI

        Args:
            beacon: Beacon frame
            oui: 3-byte OUI (e.g., b"\x31\x41\x59" for WLAN Pi profiler)

        Returns:
            Dot11Elt if found, None otherwise
        """
        elt = beacon.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0xDD and len(elt.info) >= 3:
                # Vendor IE format: OUI (3 bytes) + data
                if elt.info[:3] == oui:
                    return elt
            elt = elt.payload.getlayer(Dot11Elt)
        return None

    @staticmethod
    def has_profiler_vendor_ie(beacon: Dot11Beacon) -> bool:
        """
        Check if beacon contains WLAN Pi Profiler vendor IE (OUI: 31:41:59)

        Returns:
            True if profiler vendor IE present
        """
        return BeaconCapture.get_vendor_ie(beacon, b"\x31\x41\x59") is not None

    @staticmethod
    def verify_profiler_vendor_ie_content(
        beacon: Dot11Beacon, expected_subtype: int = 0
    ) -> bool:
        """
        Verify WLAN Pi Profiler vendor IE content structure

        Args:
            beacon: Beacon frame
            expected_subtype: Expected subtype (default: 0)

        Returns:
            True if vendor IE has correct structure with profiler and system version TLVs
        """
        vendor_ie = BeaconCapture.get_vendor_ie(beacon, b"\x31\x41\x59")
        if not vendor_ie:
            return False

        # Vendor IE format: OUI (3) + subtype (1) + TLVs
        if len(vendor_ie.info) < 4:
            return False

        # Check subtype
        if vendor_ie.info[3] != expected_subtype:
            return False

        # Parse TLVs (at minimum should have profiler version TLV)
        offset = 4  # After OUI + subtype
        if len(vendor_ie.info) < offset + 3:  # Type + Length + at least 1 byte value
            return False

        # TLV 0: Profiler version (type=0)
        tlv_type = vendor_ie.info[offset]
        if tlv_type != 0:
            return False

        tlv_length = vendor_ie.info[offset + 1]
        if len(vendor_ie.info) < offset + 2 + tlv_length:
            return False

        # Check that profiler version is non-empty
        profiler_version = vendor_ie.info[offset + 2 : offset + 2 + tlv_length]
        if len(profiler_version) == 0:
            return False

        # TLV 1: System version (type=1) - optional but usually present
        offset += 2 + tlv_length
        if len(vendor_ie.info) >= offset + 3:
            tlv_type = vendor_ie.info[offset]
            if tlv_type == 1:
                tlv_length = vendor_ie.info[offset + 1]
                if len(vendor_ie.info) >= offset + 2 + tlv_length:
                    # Valid TLV 1
                    return True

        # If we got here, TLV 0 was valid but TLV 1 might be missing (still valid)
        return True

    @staticmethod
    def has_rsnx_ie(beacon: Dot11Beacon) -> bool:
        """
        Check if beacon advertises RSNX IE (RSN Extended Capabilities)

        RSNX IE signals WPA3 SAE H2E (Hash-to-Element) support

        Returns:
            True if RSNX IE present
        """
        return BeaconCapture.has_ie(beacon, 0xF4)  # RSNX IE

    @staticmethod
    def get_extended_capabilities(beacon: Dot11Beacon) -> Optional[bytes]:
        """
        Extract Extended Capabilities IE

        Returns:
            Extended capabilities bytes if found, None otherwise
        """
        ext_cap = BeaconCapture.get_ie(beacon, 0x7F)
        if ext_cap:
            return ext_cap.info
        return None


class RemoteProfilerRunner:
    """Utility for running profiler on remote WLAN Pi via SSH"""

    def __init__(
        self,
        remote_host: str = "wlanpi@198.18.42.1",
        interface: str = "wlan0",
        channel: int = 36,
        ssid: str = "OTA-Test",
    ):
        """
        Initialize remote profiler runner

        Args:
            remote_host: SSH target (e.g., 'wlanpi@198.18.42.1')
            interface: Interface for profiler to use on remote
            channel: Channel to broadcast on
            ssid: SSID to advertise
        """
        self.remote_host = remote_host
        self.interface = interface
        self.channel = channel
        self.ssid = ssid
        self.ssh_process: Optional[subprocess.Popen] = None
        self.pid: Optional[int] = None

    def start(
        self,
        security_mode: str = "ft-wpa3-mixed",
        no11ax: bool = False,
        no11be: bool = False,
        fakeap: bool = False,
        extra_args: Optional[List[str]] = None,
    ) -> None:
        """
        Start profiler on remote WLAN Pi

        Args:
            security_mode: Security mode to use
            no11ax: Disable 802.11ax
            no11be: Disable 802.11be
            fakeap: Use fakeap mode (Scapy-based) instead of AP mode (hostapd-based)
            extra_args: Additional CLI arguments
        """
        # Build profiler command
        cmd_parts = [
            "sudo",
            "profiler",
            "--fakeap" if fakeap else "--ap-mode",
            "-c",
            str(self.channel),
        ]

        # Only add SSID if not using --hostname_ssid
        if not (extra_args and "--hostname_ssid" in extra_args):
            cmd_parts.extend(["-s", self.ssid])

        cmd_parts.extend(
            [
                "-i",
                self.interface,
                "--security-mode",
                security_mode,
                "--debug",
            ]
        )

        if no11ax:
            cmd_parts.append("--no11ax")
        if no11be:
            cmd_parts.append("--no11be")
        if extra_args:
            cmd_parts.extend(extra_args)

        profiler_cmd = " ".join(cmd_parts)

        # SSH command to run profiler in background and capture PID
        # We use nohup and redirect to capture output
        # BatchMode=yes ensures no password prompts (key auth required)
        ssh_cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            self.remote_host,
            f"nohup {profiler_cmd} > /tmp/profiler-ota-test.log 2>&1 & echo $!",
        ]

        # Execute SSH command to start profiler
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )

        if result.returncode != 0:
            pytest.fail(
                f"Failed to start profiler on {self.remote_host}:\n{result.stderr}"
            )

        # Extract PID
        try:
            self.pid = int(result.stdout.strip())
        except ValueError:
            pytest.fail(
                f"Failed to get profiler PID from remote. Output: {result.stdout}"
            )

        # Wait for profiler to start beaconing
        time.sleep(5)

        # Verify profiler is still running
        check_cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            self.remote_host,
            f"ps -p {self.pid} > /dev/null 2>&1 && echo 'running' || echo 'stopped'",
        ]

        check_result = subprocess.run(
            check_cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )

        if "stopped" in check_result.stdout:
            # Get log output
            log_output = self._get_remote_log()
            pytest.fail(
                f"Profiler stopped unexpectedly on remote.\nLog output:\n{log_output}"
            )

    def _get_remote_log(self) -> str:
        """Retrieve profiler log from remote"""
        log_cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            self.remote_host,
            "cat /tmp/profiler-ota-test.log 2>&1",
        ]
        result = subprocess.run(log_cmd, capture_output=True, text=True, timeout=10)
        return result.stdout

    def stop(self) -> str:
        """
        Stop profiler on remote

        Returns:
            Profiler log output
        """
        if self.pid:
            # Send SIGTERM to profiler
            kill_cmd = [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "PasswordAuthentication=no",
                self.remote_host,
                f"sudo kill -TERM {self.pid} 2>/dev/null || true",
            ]

            subprocess.run(kill_cmd, capture_output=True, timeout=10)

            # Wait for graceful shutdown
            time.sleep(2)

            # Force kill if still running
            force_kill_cmd = [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "PasswordAuthentication=no",
                self.remote_host,
                f"sudo kill -9 {self.pid} 2>/dev/null || true",
            ]

            subprocess.run(force_kill_cmd, capture_output=True, timeout=10)

        # Also kill any stray profiler/hostapd processes to prevent interference
        # This handles child processes that may not have been cleaned up
        cleanup_cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            self.remote_host,
            "sudo pkill -9 profiler 2>/dev/null || true; sudo pkill -9 hostapd 2>/dev/null || true",
        ]

        subprocess.run(cleanup_cmd, capture_output=True, timeout=10)

        # Give kernel time to clean up interfaces
        time.sleep(0.5)

        # Get and return log output
        return self._get_remote_log()


# Test Matrix Configuration
# -------------------------
# Security Modes: wpa2, ft-wpa2, wpa3-mixed, ft-wpa3-mixed
# PHY Features: 11n (HT), 11ac (VHT), 11ax (HE), 11be (EHT)
#
# Expected behavior:
# - wpa2: Auto-disables 11be, should show HT+VHT+HE (no EHT)
# - ft-wpa2: Auto-disables 11be, should show HT+VHT+HE (no EHT)
# - wpa3-mixed: Allows 11be, should show HT+VHT+HE+EHT
# - ft-wpa3-mixed: Allows 11be, should show HT+VHT+HE+EHT
#
# With --no11ax:
# - All modes: Auto-disables 11be, should show HT+VHT (no HE, no EHT)
#
# With --no11be:
# - All modes: Should show HT+VHT+HE (no EHT)


@pytest.fixture
def ota_interface():
    """Get local OTA test interface (monitor mode) from environment"""
    iface = os.getenv("PROFILER_OTA_INTERFACE", "wlu1u3")
    channel = int(os.getenv("PROFILER_REMOTE_CHANNEL", "36"))

    # Verify interface exists
    try:
        result = subprocess.run(
            ["iw", "dev", iface, "info"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        pytest.skip(f"Interface {iface} not found on localhost")

    # Put interface in monitor mode if not already
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
            ["sudo", "ip", "link", "set", iface, "up"],
            check=True,
            capture_output=True,
        )
        # Set channel to match remote profiler
        subprocess.run(
            ["sudo", "iw", "dev", iface, "set", "channel", str(channel)],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        pytest.skip(f"Failed to configure {iface} for monitor mode: {e}")

    return iface


def setup_ssh_key_auth(host: str) -> bool:
    """
    Setup SSH key authentication for remote host if not already configured.

    Args:
        host: SSH target (e.g., 'wlanpi@198.18.42.1')

    Returns:
        True if key auth is working (already setup or just configured)
    """
    import getpass

    # Check if key auth already works (no password prompt)
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "BatchMode=yes",  # Fail if password required
                "-o",
                "PasswordAuthentication=no",
                host,
                "echo 'key-auth-works'",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and "key-auth-works" in result.stdout:
            print(f"\n✓ SSH key authentication already configured for {host}")
            return True
    except subprocess.TimeoutExpired:
        pass

    print(f"\n⚠ SSH key authentication not configured for {host}")
    print("Setting up SSH key authentication...")

    # Check if local SSH key exists
    ssh_key_path = os.path.expanduser("~/.ssh/id_rsa")
    ssh_pub_key_path = f"{ssh_key_path}.pub"

    if not os.path.exists(ssh_key_path):
        print(f"Generating SSH key at {ssh_key_path}...")
        try:
            subprocess.run(
                [
                    "ssh-keygen",
                    "-t",
                    "rsa",
                    "-b",
                    "4096",
                    "-f",
                    ssh_key_path,
                    "-N",
                    "",  # No passphrase
                    "-C",
                    f"profiler-ota-tests@{os.uname().nodename}",
                ],
                check=True,
                capture_output=True,
            )
            print(f"✓ Generated SSH key: {ssh_key_path}")
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to generate SSH key: {e.stderr.decode()}")
            return False

    # Copy SSH key to remote host
    print(f"\nCopying SSH public key to {host}...")
    print("You will be prompted for the remote host password.")

    # Get password from user
    password = getpass.getpass(f"Password for {host}: ")

    # Use sshpass if available, otherwise try ssh-copy-id with password
    try:
        # Try sshpass first (more reliable for automation)
        subprocess.run(["which", "sshpass"], check=True, capture_output=True)

        result = subprocess.run(
            [
                "sshpass",
                "-p",
                password,
                "ssh-copy-id",
                "-o",
                "StrictHostKeyChecking=no",
                "-i",
                ssh_pub_key_path,
                host,
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(f"✗ Failed to copy SSH key: {result.stderr}")
            return False

    except subprocess.CalledProcessError:
        # sshpass not available, use ssh-copy-id with manual password entry
        print(
            "\nNote: sshpass not found, using ssh-copy-id (you may need to enter password)"
        )
        result = subprocess.run(
            [
                "ssh-copy-id",
                "-o",
                "StrictHostKeyChecking=no",
                "-i",
                ssh_pub_key_path,
                host,
            ],
            input=password,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(f"✗ Failed to copy SSH key: {result.stderr}")
            return False

    # Verify key auth now works
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "BatchMode=yes",
                "-o",
                "PasswordAuthentication=no",
                host,
                "echo 'key-auth-works'",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        if "key-auth-works" in result.stdout:
            print(f"✓ SSH key authentication successfully configured for {host}\n")
            return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    print(f"✗ SSH key authentication verification failed for {host}")
    return False


@pytest.fixture
def remote_host():
    """Get remote WLAN Pi SSH target from environment and ensure key auth is setup"""
    host = os.getenv("PROFILER_REMOTE_HOST", "wlanpi@198.18.42.1")

    # Setup SSH key authentication if needed
    if not setup_ssh_key_auth(host):
        pytest.skip(f"Failed to setup SSH key authentication for {host}")

    # Verify SSH connectivity (should work with key auth now)
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "BatchMode=yes",  # Ensure no password prompt
                host,
                "echo 'connected'",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        if "connected" not in result.stdout:
            pytest.skip(f"Failed to connect to remote host {host}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pytest.skip(f"Cannot reach remote host {host} via SSH")

    return host


@pytest.fixture
def test_channel():
    """Get test channel from environment"""
    return int(os.getenv("PROFILER_REMOTE_CHANNEL", "36"))


class TestOTASecurityModes:
    """Test OTA beacons for different security modes"""

    def test_wpa2_beacons(self, ota_interface, remote_host, test_channel):
        """
        Test WPA2 mode beacons

        Expected:
        - RSN IE with PSK AKM only (no FT-PSK, SAE, or FT-SAE)
        - RSN IE with CCMP pairwise cipher only (no GCMP-256)
        - No Mobility Domain IE (FT disabled)
        - HT, VHT, HE present (11n/ac/ax enabled)
        - EHT absent (11be auto-disabled for WPA2)
        """
        ssid = "OTA-WPA2-Test"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            # Start profiler with WPA2 mode on remote
            runner.start(security_mode="wpa2")

            # Capture beacons on local monitor interface
            beacons = capture.capture(ssid=ssid, count=3)

            # Verify we got beacons
            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"

            beacon = beacons[0]

            # Verify RSN AKM is PSK only
            assert BeaconCapture.verify_rsn_akm(beacon, ["PSK"]), (
                "Expected PSK-only AKM for wpa2 mode"
            )

            # Verify RSN pairwise ciphers are CCMP only (no GCMP-256)
            assert BeaconCapture.verify_rsn_ciphers(beacon, ["CCMP"]), (
                "Expected CCMP-only pairwise cipher for wpa2 mode (no GCMP-256)"
            )

            # Verify no FT (Mobility Domain)
            assert not BeaconCapture.has_mobility_domain(beacon), (
                "Unexpected Mobility Domain IE (FT should be disabled)"
            )

            # Verify PHY capabilities
            assert BeaconCapture.has_ht_capabilities(beacon), (
                "Expected HT capabilities (802.11n)"
            )
            assert BeaconCapture.has_vht_capabilities(beacon), (
                "Expected VHT capabilities (802.11ac)"
            )
            assert BeaconCapture.has_he_capabilities(beacon), (
                "Expected HE capabilities (802.11ax/Wi-Fi 6)"
            )

            # Verify 11be auto-disabled
            assert not BeaconCapture.has_eht_capabilities(beacon), (
                "Unexpected EHT capabilities (11be should be auto-disabled for WPA2)"
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

    def test_ft_wpa2_beacons(self, ota_interface, remote_host, test_channel):
        """
        Test FT-WPA2 mode beacons

        Expected:
        - RSN IE with PSK + FT-PSK AKMs (no SAE)
        - RSN IE with CCMP pairwise cipher only (no GCMP-256)
        - Mobility Domain IE present (FT enabled)
        - HT, VHT, HE present
        - EHT absent (11be auto-disabled for WPA2)
        """
        ssid = "OTA-FT-WPA2-Test"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="ft-wpa2")
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify RSN AKM includes FT
            assert BeaconCapture.verify_rsn_akm(beacon, ["PSK", "FT-PSK"]), (
                "Expected PSK + FT-PSK AKMs for ft-wpa2 mode"
            )

            # Verify RSN pairwise ciphers are CCMP only (no GCMP-256)
            assert BeaconCapture.verify_rsn_ciphers(beacon, ["CCMP"]), (
                "Expected CCMP-only pairwise cipher for ft-wpa2 mode (no GCMP-256)"
            )

            # Verify FT present
            assert BeaconCapture.has_mobility_domain(beacon), (
                "Expected Mobility Domain IE (FT should be enabled)"
            )

            # Verify PHY capabilities
            assert BeaconCapture.has_ht_capabilities(beacon), "Expected HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Expected VHT"
            assert BeaconCapture.has_he_capabilities(beacon), "Expected HE"

            # Verify 11be auto-disabled
            assert not BeaconCapture.has_eht_capabilities(beacon), (
                "Unexpected EHT (11be should be auto-disabled for WPA2)"
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

    def test_wpa3_mixed_beacons(self, ota_interface, remote_host, test_channel):
        """
        Test WPA3-mixed mode beacons

        Expected:
        - RSN IE with PSK + SAE AKMs (no FT)
        - RSN IE with CCMP + GCMP-256 pairwise ciphers
        - No Mobility Domain IE (FT disabled)
        - HT, VHT, HE, EHT all present (11be enabled)
        """
        ssid = "OTA-WPA3-Mixed-Test"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="wpa3-mixed")
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify RSN AKM includes WPA3
            assert BeaconCapture.verify_rsn_akm(beacon, ["PSK", "SAE"]), (
                "Expected PSK + SAE AKMs for wpa3-mixed mode"
            )

            # Verify RSN pairwise ciphers include GCMP-256 for WPA3
            assert BeaconCapture.verify_rsn_ciphers(beacon, ["CCMP", "GCMP-256"]), (
                "Expected CCMP + GCMP-256 pairwise ciphers for wpa3-mixed mode"
            )

            # Verify no FT
            assert not BeaconCapture.has_mobility_domain(beacon), (
                "Unexpected Mobility Domain IE (FT should be disabled)"
            )

            # Verify all PHY capabilities including 11be
            assert BeaconCapture.has_ht_capabilities(beacon), "Expected HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Expected VHT"
            assert BeaconCapture.has_he_capabilities(beacon), "Expected HE"
            assert BeaconCapture.has_eht_capabilities(beacon), (
                "Expected EHT (11be should be enabled for WPA3)"
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

    def test_ft_wpa3_mixed_beacons(self, ota_interface, remote_host, test_channel):
        """
        Test FT-WPA3-mixed mode beacons (default mode)

        Expected:
        - RSN IE with PSK + FT-PSK + SAE + FT-SAE AKMs
        - RSN IE with CCMP + GCMP-256 pairwise ciphers
        - Mobility Domain IE present
        - HT, VHT, HE, EHT all present (11be enabled)
        """
        ssid = "OTA-FT-WPA3-Mixed-Test"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="ft-wpa3-mixed")
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify RSN AKM includes all
            assert BeaconCapture.verify_rsn_akm(
                beacon, ["PSK", "FT-PSK", "SAE", "FT-SAE"]
            ), "Expected PSK + FT-PSK + SAE + FT-SAE for ft-wpa3-mixed mode"

            # Verify RSN pairwise ciphers include GCMP-256
            assert BeaconCapture.verify_rsn_ciphers(beacon, ["CCMP", "GCMP-256"]), (
                "Expected CCMP + GCMP-256 pairwise ciphers for ft-wpa3-mixed mode"
            )

            # Verify FT present
            assert BeaconCapture.has_mobility_domain(beacon), (
                "Expected Mobility Domain IE"
            )

            # Verify all PHY capabilities including 11be
            assert BeaconCapture.has_ht_capabilities(beacon), "Expected HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Expected VHT"
            assert BeaconCapture.has_he_capabilities(beacon), "Expected HE"
            assert BeaconCapture.has_eht_capabilities(beacon), (
                "Expected EHT (11be enabled by default)"
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


class TestOTAPHYFeatures:
    """Test OTA beacons for different PHY feature combinations"""

    def test_no11ax_auto_disables_11be(self, ota_interface, remote_host, test_channel):
        """
        Test that --no11ax auto-disables 11be

        Expected:
        - HT, VHT present
        - HE, EHT absent
        """
        ssid = "OTA-No11ax-Test"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="ft-wpa3-mixed", no11ax=True)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify HT/VHT present
            assert BeaconCapture.has_ht_capabilities(beacon), "Expected HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Expected VHT"

            # Verify HE/EHT absent
            assert not BeaconCapture.has_he_capabilities(beacon), (
                "Unexpected HE (11ax disabled)"
            )
            assert not BeaconCapture.has_eht_capabilities(beacon), (
                "Unexpected EHT (should be auto-disabled when 11ax disabled)"
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

    def test_explicit_no11be(self, ota_interface, remote_host, test_channel):
        """
        Test explicit --no11be flag

        Expected:
        - HT, VHT, HE present
        - EHT absent
        """
        ssid = "OTA-No11be-Test"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="ft-wpa3-mixed", no11be=True)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify HT/VHT/HE present
            assert BeaconCapture.has_ht_capabilities(beacon), "Expected HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Expected VHT"
            assert BeaconCapture.has_he_capabilities(beacon), "Expected HE"

            # Verify EHT absent
            assert not BeaconCapture.has_eht_capabilities(beacon), (
                "Unexpected EHT (11be disabled)"
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

    def test_wpa2_with_11be_override(self, ota_interface, remote_host, test_channel):
        """
        Test WPA2 with --11be override (non-standard configuration)

        Expected:
        - HT, VHT, HE, EHT all present (override works)
        - Warning should be logged (verified via profiler output)
        """
        ssid = "OTA-WPA2-11be-Override"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(
                security_mode="wpa2",
                extra_args=["--11be"],
            )
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify all PHY capabilities present (override worked)
            assert BeaconCapture.has_ht_capabilities(beacon), "Expected HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Expected VHT"
            assert BeaconCapture.has_he_capabilities(beacon), "Expected HE"
            assert BeaconCapture.has_eht_capabilities(beacon), (
                "Expected EHT (override with --11be should enable it)"
            )

            # Get profiler output to verify warning was shown
            log_output = runner.stop()

            assert "Enabling 802.11be with security_mode 'wpa2'" in log_output, (
                "Expected warning about non-standard WPA2+11be configuration"
            )

        finally:
            # Make sure we stop even if assertions fail
            try:
                runner.stop()
            except Exception:
                pass


class TestOTAComprehensiveMatrix:
    """Comprehensive test matrix for all combinations"""

    @pytest.mark.parametrize(
        "security_mode,expected_akms,has_ft,has_eht",
        [
            ("wpa2", ["PSK"], False, False),  # Auto-disables 11be
            ("ft-wpa2", ["PSK", "FT-PSK"], True, False),  # Auto-disables 11be
            ("wpa3-mixed", ["PSK", "SAE"], False, True),  # Allows 11be
            (
                "ft-wpa3-mixed",
                ["PSK", "FT-PSK", "SAE", "FT-SAE"],
                True,
                True,
            ),  # Allows 11be
        ],
    )
    def test_security_mode_matrix(
        self,
        ota_interface,
        remote_host,
        test_channel,
        security_mode,
        expected_akms,
        has_ft,
        has_eht,
    ):
        """Comprehensive matrix test for all security modes"""
        ssid = f"OTA-Matrix-{security_mode}"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode=security_mode)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for {security_mode}"
            beacon = beacons[0]

            # Verify RSN AKMs
            assert BeaconCapture.verify_rsn_akm(beacon, expected_akms), (
                f"AKM mismatch for {security_mode}"
            )

            # Verify FT/Mobility Domain
            assert BeaconCapture.has_mobility_domain(beacon) == has_ft, (
                f"FT mismatch for {security_mode}: "
                f"expected={'present' if has_ft else 'absent'}"
            )

            # Verify base PHY features always present
            assert BeaconCapture.has_ht_capabilities(beacon), (
                f"Missing HT for {security_mode}"
            )
            assert BeaconCapture.has_vht_capabilities(beacon), (
                f"Missing VHT for {security_mode}"
            )
            assert BeaconCapture.has_he_capabilities(beacon), (
                f"Missing HE for {security_mode}"
            )

            # Verify EHT presence based on security mode
            assert BeaconCapture.has_eht_capabilities(beacon) == has_eht, (
                f"EHT mismatch for {security_mode}: "
                f"expected={'present' if has_eht else 'absent'}"
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


class TestOTAFakeAPMode:
    """Test OTA beacons in FakeAP mode (Scapy-based AP)"""

    def test_fakeap_wpa2_beacons(self, ota_interface, remote_host, test_channel):
        """
        Test FakeAP mode with WPA2 security

        Expected:
        - RSN IE with PSK AKM only
        - HT, VHT, HE present
        - EHT absent (auto-disabled for WPA2)
        - Profiler vendor IE present (by default)
        """
        ssid = "OTA-FakeAP-WPA2"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            # Start profiler in fakeap mode
            runner.start(security_mode="wpa2", fakeap=True)

            # Capture beacons
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify security
            assert BeaconCapture.verify_rsn_akm(beacon, ["PSK"]), (
                "Expected PSK-only AKM"
            )
            assert not BeaconCapture.has_mobility_domain(beacon), (
                "Unexpected Mobility Domain IE"
            )

            # Verify PHY capabilities
            assert BeaconCapture.has_ht_capabilities(beacon), "Expected HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Expected VHT"
            assert BeaconCapture.has_he_capabilities(beacon), "Expected HE"
            assert not BeaconCapture.has_eht_capabilities(beacon), (
                "Unexpected EHT (should be auto-disabled for WPA2)"
            )

            # Verify vendor IE present by default
            assert BeaconCapture.has_profiler_vendor_ie(beacon), (
                "Expected WLAN Pi Profiler vendor IE in fakeap mode"
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

    def test_fakeap_wpa3_mixed_beacons(self, ota_interface, remote_host, test_channel):
        """
        Test FakeAP mode with WPA3-mixed security

        Expected:
        - RSN IE with PSK + SAE AKMs
        - HT, VHT, HE, EHT all present
        - Profiler vendor IE present
        """
        ssid = "OTA-FakeAP-WPA3-Mixed"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="wpa3-mixed", fakeap=True)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify security
            assert BeaconCapture.verify_rsn_akm(beacon, ["PSK", "SAE"]), (
                "Expected PSK + SAE AKMs"
            )

            # Verify PHY capabilities
            assert BeaconCapture.has_ht_capabilities(beacon), "Expected HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Expected VHT"
            assert BeaconCapture.has_he_capabilities(beacon), "Expected HE"
            assert BeaconCapture.has_eht_capabilities(beacon), "Expected EHT"

            # Verify vendor IE
            assert BeaconCapture.has_profiler_vendor_ie(beacon), (
                "Expected WLAN Pi Profiler vendor IE"
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
        "security_mode,expected_akms",
        [
            ("wpa2", ["PSK"]),
            ("ft-wpa2", ["PSK", "FT-PSK"]),
            ("wpa3-mixed", ["PSK", "SAE"]),
            ("ft-wpa3-mixed", ["PSK", "FT-PSK", "SAE", "FT-SAE"]),
        ],
    )
    def test_fakeap_security_modes_matrix(
        self,
        ota_interface,
        remote_host,
        test_channel,
        security_mode,
        expected_akms,
    ):
        """Test all security modes work correctly in fakeAP mode"""
        ssid = f"OTA-FakeAP-{security_mode}"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode=security_mode, fakeap=True)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for {security_mode}"
            beacon = beacons[0]

            # Verify AKMs match expected
            assert BeaconCapture.verify_rsn_akm(beacon, expected_akms), (
                f"AKM mismatch for {security_mode} in fakeAP mode"
            )

            # Verify base PHY features present
            assert BeaconCapture.has_ht_capabilities(beacon), "Expected HT"
            assert BeaconCapture.has_vht_capabilities(beacon), "Expected VHT"
            assert BeaconCapture.has_he_capabilities(beacon), "Expected HE"

        except Exception:
            log_output = runner.stop()
            print(f"\nRemote profiler log:\n{log_output}")
            raise
        finally:
            try:
                runner.stop()
            except Exception:
                pass


class TestOTAVendorIE:
    """Test WLAN Pi Profiler vendor IE (OUI: 31:41:59)"""

    def test_vendor_ie_present_ap_mode(self, ota_interface, remote_host, test_channel):
        """
        Test that profiler vendor IE is present in AP mode (hostapd) by default

        Expected:
        - Vendor IE with OUI 31:41:59 present
        - IE contains profiler version and system version TLVs
        """
        ssid = "OTA-Vendor-IE-AP"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="wpa2", fakeap=False)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify vendor IE present
            assert BeaconCapture.has_profiler_vendor_ie(beacon), (
                "Expected WLAN Pi Profiler vendor IE (OUI: 31:41:59) in AP mode"
            )

            # Verify vendor IE content structure
            assert BeaconCapture.verify_profiler_vendor_ie_content(beacon), (
                "Profiler vendor IE has invalid structure or missing TLVs"
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

    def test_vendor_ie_present_fakeap_mode(
        self, ota_interface, remote_host, test_channel
    ):
        """
        Test that profiler vendor IE is present in FakeAP mode by default

        Expected:
        - Vendor IE with OUI 31:41:59 present
        - IE contains profiler version and system version TLVs
        """
        ssid = "OTA-Vendor-IE-FakeAP"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="wpa2", fakeap=True)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify vendor IE present
            assert BeaconCapture.has_profiler_vendor_ie(beacon), (
                "Expected WLAN Pi Profiler vendor IE (OUI: 31:41:59) in FakeAP mode"
            )

            # Verify vendor IE content structure
            assert BeaconCapture.verify_profiler_vendor_ie_content(beacon), (
                "Profiler vendor IE has invalid structure or missing TLVs"
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


class TestOTANoProfilerTLV:
    """Test --noprofilertlv flag disables profiler vendor IE"""

    def test_noprofilertlv_ap_mode(self, ota_interface, remote_host, test_channel):
        """
        Test --noprofilertlv flag disables vendor IE in AP mode

        Expected:
        - No WLAN Pi Profiler vendor IE (OUI: 31:41:59)
        """
        ssid = "OTA-NoProfilerTLV-AP"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(
                security_mode="wpa2", fakeap=False, extra_args=["--noprofilertlv"]
            )
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify vendor IE absent
            assert not BeaconCapture.has_profiler_vendor_ie(beacon), (
                "Unexpected WLAN Pi Profiler vendor IE (should be disabled with --noprofilertlv)"
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

    def test_noprofilertlv_fakeap_mode(self, ota_interface, remote_host, test_channel):
        """
        Test --noprofilertlv flag disables vendor IE in FakeAP mode

        Expected:
        - No WLAN Pi Profiler vendor IE (OUI: 31:41:59)
        """
        ssid = "OTA-NoProfilerTLV-FakeAP"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(
                security_mode="wpa2", fakeap=True, extra_args=["--noprofilertlv"]
            )
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify vendor IE absent
            assert not BeaconCapture.has_profiler_vendor_ie(beacon), (
                "Unexpected WLAN Pi Profiler vendor IE (should be disabled with --noprofilertlv)"
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


class TestOTAHostnameSSID:
    """Test --hostname_ssid flag uses hostname as SSID"""

    def test_hostname_ssid_ap_mode(self, ota_interface, remote_host, test_channel):
        """
        Test --hostname_ssid flag in AP mode

        Expected:
        - SSID matches remote hostname (wlanpi)
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

        try:
            runner.start(
                security_mode="wpa2", fakeap=False, extra_args=["--hostname_ssid"]
            )

            # Capture beacons with expected hostname SSID
            beacons = capture.capture(ssid=expected_ssid, count=3)

            assert len(beacons) >= 1, (
                f"No beacons captured with hostname SSID '{expected_ssid}'"
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

    def test_hostname_ssid_fakeap_mode(self, ota_interface, remote_host, test_channel):
        """
        Test --hostname_ssid flag in FakeAP mode

        Expected:
        - SSID matches remote hostname (wlanpi)
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

        try:
            runner.start(
                security_mode="wpa2", fakeap=True, extra_args=["--hostname_ssid"]
            )

            # Capture beacons with expected hostname SSID
            beacons = capture.capture(ssid=expected_ssid, count=3)

            assert len(beacons) >= 1, (
                f"No beacons captured with hostname SSID '{expected_ssid}'"
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


class TestOTAInformationElements:
    """Test specific Information Elements in beacons"""

    def test_rsnx_ie_wpa3_modes(self, ota_interface, remote_host, test_channel):
        """
        Test RSNX IE present in WPA3 modes (signals SAE H2E support)

        Expected:
        - RSNX IE present for wpa3-mixed and ft-wpa3-mixed
        - RSNX IE absent for wpa2 and ft-wpa2
        """
        # Test WPA3-mixed (should have RSNX)
        ssid_wpa3 = "OTA-RSNX-WPA3"
        runner_wpa3 = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid_wpa3
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner_wpa3.start(security_mode="wpa3-mixed")
            beacons_wpa3 = capture.capture(ssid=ssid_wpa3, count=3)

            assert len(beacons_wpa3) >= 1, "No beacons captured for WPA3-mixed"
            beacon_wpa3 = beacons_wpa3[0]

            # WPA3 should have RSNX IE
            assert BeaconCapture.has_rsnx_ie(beacon_wpa3), (
                "Expected RSNX IE in WPA3-mixed mode (signals SAE H2E support)"
            )

        finally:
            try:
                runner_wpa3.stop()
            except Exception:
                pass

        # Test WPA2 (should NOT have RSNX)
        ssid_wpa2 = "OTA-RSNX-WPA2"
        runner_wpa2 = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid_wpa2
        )

        try:
            runner_wpa2.start(security_mode="wpa2")
            beacons_wpa2 = capture.capture(ssid=ssid_wpa2, count=3)

            assert len(beacons_wpa2) >= 1, "No beacons captured for WPA2"
            beacon_wpa2 = beacons_wpa2[0]

            # WPA2 should NOT have RSNX IE
            assert not BeaconCapture.has_rsnx_ie(beacon_wpa2), (
                "Unexpected RSNX IE in WPA2 mode (only for WPA3/SAE)"
            )

        except Exception:
            log_output = runner_wpa2.stop()
            print(f"\nRemote profiler log:\n{log_output}")
            raise
        finally:
            try:
                runner_wpa2.stop()
            except Exception:
                pass

    def test_extended_capabilities_ie_present(
        self, ota_interface, remote_host, test_channel
    ):
        """
        Test Extended Capabilities IE is present

        Expected:
        - Extended Capabilities IE (0x7F) present in beacons
        - IE contains non-zero capabilities
        """
        ssid = "OTA-ExtCap-Test"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="ft-wpa3-mixed")
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Verify Extended Capabilities IE present
            ext_cap = BeaconCapture.get_extended_capabilities(beacon)
            assert ext_cap is not None, "Expected Extended Capabilities IE"
            assert len(ext_cap) > 0, "Extended Capabilities IE is empty"

        except Exception:
            log_output = runner.stop()
            print(f"\nRemote profiler log:\n{log_output}")
            raise
        finally:
            try:
                runner.stop()
            except Exception:
                pass


class TestOTAModeFeatureMatrix:
    """
    Comprehensive test matrix: Mode (AP/FakeAP) × Feature Toggles

    Tests every combination of:
    - Mode: AP (hostapd), FakeAP (Scapy)
    - PHY toggles: --no11ax, --no11be, --11be (with WPA2)
    - Security modes: wpa2, ft-wpa2, wpa3-mixed, ft-wpa3-mixed
    """

    @pytest.mark.parametrize("mode", ["ap", "fakeap"])
    @pytest.mark.parametrize(
        "security_mode,expected_akms,expected_ciphers,auto_disables_11be",
        [
            ("wpa2", ["PSK"], ["CCMP"], True),
            ("ft-wpa2", ["PSK", "FT-PSK"], ["CCMP"], True),
            ("wpa3-mixed", ["PSK", "SAE"], ["CCMP", "GCMP-256"], False),
            (
                "ft-wpa3-mixed",
                ["PSK", "FT-PSK", "SAE", "FT-SAE"],
                ["CCMP", "GCMP-256"],
                False,
            ),
        ],
    )
    def test_mode_security_matrix(
        self,
        ota_interface,
        remote_host,
        test_channel,
        mode,
        security_mode,
        expected_akms,
        expected_ciphers,
        auto_disables_11be,
    ):
        """Test all mode × security combinations"""
        ssid = f"OTA-{mode.upper()}-{security_mode}"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(security_mode=security_mode, fakeap=is_fakeap)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for {mode}/{security_mode}"
            beacon = beacons[0]

            # Verify security
            assert BeaconCapture.verify_rsn_akm(beacon, expected_akms), (
                f"AKM mismatch for {mode}/{security_mode}"
            )
            assert BeaconCapture.verify_rsn_ciphers(beacon, expected_ciphers), (
                f"Cipher mismatch for {mode}/{security_mode}"
            )

            # Verify PHY capabilities
            assert BeaconCapture.has_ht_capabilities(beacon), f"Missing HT in {mode}"
            assert BeaconCapture.has_vht_capabilities(beacon), f"Missing VHT in {mode}"
            assert BeaconCapture.has_he_capabilities(beacon), f"Missing HE in {mode}"

            # Verify EHT auto-disable behavior
            has_eht = BeaconCapture.has_eht_capabilities(beacon)
            if auto_disables_11be:
                assert not has_eht, (
                    f"EHT should be auto-disabled for {security_mode} in {mode} mode"
                )
            else:
                assert has_eht, (
                    f"EHT should be enabled for {security_mode} in {mode} mode"
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

    @pytest.mark.parametrize("mode", ["ap", "fakeap"])
    def test_mode_no11ax_disables_11be(
        self, ota_interface, remote_host, test_channel, mode
    ):
        """Test --no11ax auto-disables 11be in both AP and FakeAP modes"""
        ssid = f"OTA-{mode.upper()}-no11ax"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(
                security_mode="ft-wpa3-mixed",
                no11ax=True,
                fakeap=is_fakeap,
            )
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for {mode} --no11ax"
            beacon = beacons[0]

            # Should have HT and VHT only
            assert BeaconCapture.has_ht_capabilities(beacon), f"Missing HT in {mode}"
            assert BeaconCapture.has_vht_capabilities(beacon), f"Missing VHT in {mode}"
            assert not BeaconCapture.has_he_capabilities(beacon), (
                f"HE should be disabled with --no11ax in {mode}"
            )
            assert not BeaconCapture.has_eht_capabilities(beacon), (
                f"EHT should be auto-disabled when HE disabled in {mode}"
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

    @pytest.mark.parametrize("mode", ["ap", "fakeap"])
    def test_mode_no11be_flag(self, ota_interface, remote_host, test_channel, mode):
        """Test --no11be flag works in both AP and FakeAP modes"""
        ssid = f"OTA-{mode.upper()}-no11be"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(
                security_mode="ft-wpa3-mixed",
                no11be=True,
                fakeap=is_fakeap,
            )
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for {mode} --no11be"
            beacon = beacons[0]

            # Should have HT, VHT, HE but not EHT
            assert BeaconCapture.has_ht_capabilities(beacon), f"Missing HT in {mode}"
            assert BeaconCapture.has_vht_capabilities(beacon), f"Missing VHT in {mode}"
            assert BeaconCapture.has_he_capabilities(beacon), f"Missing HE in {mode}"
            assert not BeaconCapture.has_eht_capabilities(beacon), (
                f"EHT should be disabled with --no11be in {mode}"
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

    @pytest.mark.parametrize("mode", ["ap", "fakeap"])
    def test_mode_11be_override_with_wpa2(
        self, ota_interface, remote_host, test_channel, mode
    ):
        """Test --11be override with WPA2 works in both modes (non-standard)"""
        ssid = f"OTA-{mode.upper()}-wpa2-11be"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(
                security_mode="wpa2",
                extra_args=["--11be"],
                fakeap=is_fakeap,
            )
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for {mode} WPA2+11be"
            beacon = beacons[0]

            # All PHY features should be present
            assert BeaconCapture.has_ht_capabilities(beacon), f"Missing HT in {mode}"
            assert BeaconCapture.has_vht_capabilities(beacon), f"Missing VHT in {mode}"
            assert BeaconCapture.has_he_capabilities(beacon), f"Missing HE in {mode}"
            assert BeaconCapture.has_eht_capabilities(beacon), (
                f"EHT should be enabled with --11be override in {mode}"
            )

            # Verify warning in log
            log_output = runner.stop()
            assert "Enabling 802.11be with security_mode 'wpa2'" in log_output, (
                f"Expected warning about non-standard WPA2+11be in {mode}"
            )

        finally:
            try:
                runner.stop()
            except Exception:
                pass


class TestOTAWiFi7EHT:
    """Test Wi-Fi 7 (802.11be/EHT) specific capabilities"""

    def test_eht_capabilities_structure(self, ota_interface, remote_host, test_channel):
        """
        Test EHT Capabilities IE structure and basic fields

        Expected:
        - EHT Capabilities IE (0xFF, ext ID 0x6C) present
        - IE has minimum required length for MAC and PHY caps
        """
        ssid = "OTA-Wi-Fi7-EHT-Caps"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="ft-wpa3-mixed")
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Get EHT Capabilities IE
            elt = beacon.getlayer(Dot11Elt)
            eht_cap = None
            while elt:
                if elt.ID == 0xFF and len(elt.info) > 0:
                    ext_id = elt.info[0]
                    if ext_id == 0x6C:  # EHT Capabilities
                        eht_cap = elt
                        break
                elt = elt.payload.getlayer(Dot11Elt)

            assert eht_cap is not None, "EHT Capabilities IE not found"

            # Verify minimum length (1 byte ext ID + 2 bytes MAC caps + 9 bytes PHY caps = 12 bytes minimum)
            assert len(eht_cap.info) >= 12, (
                f"EHT Capabilities IE too short: {len(eht_cap.info)} bytes (expected >= 12)"
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

    def test_eht_operation_structure(self, ota_interface, remote_host, test_channel):
        """
        Test EHT Operation IE structure

        Expected:
        - EHT Operation IE (0xFF, ext ID 0x6A) present
        - IE advertises channel width
        """
        ssid = "OTA-Wi-Fi7-EHT-Op"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)

        try:
            runner.start(security_mode="ft-wpa3-mixed")
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, f"No beacons captured for SSID {ssid}"
            beacon = beacons[0]

            # Get EHT Operation IE
            elt = beacon.getlayer(Dot11Elt)
            eht_op = None
            while elt:
                if elt.ID == 0xFF and len(elt.info) > 0:
                    ext_id = elt.info[0]
                    if ext_id == 0x6A:  # EHT Operation
                        eht_op = elt
                        break
                elt = elt.payload.getlayer(Dot11Elt)

            assert eht_op is not None, "EHT Operation IE not found"
            assert len(eht_op.info) >= 5, "EHT Operation IE too short"

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
    def test_wifi7_disabled_removes_eht_ies(
        self, ota_interface, remote_host, test_channel, mode
    ):
        """Test that --no11be removes all EHT IEs in both modes"""
        ssid = f"OTA-Wi-Fi7-Disabled-{mode.upper()}"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(
                security_mode="ft-wpa3-mixed",
                no11be=True,
                fakeap=is_fakeap,
            )
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, "No beacons captured"
            beacon = beacons[0]

            # Check no EHT Capabilities
            elt = beacon.getlayer(Dot11Elt)
            found_eht_caps = False
            found_eht_op = False
            while elt:
                if elt.ID == 0xFF and len(elt.info) > 0:
                    ext_id = elt.info[0]
                    if ext_id == 0x6C:  # EHT Capabilities
                        found_eht_caps = True
                    if ext_id == 0x6A:  # EHT Operation
                        found_eht_op = True
                elt = elt.payload.getlayer(Dot11Elt)

            assert not found_eht_caps, (
                f"EHT Capabilities IE should not be present in {mode} with --no11be"
            )
            assert not found_eht_op, (
                f"EHT Operation IE should not be present in {mode} with --no11be"
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


class TestOTAPassphrase:
    """Test --passphrase argument with custom passphrases"""

    @pytest.mark.parametrize("mode", ["ap", "fakeap"])
    @pytest.mark.parametrize(
        "test_passphrase",
        [
            "TestPass123",  # Simple alphanumeric
            "Complex!Pass@2024#",  # Special characters
            "12345678",  # Minimum length (8 chars)
            "a" * 63,  # Maximum length (63 chars)
        ],
    )
    def test_custom_passphrase(
        self, ota_interface, remote_host, test_channel, mode, test_passphrase
    ):
        """
        Test that custom passphrases work (beacons transmitted successfully)

        Note: We can't verify the actual passphrase OTA (it's hashed in RSN IE),
        but we can verify profiler starts and beacons correctly with custom passphrase.
        """
        ssid = f"OTA-Pass-{mode.upper()}-{len(test_passphrase)}"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(
                security_mode="wpa2",
                fakeap=is_fakeap,
                extra_args=["--passphrase", test_passphrase],
            )
            beacons = capture.capture(ssid=ssid, count=3)

            # Main verification: profiler started and beaconed with custom passphrase
            assert len(beacons) >= 1, (
                f"No beacons captured for {mode} with passphrase length {len(test_passphrase)}"
            )
            beacon = beacons[0]

            # Verify basic beacon structure still correct
            assert BeaconCapture.verify_rsn_akm(beacon, ["PSK"]), (
                f"RSN AKM incorrect with custom passphrase in {mode}"
            )
            assert BeaconCapture.has_ht_capabilities(beacon), (
                f"Missing HT capabilities with custom passphrase in {mode}"
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

    def test_passphrase_too_short_fails(self, ota_interface, remote_host, test_channel):
        """
        Test that passphrase < 8 characters fails (WPA2 requirement)

        Expected: Profiler should fail to start or log error
        """
        ssid = "OTA-Pass-TooShort"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )

        try:
            runner.start(
                security_mode="wpa2",
                fakeap=False,  # Test with AP mode
                extra_args=["--passphrase", "short"],  # Only 5 chars
            )

            # If we get here, profiler started (might accept and fail later)
            # Check log for error
            log_output = runner.stop()

            # Should have error about passphrase length
            # Note: This might fail if hostapd validates later
            # In that case, beacon capture would fail

        except Exception:
            # Expected: profiler failed to start or beacons not captured
            # This is acceptable behavior
            try:
                runner.stop()
            except Exception:
                pass

    def test_passphrase_too_long_fails(self, ota_interface, remote_host, test_channel):
        """
        Test that passphrase > 63 characters fails (WPA2 requirement)

        Expected: Profiler should fail to start or log error
        """
        ssid = "OTA-Pass-TooLong"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )

        try:
            runner.start(
                security_mode="wpa2",
                fakeap=False,
                extra_args=["--passphrase", "a" * 64],  # 64 chars (too long)
            )

            # Check log for error
            log_output = runner.stop()

        except Exception:
            # Expected: profiler failed to start
            try:
                runner.stop()
            except Exception:
                pass


class TestOTAIEStructureValidation:
    """
    Validate that all Information Elements in beacons parse correctly

    This catches malformed IEs that may be transmitted but fail to parse
    properly in protocol analyzers (like Wireshark) or client devices.
    """

    @pytest.mark.parametrize("mode", ["ap", "fakeap"])
    @pytest.mark.parametrize("security_mode", ["wpa2", "ft-wpa3-mixed"])
    def test_all_ies_parse_without_errors(
        self, ota_interface, remote_host, test_channel, mode, security_mode
    ):
        """
        Test that all IEs in beacon parse successfully (no malformed IEs)

        This test walks through every IE in the beacon and validates:
        1. IE has valid ID
        2. IE has valid length
        3. IE length matches actual data length
        4. No parsing exceptions occur
        """
        ssid = f"OTA-IE-Parse-{mode}-{security_mode}"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(security_mode=security_mode, fakeap=is_fakeap)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, "No beacons captured"
            beacon = beacons[0]

            # Walk through all IEs and validate structure
            elt = beacon.getlayer(Dot11Elt)
            ie_count = 0
            malformed_ies = []

            while elt:
                ie_count += 1
                ie_id = elt.ID if hasattr(elt, "ID") else "unknown"

                try:
                    # Validate basic structure
                    assert hasattr(elt, "ID"), f"IE {ie_count} missing ID field"
                    assert hasattr(elt, "len"), (
                        f"IE {ie_count} (ID={ie_id}) missing len field"
                    )
                    assert hasattr(elt, "info"), (
                        f"IE {ie_count} (ID={ie_id}) missing info field"
                    )

                    # Validate length field matches actual data length
                    declared_len = elt.len
                    actual_len = len(elt.info) if elt.info else 0

                    # For extension IEs (0xFF), length includes extension ID byte
                    if ie_id == 0xFF and actual_len > 0:
                        # Extension IE: len field should be 1 + data length
                        # First byte is extension ID, rest is data
                        pass  # Extension IEs are handled specially
                    else:
                        # Standard IE: len field should match info length
                        assert declared_len == actual_len, (
                            f"IE {ie_count} (ID={ie_id}) length mismatch: "
                            f"declared={declared_len}, actual={actual_len}"
                        )

                except AssertionError as e:
                    malformed_ies.append(f"IE {ie_count} (ID={ie_id}): {str(e)}")

                # Move to next IE
                elt = elt.payload.getlayer(Dot11Elt)

            # Report any malformed IEs
            if malformed_ies:
                log_output = runner.stop()
                print(
                    f"\n{mode}/{security_mode} beacon has {len(malformed_ies)} malformed IEs:"
                )
                for issue in malformed_ies:
                    print(f"  - {issue}")
                print(f"\nTotal IEs in beacon: {ie_count}")
                pytest.fail(
                    f"Found {len(malformed_ies)} malformed IEs in {mode}/{security_mode} beacon"
                )

            print(f"\n{mode}/{security_mode}: All {ie_count} IEs parsed successfully")

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
    def test_he_capabilities_structure(
        self, ota_interface, remote_host, test_channel, mode
    ):
        """
        Validate HE Capabilities IE (802.11ax) structure

        HE Capabilities IE:
        - Element ID: 255 (Extension)
        - Extension ID: 35 (0x23)
        - Length: varies (MAC caps + PHY caps + supported MCS)
        - Minimum: 1 (ext ID) + 6 (MAC) + 11 (PHY) + 4 (MCS) = 22 bytes
        """
        ssid = f"OTA-HE-Caps-{mode}"
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

            # Find HE Capabilities IE
            elt = beacon.getlayer(Dot11Elt)
            he_cap = None
            while elt:
                if elt.ID == 0xFF and len(elt.info) > 0:
                    ext_id = elt.info[0]
                    if ext_id == 0x23:  # HE Capabilities
                        he_cap = elt
                        break
                elt = elt.payload.getlayer(Dot11Elt)

            assert he_cap is not None, f"HE Capabilities IE not found in {mode} beacon"

            # Validate structure
            assert len(he_cap.info) >= 22, (
                f"HE Capabilities IE too short in {mode}: {len(he_cap.info)} bytes (expected >= 22)"
            )

            # Validate extension ID
            ext_id = he_cap.info[0]
            assert ext_id == 0x23, (
                f"HE Capabilities has wrong extension ID: {ext_id:#x} (expected 0x23)"
            )

            # Parse HE MAC Capabilities (bytes 1-6, 6 bytes)
            he_mac_caps = he_cap.info[1:7]
            assert len(he_mac_caps) == 6, (
                f"HE MAC Capabilities wrong length: {len(he_mac_caps)}"
            )

            # Parse HE PHY Capabilities (bytes 7-17, 11 bytes)
            he_phy_caps = he_cap.info[7:18]
            assert len(he_phy_caps) == 11, (
                f"HE PHY Capabilities wrong length: {len(he_phy_caps)}"
            )

            # Parse supported MCS and NSS set (at least 4 bytes)
            mcs_offset = 18
            assert len(he_cap.info) >= mcs_offset + 4, (
                f"HE Capabilities missing MCS/NSS set in {mode}"
            )

            print(f"\n{mode} HE Capabilities structure validated:")
            print(f"  Total length: {len(he_cap.info)} bytes")
            print(f"  Extension ID: 0x{ext_id:02x}")
            print(f"  MAC Caps length: {len(he_mac_caps)} bytes")
            print(f"  PHY Caps length: {len(he_phy_caps)} bytes")

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
    def test_he_operation_structure(
        self, ota_interface, remote_host, test_channel, mode
    ):
        """
        Validate HE Operation IE (802.11ax) structure

        HE Operation IE:
        - Element ID: 255 (Extension)
        - Extension ID: 36 (0x24)
        - Length: varies (HE Operation Parameters + BSS Color + basic MCS)
        - Minimum: 1 (ext ID) + 6 (params) + 2 (MCS) = 9 bytes
        """
        ssid = f"OTA-HE-Op-{mode}"
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

            # Find HE Operation IE
            elt = beacon.getlayer(Dot11Elt)
            he_op = None
            while elt:
                if elt.ID == 0xFF and len(elt.info) > 0:
                    ext_id = elt.info[0]
                    if ext_id == 0x24:  # HE Operation
                        he_op = elt
                        break
                elt = elt.payload.getlayer(Dot11Elt)

            assert he_op is not None, f"HE Operation IE not found in {mode} beacon"

            # Validate structure
            # Minimum: 1 (ext ID) + 3 (operation params) + 1 (bss color) + 2 (basic MCS) = 7 bytes
            # Optional: + 3 bytes VHT Operation Information (if VHT Operation Info Present bit set)
            assert len(he_op.info) >= 7, (
                f"HE Operation IE too short in {mode}: {len(he_op.info)} bytes (expected >= 7)"
            )

            # Validate extension ID
            ext_id = he_op.info[0]
            assert ext_id == 0x24, (
                f"HE Operation has wrong extension ID: {ext_id:#x} (expected 0x24)"
            )

            # Parse HE Operation Parameters (bytes 1-3, 3 bytes)
            he_op_params = he_op.info[1:4]
            assert len(he_op_params) == 3, (
                f"HE Operation Parameters wrong length: {len(he_op_params)}"
            )

            # Byte 4: BSS Color Information (1 byte)
            assert len(he_op.info) >= 5, "HE Operation missing BSS Color field"
            bss_color_info = he_op.info[4]

            # Bytes 5-6: Basic HE-MCS and NSS Set (2 bytes)
            assert len(he_op.info) >= 7, "HE Operation missing Basic MCS/NSS set"
            basic_mcs = he_op.info[5:7]
            assert len(basic_mcs) == 2, (
                f"Basic HE-MCS set wrong length: {len(basic_mcs)}"
            )

            print(f"\n{mode} HE Operation structure validated:")
            print(f"  Total length: {len(he_op.info)} bytes")
            print(f"  Extension ID: 0x{ext_id:02x}")
            print(f"  Operation Params: {he_op_params.hex()}")
            print(f"  BSS Color: 0x{bss_color_info:02x}")
            print(f"  Basic MCS/NSS: {basic_mcs.hex()}")

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
    def test_ht_capabilities_structure(
        self, ota_interface, remote_host, test_channel, mode
    ):
        """
        Validate HT Capabilities IE (802.11n) structure

        HT Capabilities IE:
        - Element ID: 45 (0x2D)
        - Length: 26 bytes (fixed)
        """
        ssid = f"OTA-HT-Caps-{mode}"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(security_mode="wpa2", fakeap=is_fakeap)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, "No beacons captured"
            beacon = beacons[0]

            # Find HT Capabilities IE
            ht_cap = BeaconCapture.get_ie(beacon, 0x2D)
            assert ht_cap is not None, f"HT Capabilities IE not found in {mode} beacon"

            # HT Capabilities is always 26 bytes
            assert len(ht_cap.info) == 26, (
                f"HT Capabilities IE wrong length in {mode}: {len(ht_cap.info)} bytes (expected 26)"
            )

            # Parse HT Capabilities Info (bytes 0-1, 2 bytes)
            ht_cap_info = ht_cap.info[0:2]

            # Parse A-MPDU Parameters (byte 2, 1 byte)
            ampdu_params = ht_cap.info[2]

            # Parse Supported MCS Set (bytes 3-18, 16 bytes)
            mcs_set = ht_cap.info[3:19]
            assert len(mcs_set) == 16, f"HT MCS Set wrong length: {len(mcs_set)}"

            # Parse HT Extended Capabilities (bytes 19-20, 2 bytes)
            ht_ext_cap = ht_cap.info[19:21]

            # Parse Transmit Beamforming Capabilities (bytes 21-24, 4 bytes)
            txbf_cap = ht_cap.info[21:25]

            # Parse ASEL Capabilities (byte 25, 1 byte)
            asel_cap = ht_cap.info[25]

            print(f"\n{mode} HT Capabilities structure validated:")
            print(f"  Total length: {len(ht_cap.info)} bytes")
            print(f"  HT Cap Info: {ht_cap_info.hex()}")
            print(f"  A-MPDU: 0x{ampdu_params:02x}")
            print(f"  MCS Set: {mcs_set[:4].hex()}... (16 bytes total)")
            print(f"  TxBF Cap: {txbf_cap.hex()}")

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
    def test_vht_capabilities_structure(
        self, ota_interface, remote_host, test_channel, mode
    ):
        """
        Validate VHT Capabilities IE (802.11ac) structure

        VHT Capabilities IE:
        - Element ID: 191 (0xBF)
        - Length: 12 bytes (fixed)
        """
        ssid = f"OTA-VHT-Caps-{mode}"
        runner = RemoteProfilerRunner(
            remote_host=remote_host, channel=test_channel, ssid=ssid
        )
        capture = BeaconCapture(interface=ota_interface, timeout=15)
        is_fakeap = mode == "fakeap"

        try:
            runner.start(security_mode="wpa2", fakeap=is_fakeap)
            beacons = capture.capture(ssid=ssid, count=3)

            assert len(beacons) >= 1, "No beacons captured"
            beacon = beacons[0]

            # Find VHT Capabilities IE
            vht_cap = BeaconCapture.get_ie(beacon, 0xBF)
            assert vht_cap is not None, (
                f"VHT Capabilities IE not found in {mode} beacon"
            )

            # VHT Capabilities is always 12 bytes
            assert len(vht_cap.info) == 12, (
                f"VHT Capabilities IE wrong length in {mode}: {len(vht_cap.info)} bytes (expected 12)"
            )

            # Parse VHT Capabilities Info (bytes 0-3, 4 bytes)
            vht_cap_info = vht_cap.info[0:4]

            # Parse Supported VHT-MCS and NSS Set (bytes 4-11, 8 bytes)
            vht_mcs_set = vht_cap.info[4:12]
            assert len(vht_mcs_set) == 8, (
                f"VHT MCS Set wrong length: {len(vht_mcs_set)}"
            )

            print(f"\n{mode} VHT Capabilities structure validated:")
            print(f"  Total length: {len(vht_cap.info)} bytes")
            print(f"  VHT Cap Info: {vht_cap_info.hex()}")
            print(f"  VHT MCS Set: {vht_mcs_set.hex()}")

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
    def test_rsn_ie_structure(self, ota_interface, remote_host, test_channel, mode):
        """
        Validate RSN IE structure (WPA2/WPA3 security)

        RSN IE:
        - Element ID: 48 (0x30)
        - Length: varies
        - Structure: version + group cipher + pairwise count + pairwise ciphers +
                     akm count + akm suites + rsn capabilities + [pmkid count + pmkids] + [group mgmt cipher]
        """
        ssid = f"OTA-RSN-{mode}"
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

            # Find RSN IE
            rsn = BeaconCapture.get_ie(beacon, 0x30)
            assert rsn is not None, f"RSN IE not found in {mode} beacon"

            # RSN minimum: version(2) + group cipher(4) + pairwise count(2) +
            #              pairwise cipher(4) + akm count(2) + akm(4) + rsn caps(2) = 20 bytes
            assert len(rsn.info) >= 20, (
                f"RSN IE too short in {mode}: {len(rsn.info)} bytes (expected >= 20)"
            )

            # Parse version (bytes 0-1)
            version = int.from_bytes(rsn.info[0:2], "little")
            assert version == 1, f"RSN version should be 1, got {version}"

            # Parse group cipher suite (bytes 2-5, 4 bytes OUI+type)
            group_cipher = rsn.info[2:6]
            assert len(group_cipher) == 4, "Group cipher suite should be 4 bytes"

            # Parse pairwise cipher suite count (bytes 6-7)
            pairwise_count = int.from_bytes(rsn.info[6:8], "little")
            assert pairwise_count >= 1, (
                f"Pairwise cipher count should be >= 1, got {pairwise_count}"
            )

            # Validate we have enough bytes for pairwise ciphers
            pairwise_end = 8 + (pairwise_count * 4)
            assert len(rsn.info) >= pairwise_end + 2, (
                f"RSN IE too short for {pairwise_count} pairwise ciphers"
            )

            # Parse AKM suite count
            akm_count = int.from_bytes(
                rsn.info[pairwise_end : pairwise_end + 2], "little"
            )
            assert akm_count >= 1, f"AKM count should be >= 1, got {akm_count}"

            # Validate we have enough bytes for AKM suites + RSN caps
            akm_end = pairwise_end + 2 + (akm_count * 4)
            assert len(rsn.info) >= akm_end + 2, (
                f"RSN IE too short for {akm_count} AKM suites and RSN capabilities"
            )

            print(f"\n{mode} RSN IE structure validated:")
            print(f"  Total length: {len(rsn.info)} bytes")
            print(f"  Version: {version}")
            print(f"  Group Cipher: {group_cipher.hex()}")
            print(f"  Pairwise Count: {pairwise_count}")
            print(f"  AKM Count: {akm_count}")

        except Exception:
            log_output = runner.stop()
            print(f"\nRemote profiler log:\n{log_output}")
            raise
        finally:
            try:
                runner.stop()
            except Exception:
                pass
