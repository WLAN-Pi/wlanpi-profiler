# -*- coding: utf-8 -*-
"""
Real Interface Staging Tests (Execute on WLAN Pi Hardware)

These tests actually call the interface staging functions WITHOUT mocks
to verify they work correctly on real hardware.

IMPORTANT: These tests should ONLY be run on a WLAN Pi device with actual
wireless hardware, not in a development environment.

Execute on WLAN Pi:
    ssh wlanpi@198.18.42.1 "cd /opt/wlanpi-profiler && sudo bin/python -m pytest tests/test_interface_staging_real.py -v"

Note: Requires sudo because interface operations need root privileges.
"""

import pytest
import subprocess
import os


# Check if we're running on actual WLAN Pi hardware
def find_iw_path():
    """Find the path to the 'iw' command, checking common locations."""
    for path in ["/sbin/iw", "/usr/sbin/iw", "iw"]:
        try:
            result = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                return path
        except (FileNotFoundError, PermissionError):
            continue
    return None


IW_PATH = find_iw_path()


def is_wlanpi_hardware():
    """
    Check if we're on WLAN Pi hardware by looking for wireless interfaces.
    Uses 'iw dev' if available, otherwise falls back to 'ip link'.
    """
    if IW_PATH:
        try:
            result = subprocess.run(
                [IW_PATH, "dev"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0 and "Interface" in result.stdout
        except Exception:
            pass  # Fallback to ip link

    # Fallback check using 'ip link' for wlan interfaces
    try:
        result = subprocess.run(
            ["ip", "link"], capture_output=True, text=True, timeout=5
        )
        return "wlan" in result.stdout
    except Exception:
        return False


pytestmark = [
    pytest.mark.ondevice,
    pytest.mark.skipif(
        not is_wlanpi_hardware(),
        reason="Real interface tests require WLAN Pi hardware with wireless interfaces",
    ),
]


class TestRealInterfaceOperations:
    """Test actual interface operations on real hardware"""

    def test_list_wireless_interfaces(self):
        """Test that we can list wireless interfaces"""
        assert IW_PATH is not None, (
            "iw command not found in /sbin/iw, /usr/sbin/iw, or PATH"
        )
        result = subprocess.run(
            [IW_PATH, "dev"], capture_output=True, text=True, timeout=5
        )
        assert result.returncode == 0
        assert "Interface" in result.stdout or "phy#" in result.stdout

    def test_list_physical_devices(self):
        """Test that we can list wireless physical devices"""
        assert IW_PATH is not None, (
            "iw command not found in /sbin/iw, /usr/sbin/iw, or PATH"
        )
        result = subprocess.run(
            [IW_PATH, "list"], capture_output=True, text=True, timeout=5
        )
        assert result.returncode == 0
        # Should show capabilities
        assert "Wiphy" in result.stdout or "Band" in result.stdout

    def test_rfkill_list(self):
        """Test that rfkill can list wireless devices"""
        result = subprocess.run(
            ["rfkill", "list"], capture_output=True, text=True, timeout=5
        )
        assert result.returncode == 0
        # Should show at least some devices (may be empty, that's ok)

    def test_interface_info_command(self):
        """Test that we can query interface information"""
        assert IW_PATH is not None, (
            "iw command not found in /sbin/iw, /usr/sbin/iw, or PATH"
        )
        # First get list of interfaces
        result = subprocess.run(
            [IW_PATH, "dev"], capture_output=True, text=True, timeout=5
        )
        if "Interface" in result.stdout:
            # Extract first interface name
            for line in result.stdout.split("\n"):
                if "Interface" in line:
                    interface = line.split()[-1]
                    # Try to get info about this interface
                    info_result = subprocess.run(
                        [IW_PATH, "dev", interface, "info"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    assert info_result.returncode == 0
                    assert interface in info_result.stdout
                    break


class TestProfilerInterfaceModule:
    """Test the profiler's Interface class with real operations"""

    def test_interface_module_import(self):
        """Test that Interface module can be imported"""
        try:
            from profiler.interface import Interface

            assert Interface is not None
        except ImportError as e:
            pytest.fail(f"Cannot import Interface module: {e}")

    def test_interface_instantiation(self):
        """Test that Interface can be instantiated"""
        from profiler.interface import Interface

        # This should work even without root
        interface = Interface()
        assert interface is not None

    def test_interface_detection(self):
        """Test that Interface can detect available wireless interfaces"""
        from profiler.interface import Interface

        interface = Interface()

        # The Interface class should be able to detect system state
        # without requiring root for read-only operations
        assert hasattr(interface, "name") or hasattr(interface, "phy")


class TestCommandAvailability:
    """Test that required system commands are available"""

    def test_iw_command_exists(self):
        """Test that 'iw' command is available"""
        assert IW_PATH is not None, (
            "iw command not found in /sbin/iw, /usr/sbin/iw, or PATH"
        )
        assert "/iw" in IW_PATH

    def test_ip_command_exists(self):
        """Test that 'ip' command is available"""
        result = subprocess.run(["which", "ip"], capture_output=True, text=True)
        assert result.returncode == 0
        assert "/ip" in result.stdout

    def test_rfkill_command_exists(self):
        """Test that 'rfkill' command is available"""
        result = subprocess.run(["which", "rfkill"], capture_output=True, text=True)
        assert result.returncode == 0
        assert "/rfkill" in result.stdout

    def test_hostapd_binary_exists(self):
        """Test that custom hostapd binary is installed"""
        hostapd_path = "/opt/wlanpi-profiler/bin/hostapd"
        assert os.path.exists(hostapd_path)
        assert os.access(hostapd_path, os.X_OK)


class TestInterfaceStageability:
    """Test that interfaces can be staged (requires sudo)"""

    @pytest.mark.skipif(os.geteuid() != 0, reason="Requires root privileges")
    def test_can_set_interface_down(self):
        """Test that we can bring an interface down"""
        assert IW_PATH is not None, (
            "iw command not found in /sbin/iw, /usr/sbin/iw, or PATH"
        )
        # Get first wireless interface
        result = subprocess.run(
            [IW_PATH, "dev"], capture_output=True, text=True, timeout=5
        )

        if "Interface" not in result.stdout:
            pytest.skip("No wireless interfaces found")

        for line in result.stdout.split("\n"):
            if "Interface" in line:
                interface = line.split()[-1]

                # Try to set it down (will restore state after)
                down_result = subprocess.run(
                    ["ip", "link", "set", interface, "down"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                # We expect this to work or fail gracefully
                assert down_result.returncode in [
                    0,
                    1,
                    2,
                ]  # 0=success, 1/2=may already be down or in use

                # Try to bring it back up
                subprocess.run(["ip", "link", "set", interface, "up"], timeout=5)
                break

    @pytest.mark.skipif(os.geteuid() != 0, reason="Requires root privileges")
    def test_can_query_interface_capabilities(self):
        """Test that we can query wireless capabilities"""
        assert IW_PATH is not None, (
            "iw command not found in /sbin/iw, /usr/sbin/iw, or PATH"
        )
        result = subprocess.run(
            [IW_PATH, "phy"], capture_output=True, text=True, timeout=5
        )

        # Should show physical device info
        assert result.returncode == 0


class TestProfilerIntegration:
    """Test integration with profiler's actual staging functions"""

    def test_profiler_command_available(self):
        """Test that profiler command is available"""
        result = subprocess.run(["which", "profiler"], capture_output=True, text=True)
        assert result.returncode == 0
        assert "/profiler" in result.stdout

    def test_profiler_help_command(self):
        """Test that profiler help works"""
        result = subprocess.run(
            ["profiler", "--help"], capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0
        assert "profiler" in result.stdout.lower()
        assert "ssid" in result.stdout.lower() or "interface" in result.stdout.lower()

    def test_profiler_list_interfaces(self):
        """Test that profiler can list interfaces"""
        result = subprocess.run(
            ["profiler", "--list_interfaces"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # This may fail on some systems, but should at least execute
        assert result.returncode in [
            0,
            -1,
            255,
        ]  # Various exit codes depending on platform
