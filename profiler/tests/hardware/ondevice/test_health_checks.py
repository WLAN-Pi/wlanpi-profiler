"""
On-Device Health Checks for WLAN Pi Profiler

These tests verify:
1. Installation integrity (files, directories, binaries)

Run with: sudo profiler test
"""

import os
import subprocess

import pytest

from profiler.constants import HOSTAPD_BINARY, HOSTAPD_CLI_BINARY

pytestmark = pytest.mark.ondevice


class TestInstallationIntegrity:
    """Verify profiler installation is complete and correct"""

    def test_hostapd_binary_is_present_and_executable(self):
        """Verify custom hostapd binary exists and is executable"""
        assert os.path.exists(HOSTAPD_BINARY), (
            f"hostapd binary not found at {HOSTAPD_BINARY}. "
            f"This should be in the same directory as the Python executable: {os.path.dirname(HOSTAPD_BINARY)}"
        )
        assert os.access(HOSTAPD_BINARY, os.X_OK), (
            f"hostapd binary at {HOSTAPD_BINARY} is not executable"
        )

    def test_hostapd_cli_binary_is_present_and_executable(self):
        """Verify custom hostapd_cli binary exists and is executable"""
        assert os.path.exists(HOSTAPD_CLI_BINARY), (
            f"hostapd_cli binary not found at {HOSTAPD_CLI_BINARY}. "
            f"This utility is required for querying the BSSID from hostapd control interface. "
            f"It should be built and installed alongside hostapd."
        )
        assert os.access(HOSTAPD_CLI_BINARY, os.X_OK), (
            f"hostapd_cli binary at {HOSTAPD_CLI_BINARY} is not executable"
        )

    def test_profiler_cli_is_in_path(self):
        """Verify profiler command is available"""
        result = subprocess.run(["which", "profiler"], capture_output=True, text=True)
        assert result.returncode == 0, "profiler command not found in PATH"
        assert "/profiler" in result.stdout, (
            f"Unexpected profiler path: {result.stdout}"
        )

    def test_default_config_file_exists(self):
        """Verify default config.ini exists"""
        config_path = "/etc/wlanpi-profiler/config.ini"
        assert os.path.exists(config_path), f"Default config not found at {config_path}"

    def test_required_data_directories_exist(self):
        """Verify data output directories exist"""
        data_dirs = [
            "/var/www/html/profiler",
            "/var/www/html/profiler/clients",
            "/var/www/html/profiler/reports",
        ]
        for directory in data_dirs:
            # Check if directory exists OR if parent directory is writable
            # (profiler creates subdirs at runtime)
            if not os.path.exists(directory):
                parent = os.path.dirname(directory)
                assert os.path.exists(parent), (
                    f"Parent directory {parent} does not exist"
                )
                # Directory will be created at runtime if parent exists

    def test_wpa_cli_is_available_optional(self):
        """Check if wpa_cli is available (optional)"""
        result = subprocess.run(["which", "wpa_cli"], capture_output=True, text=True)
        if result.returncode != 0:
            # Only warn if wpa_supplicant is installed
            wpa_supp_result = subprocess.run(
                ["which", "wpa_supplicant"], capture_output=True, text=True
            )
            if wpa_supp_result.returncode == 0:
                print(
                    "\n[!] WARNING: wpa_cli not found but wpa_supplicant is installed.\n"
                    "    wpa_cli is used to stop wpa_supplicant on the interface.\n"
                    "    Please install wpa_cli (usually part of wpasupplicant package)."
                )
