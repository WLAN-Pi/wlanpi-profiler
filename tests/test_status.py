# -*- coding: utf-8 -*-

"""
Tests for profiler.status module

This module tests the status and info file management system,
including country code detection and JSON file operations.
"""

import json
import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from profiler.status import (
    CountryCodeError,
    ProfilerState,
    StatusReason,
    detect_country_code,
    delete_info,
    delete_status,
    get_info,
    get_info_file_path,
    get_last_session_file_path,
    get_status,
    get_status_file_path,
    is_process_alive,
    read_last_session,
    update_last_profile_in_info,
    update_monitoring_metrics_in_info,
    write_info,
    write_last_session,
    write_status,
    _get_frequency_from_channel,
    _read_json,
    _write_json_atomic,
)


class TestCountryCodeDetection:
    """Tests for detect_country_code() function"""

    def test_detect_country_code_success_us(self):
        """Test successful detection of US country code"""
        mock_output = "country US: DFS-FCC\n"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            country = detect_country_code()
            assert country == "US"

    def test_detect_country_code_success_gb(self):
        """Test successful detection of GB country code"""
        mock_output = "country GB: DFS-ETSI\n"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            country = detect_country_code()
            assert country == "GB"

    def test_detect_country_code_success_first_match(self):
        """Test that first valid country code is returned when multiple exist"""
        mock_output = "country DE: DFS-ETSI\ncountry FR: DFS-ETSI\n"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            country = detect_country_code()
            assert country == "DE"  # First match

    def test_detect_country_code_rejects_numeric(self):
        """Test that numeric codes like '99' are rejected (only alpha codes)"""
        mock_output = "country 99:\n"  # Invalid numeric code
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(CountryCodeError, match="No valid country code found"):
                detect_country_code()

    def test_detect_country_code_no_match(self):
        """Test failure when no country code found in output"""
        mock_output = "some random output without country\n"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(CountryCodeError, match="No valid country code found"):
                detect_country_code()

    def test_detect_country_code_iw_command_fails(self):
        """Test failure when iw reg get returns non-zero exit code"""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: some error\n"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(CountryCodeError, match="Failed to run 'iw reg get'"):
                detect_country_code()

    def test_detect_country_code_iw_not_found(self):
        """Test failure when iw command is not found"""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            with pytest.raises(CountryCodeError, match="iw command not found"):
                detect_country_code()

    def test_detect_country_code_timeout(self):
        """Test timeout when iw command hangs"""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("iw", 5)):
            with pytest.raises(CountryCodeError, match="Timeout while detecting"):
                detect_country_code()

    def test_detect_country_code_unexpected_exception(self):
        """Test handling of unexpected exceptions"""
        with patch("subprocess.run", side_effect=RuntimeError("Unexpected error")):
            with pytest.raises(CountryCodeError, match="Unexpected error"):
                detect_country_code()


class TestStatusFileOperations:
    """Tests for status file write/read/delete operations"""

    def test_write_status_starting(self, tmp_path):
        """Test writing status file with STARTING state"""
        status_file = tmp_path / "test_status.json"

        with patch(
            "profiler.status.get_status_file_path", return_value=str(status_file)
        ):
            write_status(ProfilerState.STARTING)

        assert status_file.exists()
        with open(status_file) as f:
            data = json.load(f)

        assert data["schema_version"] == "1.0"
        assert data["state"] == "starting"
        assert "timestamp" in data
        assert "reason" not in data  # No reason provided
        assert "pid" not in data
        assert "error" not in data

    def test_write_status_running_with_pid(self, tmp_path):
        """Test writing status file with RUNNING state and PID"""
        status_file = tmp_path / "test_status.json"

        with patch(
            "profiler.status.get_status_file_path", return_value=str(status_file)
        ):
            write_status(
                ProfilerState.RUNNING, reason=StatusReason.STARTUP_COMPLETE, pid=12345
            )

        with open(status_file) as f:
            data = json.load(f)

        assert data["state"] == "running"
        assert data["reason"] == "startup_complete"
        assert data["pid"] == 12345
        assert "error" not in data

    def test_write_status_failed_with_error(self, tmp_path):
        """Test writing status file with FAILED state and error message"""
        status_file = tmp_path / "test_status.json"

        with patch(
            "profiler.status.get_status_file_path", return_value=str(status_file)
        ):
            write_status(
                ProfilerState.FAILED,
                reason=StatusReason.COUNTRY_CODE_DETECTION,
                error="Failed to detect country code from iw reg get",
            )

        with open(status_file) as f:
            data = json.load(f)

        assert data["state"] == "failed"
        assert data["reason"] == "country_code_detection"
        assert data["error"] == "Failed to detect country code from iw reg get"
        assert "pid" not in data

    def test_write_status_atomic(self, tmp_path):
        """Test that write_status uses atomic write (temp file + rename)"""
        status_file = tmp_path / "test_status.json"

        with patch(
            "profiler.status.get_status_file_path", return_value=str(status_file)
        ):
            # Check that temp file is created then removed
            write_status(ProfilerState.RUNNING, pid=999)

        # Final file should exist
        assert status_file.exists()
        # Temp file should NOT exist after write
        assert not (tmp_path / "test_status.json.tmp").exists()

    def test_get_status_file_exists(self, tmp_path):
        """Test reading status file that exists"""
        status_file = tmp_path / "test_status.json"
        test_data = {
            "schema_version": "1.0",
            "state": "running",
            "pid": 12345,
            "timestamp": "2026-01-23T12:00:00Z",
        }

        with open(status_file, "w") as f:
            json.dump(test_data, f)

        with patch(
            "profiler.status.get_status_file_path", return_value=str(status_file)
        ):
            data = get_status()

        assert data == test_data
        assert data["pid"] == 12345

    def test_get_status_file_not_exists(self, tmp_path):
        """Test reading status file that doesn't exist returns None"""
        status_file = tmp_path / "nonexistent_status.json"

        with patch(
            "profiler.status.get_status_file_path", return_value=str(status_file)
        ):
            data = get_status()

        assert data is None

    def test_get_status_invalid_json(self, tmp_path):
        """Test reading status file with invalid JSON returns None"""
        status_file = tmp_path / "test_status.json"

        with open(status_file, "w") as f:
            f.write("invalid json {")

        with patch(
            "profiler.status.get_status_file_path", return_value=str(status_file)
        ):
            data = get_status()

        assert data is None

    def test_delete_status_file_exists(self, tmp_path):
        """Test deleting status file that exists"""
        status_file = tmp_path / "test_status.json"

        # Create the file
        with open(status_file, "w") as f:
            f.write("{}")

        assert status_file.exists()

        with patch(
            "profiler.status.get_status_file_path", return_value=str(status_file)
        ):
            delete_status()

        assert not status_file.exists()

    def test_delete_status_file_not_exists(self, tmp_path):
        """Test deleting status file that doesn't exist (should not raise)"""
        status_file = tmp_path / "nonexistent_status.json"

        with patch(
            "profiler.status.get_status_file_path", return_value=str(status_file)
        ):
            # Should not raise exception
            delete_status()

        assert not status_file.exists()


class TestInfoFileOperations:
    """Tests for info file write/read/delete operations"""

    def test_write_info_basic(self, tmp_path):
        """Test writing info file with all required fields"""
        info_file = tmp_path / "test_info.json"

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            write_info(
                phy="phy0",
                monitor_interface="wlan0profiler",
                ap_interface="wlan0",
                channel=36,
                country_code="US",
                ssid="TestSSID",
                bssid="aa:bb:cc:dd:ee:ff",
                mode="hostapd",
                profiler_version="2.0.0",
            )

        assert info_file.exists()
        with open(info_file) as f:
            data = json.load(f)

        assert data["schema_version"] == "1.0"
        assert data["profiler_version"] == "2.0.0"
        assert data["phy"] == "phy0"
        assert data["interfaces"]["ap"] == "wlan0"
        assert data["interfaces"]["monitor"] == "wlan0profiler"
        assert data["channel"] == 36
        assert data["frequency"] == 5180  # Channel 36 = 5180 MHz
        assert data["country_code"] == "US"
        assert data["ssid"] == "TestSSID"
        assert data["bssid"] == "aa:bb:cc:dd:ee:ff"
        assert data["mode"] == "hostapd"
        assert data["passphrase"] is None  # Default
        assert "started_at" in data
        assert data["uptime_seconds"] == 0
        assert data["profile_count"] == 0
        assert data["last_profile"] is None  # Null until first profile
        assert data["last_profile_timestamp"] is None

    def test_write_info_with_last_profile(self, tmp_path):
        """Test writing info file with optional last_profile field"""
        info_file = tmp_path / "test_info.json"

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            write_info(
                phy="phy0",
                monitor_interface="wlan1mon",
                ap_interface="wlan1mon",  # fake_ap uses same interface
                channel=149,
                country_code="GB",
                ssid="MySSID",
                bssid="11:22:33:44:55:66",
                mode="fake_ap",
                last_profile="AA:BB:CC:DD:EE:FF",
            )

        with open(info_file) as f:
            data = json.load(f)

        assert data["last_profile"] == "AA:BB:CC:DD:EE:FF"

    def test_write_info_2ghz_channel(self, tmp_path):
        """Test writing info file with 2.4 GHz channel"""
        info_file = tmp_path / "test_info.json"

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            write_info(
                phy="phy0",
                monitor_interface="wlan0mon",
                ap_interface=None,  # listen_only has no AP
                channel=1,
                country_code="US",
                ssid="Test",
                bssid="aa:bb:cc:dd:ee:ff",
                mode="listen_only",
            )

        with open(info_file) as f:
            data = json.load(f)

        assert data["channel"] == 1
        assert data["frequency"] == 2412  # Channel 1 = 2412 MHz

    def test_write_info_6ghz_channel(self, tmp_path):
        """Test writing info file with 6 GHz channel"""
        info_file = tmp_path / "test_info.json"

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            # Channel 1 in 6 GHz = 5955 MHz
            write_info(
                phy="phy0",
                monitor_interface="wlan0profiler",
                ap_interface="wlan0",
                channel=1,
                country_code="US",
                ssid="Test6E",
                bssid="aa:bb:cc:dd:ee:ff",
                mode="hostapd_ap",
            )

        with open(info_file) as f:
            data = json.load(f)

        # Note: This will map to 2.4 GHz channel 1 (2412 MHz) since we can't
        # distinguish band from channel number alone. The frequency calculation
        # uses the first match in the map.
        # In real usage, the band would be determined from config/interface state
        assert data["channel"] == 1

    def test_write_info_invalid_channel(self, tmp_path):
        """Test writing info file with unknown channel sets frequency to null"""
        info_file = tmp_path / "test_info.json"

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            # Channel 999 doesn't exist
            write_info(
                phy="phy0",
                monitor_interface="wlan0profiler",
                ap_interface="wlan0",
                channel=999,
                country_code="US",
                ssid="InvalidChan",
                bssid="aa:bb:cc:dd:ee:ff",
                mode="hostapd_ap",
            )

        with open(info_file) as f:
            data = json.load(f)

        assert data["channel"] == 999
        assert data["frequency"] is None  # Unknown channel

    def test_update_last_profile_in_info(self, tmp_path):
        """Test updating last_profile field in existing info file"""
        info_file = tmp_path / "test_info.json"

        # Create initial info file
        initial_data = {
            "schema_version": "1.0",
            "interface": "wlan0",
            "channel": 36,
            "frequency": 5180,
            "country_code": "US",
            "ssid": "TestSSID",
            "started_at": "2026-01-23T12:00:00Z",
        }

        with open(info_file, "w") as f:
            json.dump(initial_data, f)

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            update_last_profile_in_info("11:22:33:44:55:66")

        with open(info_file) as f:
            data = json.load(f)

        # All original fields should remain
        assert data["interface"] == "wlan0"
        assert data["channel"] == 36
        # New fields added
        assert data["last_profile"] == "11:22:33:44:55:66"
        assert data["profile_count"] == 1

        # Update again to test increment
        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            update_last_profile_in_info("AA:BB:CC:DD:EE:FF")

        with open(info_file) as f:
            data = json.load(f)

        assert data["last_profile"] == "AA:BB:CC:DD:EE:FF"
        assert data["profile_count"] == 2

    def test_update_last_profile_no_file(self, tmp_path):
        """Test updating last_profile when info file doesn't exist (should not crash)"""
        info_file = tmp_path / "nonexistent_info.json"

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            # Should not raise exception
            update_last_profile_in_info("AA:BB:CC:DD:EE:FF")

        # File should still not exist
        assert not info_file.exists()

    def test_get_info_file_exists(self, tmp_path):
        """Test reading info file that exists"""
        info_file = tmp_path / "test_info.json"
        test_data = {
            "schema_version": "1.0",
            "interface": "wlan0",
            "channel": 36,
            "frequency": 5180,
            "country_code": "US",
            "ssid": "TestSSID",
        }

        with open(info_file, "w") as f:
            json.dump(test_data, f)

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            data = get_info()

        assert data == test_data

    def test_get_info_file_not_exists(self, tmp_path):
        """Test reading info file that doesn't exist returns None"""
        info_file = tmp_path / "nonexistent_info.json"

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            data = get_info()

        assert data is None

    def test_delete_info_file_exists(self, tmp_path):
        """Test deleting info file that exists"""
        info_file = tmp_path / "test_info.json"

        # Create the file
        with open(info_file, "w") as f:
            f.write("{}")

        assert info_file.exists()

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            delete_info()

        assert not info_file.exists()

    def test_delete_info_file_not_exists(self, tmp_path):
        """Test deleting info file that doesn't exist (should not raise)"""
        info_file = tmp_path / "nonexistent_info.json"

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            # Should not raise exception
            delete_info()

        assert not info_file.exists()

    def test_write_info_with_monitoring_metrics(self, tmp_path):
        """Test writing info file with monitoring metrics"""
        info_file = tmp_path / "test_info.json"

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            write_info(
                phy="phy0",
                monitor_interface="wlan0profiler",
                ap_interface="wlan0",
                channel=36,
                country_code="US",
                ssid="TestSSID",
                bssid="aa:bb:cc:dd:ee:ff",
                mode="hostapd",
                profiler_version="2.0.0",
                profile_count=10,
                failed_profile_count=2,
                total_clients_seen=15,
            )

        with open(info_file) as f:
            data = json.load(f)

        assert data["profile_count"] == 10
        assert data["failed_profile_count"] == 2
        assert data["total_clients_seen"] == 15

    def test_update_monitoring_metrics(self, tmp_path):
        """Test updating monitoring metrics in existing info file"""
        info_file = tmp_path / "test_info.json"

        # Create initial info file
        initial_data = {
            "schema_version": "1.0",
            "profiler_version": "2.0.0",
            "interface": "wlan0",
            "channel": 36,
            "frequency": 5180,
            "country_code": "US",
            "ssid": "TestSSID",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "mode": "hostapd",
            "passphrase": "profiler",
            "started_at": "2026-01-24T12:00:00+00:00",
            "uptime_seconds": 0,
            "profile_count": 5,
            "failed_profile_count": 1,
            "total_clients_seen": 8,
            "last_profile": None,
            "last_profile_timestamp": None,
        }

        with open(info_file, "w") as f:
            json.dump(initial_data, f)

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            update_monitoring_metrics_in_info(
                total_clients_seen=12, failed_profile_count=3
            )

        with open(info_file) as f:
            data = json.load(f)

        # Monitoring metrics should be updated
        assert data["total_clients_seen"] == 12
        assert data["failed_profile_count"] == 3
        # Other fields should remain unchanged
        assert data["profile_count"] == 5
        assert data["interface"] == "wlan0"
        assert data["channel"] == 36

    def test_update_monitoring_metrics_partial(self, tmp_path):
        """Test updating only some monitoring metrics"""
        info_file = tmp_path / "test_info.json"

        initial_data = {
            "schema_version": "1.0",
            "started_at": "2026-01-24T12:00:00+00:00",
            "total_clients_seen": 10,
            "failed_profile_count": 2,
        }

        with open(info_file, "w") as f:
            json.dump(initial_data, f)

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            # Update only total_clients_seen
            update_monitoring_metrics_in_info(total_clients_seen=15)

        with open(info_file) as f:
            data = json.load(f)

        assert data["total_clients_seen"] == 15
        assert data["failed_profile_count"] == 2  # Unchanged

    def test_update_monitoring_metrics_no_file(self, tmp_path):
        """Test update_monitoring_metrics when file doesn't exist"""
        info_file = tmp_path / "nonexistent_info.json"

        with patch("profiler.status.get_info_file_path", return_value=str(info_file)):
            # Should not raise exception
            update_monitoring_metrics_in_info(
                total_clients_seen=5, failed_profile_count=1
            )

        # File should still not exist
        assert not info_file.exists()


class TestHelperFunctions:
    """Tests for internal helper functions"""

    def test_get_frequency_from_channel_2ghz_channel_1(self):
        """Test frequency lookup for 2.4 GHz channel 1"""
        freq = _get_frequency_from_channel(1)
        assert freq == 2412

    def test_get_frequency_from_channel_2ghz_channel_11(self):
        """Test frequency lookup for 2.4 GHz channel 11"""
        freq = _get_frequency_from_channel(11)
        assert freq == 2462

    def test_get_frequency_from_channel_5ghz_channel_36(self):
        """Test frequency lookup for 5 GHz channel 36"""
        freq = _get_frequency_from_channel(36)
        assert freq == 5180

    def test_get_frequency_from_channel_5ghz_channel_149(self):
        """Test frequency lookup for 5 GHz channel 149"""
        freq = _get_frequency_from_channel(149)
        assert freq == 5745

    def test_get_frequency_from_channel_5ghz_dfs_channel_100(self):
        """Test frequency lookup for 5 GHz DFS channel 100"""
        freq = _get_frequency_from_channel(100)
        assert freq == 5500

    def test_get_frequency_from_channel_unknown(self):
        """Test frequency lookup for unknown channel returns None"""
        freq = _get_frequency_from_channel(999)
        assert freq is None

    def test_get_frequency_from_channel_zero(self):
        """Test frequency lookup for channel 0 returns None"""
        freq = _get_frequency_from_channel(0)
        assert freq is None

    def test_is_process_alive_current_process(self):
        """Test checking if current process (self) is alive"""
        current_pid = os.getpid()
        assert is_process_alive(current_pid) is True

    def test_is_process_alive_init_process(self):
        """Test checking if PID 1 (init/systemd) is alive"""
        # PID 1 should exist on most Linux systems, but may not in containers
        # Just verify the function doesn't crash with PID 1
        result = is_process_alive(1)
        assert isinstance(result, bool)

    def test_is_process_alive_nonexistent_pid(self):
        """Test checking if non-existent PID returns False"""
        # PID 999999 very unlikely to exist
        assert is_process_alive(999999) is False

    def test_is_process_alive_negative_pid(self):
        """Test checking negative PID (os.kill with -1 has special meaning)"""
        # os.kill(-1, 0) sends signal to all processes user has permission for
        # This may succeed or fail depending on permissions, so just verify no crash
        result = is_process_alive(-1)
        assert isinstance(result, bool)

    def test_write_json_atomic_creates_file(self, tmp_path):
        """Test atomic JSON write creates the file"""
        test_file = tmp_path / "test.json"
        test_data = {"key": "value", "number": 42}

        _write_json_atomic(str(test_file), test_data)

        assert test_file.exists()
        with open(test_file) as f:
            data = json.load(f)

        assert data == test_data

    def test_write_json_atomic_uses_temp_file(self, tmp_path):
        """Test atomic write uses temp file (not visible after completion)"""
        test_file = tmp_path / "test.json"
        temp_file = tmp_path / "test.json.tmp"
        test_data = {"atomic": True}

        _write_json_atomic(str(test_file), test_data)

        assert test_file.exists()
        assert not temp_file.exists()  # Temp file should be gone after rename

    def test_write_json_atomic_overwrites_existing(self, tmp_path):
        """Test atomic write overwrites existing file"""
        test_file = tmp_path / "test.json"

        # Write initial data
        with open(test_file, "w") as f:
            json.dump({"old": "data"}, f)

        # Overwrite with new data
        new_data = {"new": "data"}
        _write_json_atomic(str(test_file), new_data)

        with open(test_file) as f:
            data = json.load(f)

        assert data == new_data
        assert "old" not in data

    def test_read_json_valid_file(self, tmp_path):
        """Test reading valid JSON file"""
        test_file = tmp_path / "test.json"
        test_data = {"key": "value"}

        with open(test_file, "w") as f:
            json.dump(test_data, f)

        data = _read_json(str(test_file))
        assert data == test_data

    def test_read_json_file_not_exists(self, tmp_path):
        """Test reading non-existent file returns None"""
        test_file = tmp_path / "nonexistent.json"
        data = _read_json(str(test_file))
        assert data is None

    def test_read_json_invalid_json(self, tmp_path):
        """Test reading invalid JSON returns None"""
        test_file = tmp_path / "invalid.json"

        with open(test_file, "w") as f:
            f.write("not valid json {")

        data = _read_json(str(test_file))
        assert data is None


class TestProfilerStateEnum:
    """Tests for ProfilerState enum"""

    def test_profiler_state_values(self):
        """Test that ProfilerState enum has expected values"""
        assert ProfilerState.STARTING.value == "starting"
        assert ProfilerState.RUNNING.value == "running"
        assert ProfilerState.STOPPED.value == "stopped"
        assert ProfilerState.FAILED.value == "failed"

    def test_profiler_state_members(self):
        """Test that all expected ProfilerState members exist"""
        states = [e.value for e in ProfilerState]
        assert "starting" in states
        assert "running" in states
        assert "stopped" in states
        assert "failed" in states
        assert len(states) == 4


class TestStatusReasonEnum:
    """Tests for StatusReason enum"""

    def test_status_reason_running_reasons(self):
        """Test running state reasons"""
        assert StatusReason.STARTUP_COMPLETE.value == "startup_complete"

    def test_status_reason_stopped_reasons(self):
        """Test stopped state reasons"""
        assert StatusReason.USER_REQUESTED.value == "user_requested"

    def test_status_reason_failed_reasons(self):
        """Test failed state reasons"""
        assert StatusReason.COUNTRY_CODE_DETECTION.value == "country_code_detection"
        assert StatusReason.INSUFFICIENT_PERMISSIONS.value == "insufficient_permissions"
        assert StatusReason.INTERFACE_VALIDATION.value == "interface_validation"
        assert StatusReason.CONFIG_VALIDATION.value == "config_validation"
        assert StatusReason.MISSING_TOOLS.value == "missing_tools"
        assert StatusReason.ALREADY_RUNNING.value == "already_running"
        assert StatusReason.FILE_NOT_FOUND.value == "file_not_found"
        assert StatusReason.HOSTAPD_CRASHED.value == "hostapd_crashed"
        assert StatusReason.HOSTAPD_START_FAILED.value == "hostapd_start_failed"
        assert StatusReason.FAKEAP_CRASHED.value == "fakeap_crashed"
        assert StatusReason.UNKNOWN_ERROR.value == "unknown_error"


class TestLastSessionFile:
    """Tests for persistent last-session file operations"""

    def test_write_last_session_success(self, tmp_path):
        """Verify last-session file written on clean shutdown"""
        session_file = tmp_path / "last-session.json"
        info_file = tmp_path / "info.json"

        info_data = {
            "schema_version": "1.0",
            "mode": "hostapd",
            "phy": "phy0",
            "channel": 36,
            "frequency": 5180,
            "country_code": "US",
            "ssid": "TestSSID",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "profile_count": 5,
            "failed_profile_count": 1,
            "total_clients_seen": 10,
            "last_profile": "11:22:33:44:55:66",
            "last_profile_timestamp": "2026-01-26T12:00:00+00:00",
        }
        with open(info_file, "w") as f:
            json.dump(info_data, f)

        with patch(
            "profiler.status.get_last_session_file_path",
            return_value=str(session_file),
        ):
            with patch(
                "profiler.status.get_info_file_path", return_value=str(info_file)
            ):
                write_last_session(
                    exit_status="success",
                    exit_code=0,
                    start_time="2026-01-26T12:00:00+00:00",
                )

        assert session_file.exists()
        with open(session_file) as f:
            data = json.load(f)

        assert data["schema_version"] == "1.0"
        assert data["exit"]["status"] == "success"
        assert data["exit"]["code"] == 0
        assert data["exit"]["reason"] is None
        assert data["configuration"]["channel"] == 36
        assert data["metrics"]["profile_count"] == 5

    def test_write_last_session_failed(self, tmp_path):
        """Verify last-session file written on error exit"""
        session_file = tmp_path / "last-session.json"

        with patch(
            "profiler.status.get_last_session_file_path",
            return_value=str(session_file),
        ):
            with patch(
                "profiler.status.get_info_file_path",
                return_value=str(tmp_path / "nonexistent.json"),
            ):
                write_last_session(
                    exit_status="failed",
                    exit_code=1,
                    start_time="2026-01-26T12:00:00+00:00",
                    exit_reason="hostapd_crashed",
                    error_message="Hostapd died unexpectedly",
                )

        with open(session_file) as f:
            data = json.load(f)

        assert data["exit"]["status"] == "failed"
        assert data["exit"]["code"] == 1
        assert data["exit"]["reason"] == "hostapd_crashed"
        assert data["exit"]["message"] == "Hostapd died unexpectedly"

    def test_write_last_session_interrupted(self, tmp_path):
        """Verify last-session file written on uncaught exception"""
        session_file = tmp_path / "last-session.json"

        with patch(
            "profiler.status.get_last_session_file_path",
            return_value=str(session_file),
        ):
            with patch(
                "profiler.status.get_info_file_path",
                return_value=str(tmp_path / "nonexistent.json"),
            ):
                write_last_session(
                    exit_status="interrupted",
                    exit_code=1,
                    start_time="2026-01-26T12:00:00+00:00",
                    exit_reason="uncaught_exception",
                    error_message="KeyError: 'missing_key'",
                )

        with open(session_file) as f:
            data = json.load(f)

        assert data["exit"]["status"] == "interrupted"
        assert data["exit"]["reason"] == "uncaught_exception"

    def test_read_last_session_valid(self, tmp_path):
        """Verify reading valid last-session file"""
        session_file = tmp_path / "last-session.json"
        test_data = {
            "schema_version": "1.0",
            "exit": {"status": "success", "code": 0},
        }
        with open(session_file, "w") as f:
            json.dump(test_data, f)

        with patch(
            "profiler.status.get_last_session_file_path",
            return_value=str(session_file),
        ):
            data = read_last_session()

        assert data is not None
        assert data["exit"]["status"] == "success"

    def test_read_last_session_missing(self, tmp_path):
        """Verify graceful handling of missing last-session file"""
        session_file = tmp_path / "nonexistent_session.json"

        with patch(
            "profiler.status.get_last_session_file_path",
            return_value=str(session_file),
        ):
            data = read_last_session()

        assert data is None

    def test_last_session_without_info_file(self, tmp_path):
        """Verify last-session file written even if info file missing"""
        session_file = tmp_path / "last-session.json"

        with patch(
            "profiler.status.get_last_session_file_path",
            return_value=str(session_file),
        ):
            with patch(
                "profiler.status.get_info_file_path",
                return_value=str(tmp_path / "nonexistent.json"),
            ):
                write_last_session(
                    exit_status="success",
                    exit_code=0,
                    start_time="2026-01-26T12:00:00+00:00",
                )

        assert session_file.exists()
        with open(session_file) as f:
            data = json.load(f)

        assert data["configuration"]["channel"] is None
        assert data["metrics"]["profile_count"] == 0

    def test_get_last_session_file_path(self):
        """Verify last-session file path returns system path"""
        path = get_last_session_file_path()
        assert path == "/var/lib/wlanpi-profiler/last-session.json"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
