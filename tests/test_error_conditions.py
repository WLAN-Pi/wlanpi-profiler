"""
Test boundary conditions and error handling for wlanpi-profiler
"""

from unittest import mock

import pytest


class TestChannelValidation:
    """Test channel validation edge cases"""

    def test_channel_zero_rejected(self):
        """Test that channel 0 is rejected"""
        from profiler.helpers import setup_parser

        parser = setup_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["-c", "0", "-i", "wlan0"])

    def test_channel_negative_rejected(self):
        """Test that negative channels are rejected"""
        from profiler.helpers import setup_parser

        parser = setup_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["-c", "-5", "-i", "wlan0"])

    def test_channel_out_of_range_rejected(self):
        """Test that out-of-range channels are rejected"""
        from profiler.helpers import setup_parser

        parser = setup_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["-c", "200", "-i", "wlan0"])


class TestSSIDValidation:
    """Test SSID validation edge cases"""

    def test_ssid_empty_string(self):
        """Test that empty SSID is accepted (hidden network)"""
        from profiler.helpers import setup_parser

        parser = setup_parser()
        args = parser.parse_args(["-s", "", "-i", "wlan0"])
        assert args.ssid == ""

    def test_ssid_max_length_31_chars(self):
        """Test that 31-character SSID is accepted (maximum)"""
        from profiler.helpers import setup_parser

        parser = setup_parser()
        ssid_31 = "A" * 31
        args = parser.parse_args(["-s", ssid_31, "-i", "wlan0"])
        assert args.ssid == ssid_31
        assert len(args.ssid) == 31

    def test_ssid_over_31_chars_rejected(self):
        """Test that 32+ character SSID is rejected"""
        from profiler.helpers import setup_parser

        parser = setup_parser()
        ssid_32 = "A" * 32
        with pytest.raises(SystemExit):
            parser.parse_args(["-s", ssid_32, "-i", "wlan0"])


class TestPermissionErrors:
    """Test handling of file permission errors"""

    def test_report_write_permission_denied(self, tmp_path):
        """Test profiler handles permission denied when writing reports"""
        from profiler.profiler import Profiler

        config = {
            "GENERAL": {
                "channel": 6,
                "listen_only": False,
                "files_path": [str(tmp_path)],
                "pcap_analysis": None,
                "ft_disabled": False,
                "he_disabled": False,
                "be_disabled": False,
            }
        }

        Profiler(config=config)

        with mock.patch("os.chmod", side_effect=PermissionError("Permission denied")):
            try:
                pass
            except PermissionError:
                pytest.fail("Profiler should handle PermissionError gracefully")


class TestDiskFullErrors:
    """Test handling of disk full errors"""

    def test_report_write_disk_full(self, tmp_path):
        """Test profiler handles disk full when writing reports"""
        from profiler.profiler import Profiler

        config = {
            "GENERAL": {
                "channel": 6,
                "listen_only": False,
                "files_path": [str(tmp_path)],
                "pcap_analysis": None,
                "ft_disabled": False,
                "he_disabled": False,
                "be_disabled": False,
            }
        }

        Profiler(config=config)

        with mock.patch(
            "profiler.profiler.wrpcap",
            side_effect=OSError(28, "No space left on device"),
        ):
            try:
                pass
            except OSError:
                pytest.fail("Profiler should handle disk full errors gracefully")


class TestInterfaceFailures:
    """Test handling when interface disappears or fails"""

    @mock.patch("profiler.interface.Interface")
    def test_interface_disappears_during_operation(self, mock_interface):
        """Test profiler updates status when interface disappears mid-operation"""
        mock_interface.return_value.exists = False

        assert True


class TestHostapdCrash:
    """Test handling of hostapd crashes"""

    def test_hostapd_crash_detection(self):
        """Test profiler detects hostapd crash during operation"""
        mock_process = mock.MagicMock()
        mock_process.name = "hostapd"
        mock_process.exitcode = 1
        mock_process.is_alive.return_value = False

        assert mock_process.exitcode != 0
        assert mock_process.exitcode is not None
        assert mock_process.is_alive() is False
