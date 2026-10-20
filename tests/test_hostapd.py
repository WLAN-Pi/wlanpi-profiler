import logging
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from profiler.config_generator import (
    ConfigGeneratorError,
    calculate_center_frequency,
    generate_hostapd_config,
)
from profiler.hostapd_manager import (
    HostapdManager,
    HostapdNotFoundError,
    HostapdStartupError,
)


class TestConfigGenerator:
    """Test hostapd config generation"""

    @pytest.mark.parametrize(
        "channel,bandwidth,expected",
        [
            (36, 80, 42),
            (40, 80, 42),
            (52, 80, 58),
            (149, 80, 155),
            (36, 160, 50),
            (52, 160, 50),
            (100, 160, 114),
            (149, 160, 163),
            (6, 20, 6),
            (36, 40, 38),
        ],
    )
    def test_calculate_center_frequency(self, channel, bandwidth, expected):
        """Test center frequency calculation"""
        result = calculate_center_frequency(channel, bandwidth)
        assert result == expected

    def test_generate_5ghz_basic(self):
        """Test basic 5 GHz config generation"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            channel=36,
            ssid="Test5G",
            band="5ghz",
            country_code="US",
        )

        assert os.path.exists(config_path)
        config = Path(config_path).read_text()

        assert "interface=wlan0" in config
        assert "ssid=Test5G" in config
        assert "channel=36" in config
        assert "hw_mode=a" in config

        assert "ieee80211n=1" in config
        assert "ieee80211ac=1" in config
        assert "ieee80211ax=1" in config
        assert "ieee80211be=1" in config

        assert "vht_oper_chwidth=0" in config
        assert "vht_oper_centr_freq_seg0_idx=0" in config

        os.remove(config_path)

    def test_generate_2ghz_basic(self):
        """Test basic 2.4 GHz config generation"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            channel=6,
            ssid="Test24G",
            band="2ghz",
            country_code="US",
        )

        assert os.path.exists(config_path)
        config = Path(config_path).read_text()

        assert "interface=wlan0" in config
        assert "ssid=Test24G" in config
        assert "channel=6" in config
        assert "hw_mode=g" in config

        assert "ieee80211n=1" in config
        assert "ieee80211ac=0" in config

        assert "ieee80211ax=1" in config
        assert "ieee80211be=1" in config

        os.remove(config_path)

    @pytest.mark.parametrize(
        "band,channel",
        [
            ("5ghz", 36),
            ("2ghz", 6),
        ],
    )
    def test_generate_no_beacon_rate(self, band, channel):
        """beacon_rate must not be emitted: drivers lacking BEACON_RATE_LEGACY
        refuse to start the AP when a legacy beacon rate is configured."""
        config_path = generate_hostapd_config(
            interface="wlan0",
            channel=channel,
            ssid="Test",
            band=band,
            country_code="US",
        )

        config = Path(config_path).read_text()
        assert "beacon_rate" not in config

        os.remove(config_path)

    def test_generate_5ghz_he_disabled(self):
        """Test 5 GHz config with Wi-Fi 6 disabled"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            channel=36,
            ssid="Test",
            band="5ghz",
            country_code="US",
            he_disabled=True,
        )

        config = Path(config_path).read_text()

        assert "ieee80211ax=0" in config
        assert "ieee80211be=0" in config

        assert "ieee80211ac=1" in config

        os.remove(config_path)

    def test_generate_5ghz_be_disabled(self):
        """Test 5 GHz config with Wi-Fi 7 disabled"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            channel=36,
            ssid="Test",
            band="5ghz",
            country_code="US",
            be_disabled=True,
        )

        config = Path(config_path).read_text()

        assert "ieee80211ax=1" in config
        assert "ieee80211be=0" in config

        os.remove(config_path)

    def test_generate_ft_disabled(self):
        """Test config with 802.11r disabled (wpa3-mixed mode)"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            channel=36,
            ssid="Test",
            band="5ghz",
            country_code="US",
            security_mode="wpa3-mixed",
        )

        config = Path(config_path).read_text()

        assert "mobility_domain" not in config
        assert "ft_over_ds" not in config
        assert "FT-PSK" not in config
        assert "FT-SAE" not in config
        assert "SAE" in config
        assert "WPA-PSK" in config

        os.remove(config_path)

    def test_generate_wpa3_enabled(self):
        """Test config with WPA3 enabled (ft-wpa3-mixed mode - default)"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            channel=36,
            ssid="Test",
            band="5ghz",
            country_code="US",
            security_mode="ft-wpa3-mixed",
        )

        config = Path(config_path).read_text()

        assert "SAE" in config
        assert "sae_password" in config
        assert "FT-SAE" in config
        assert "FT-PSK" in config

        os.remove(config_path)

    def test_generate_wpa3_disabled(self):
        """Test config with WPA3 disabled (ft-wpa2 mode)"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            channel=36,
            ssid="Test",
            band="5ghz",
            country_code="US",
            security_mode="ft-wpa2",
        )

        config = Path(config_path).read_text()

        assert "WPA-PSK" in config
        assert "SAE" not in config
        assert "FT-PSK" in config

        os.remove(config_path)

    def test_generate_invalid_band(self):
        """Test error on invalid band"""
        with pytest.raises(ConfigGeneratorError, match="Invalid band"):
            generate_hostapd_config(
                interface="wlan0",
                channel=36,
                ssid="Test",
                band="invalid",
                country_code="US",
            )

    def test_generate_6ghz_not_supported(self):
        """Test error on 6 GHz band"""
        with pytest.raises(
            ConfigGeneratorError, match="6 GHz band not currently supported"
        ):
            generate_hostapd_config(
                interface="wlan0",
                channel=5,
                ssid="Test",
                band="6ghz",
                country_code="US",
            )

    def test_generate_ssid_too_long(self):
        """Test error on SSID > 31 chars"""
        with pytest.raises(ConfigGeneratorError, match="SSID too long"):
            generate_hostapd_config(
                interface="wlan0",
                channel=36,
                ssid="A" * 32,
                band="5ghz",
                country_code="US",
            )

    def test_generate_invalid_2ghz_channel(self):
        """Test error on invalid 2.4 GHz channel"""
        with pytest.raises(ConfigGeneratorError, match=r"Invalid 2\.4 GHz channel"):
            generate_hostapd_config(
                interface="wlan0",
                channel=15,
                ssid="Test",
                band="2ghz",
                country_code="US",
            )

    def test_generate_invalid_5ghz_channel(self):
        """Test error on invalid 5 GHz channel"""
        with pytest.raises(ConfigGeneratorError, match="Invalid 5 GHz channel"):
            generate_hostapd_config(
                interface="wlan0",
                channel=37,
                ssid="Test",
                band="5ghz",
                country_code="US",
            )

    def test_generate_custom_output_path(self):
        """Test config generation with custom output path"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as f:
            custom_path = f.name

        try:
            config_path = generate_hostapd_config(
                interface="wlan0",
                channel=36,
                ssid="Test",
                band="5ghz",
                country_code="US",
                output_path=custom_path,
            )

            assert config_path == custom_path
            assert os.path.exists(custom_path)
        finally:
            if os.path.exists(custom_path):
                os.remove(custom_path)

    def test_config_file_permissions(self):
        """Test generated config has restrictive permissions"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            channel=36,
            ssid="Test",
            band="5ghz",
            country_code="US",
        )

        stat_info = os.stat(config_path)
        permissions = stat_info.st_mode & 0o777
        assert permissions == 0o600

        os.remove(config_path)


class TestHostapdManager:
    """Test hostapd process manager"""

    def test_init(self):
        """Test HostapdManager initialization"""
        config = {
            "interface": "wlan0",
            "channel": 36,
            "ssid": "Test",
        }
        log = logging.getLogger("test")

        mgr = HostapdManager(config, "US", log)

        assert mgr.config == config
        assert mgr.log == log
        assert mgr.process is None
        assert mgr.config_path is None
        assert mgr.interface == "wlan0"

    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_generate_config_5ghz(self, mock_gen):
        """Test config generation for 5 GHz"""
        mock_gen.return_value = "/tmp/test.conf"

        config = {
            "interface": "wlan0",
            "channel": 36,
            "frequency": 5180,
            "ssid": "Test",
        }
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        config_path = mgr.generate_config()

        assert config_path == "/tmp/test.conf"
        mock_gen.assert_called_once()
        args = mock_gen.call_args
        assert args[1]["interface"] == "wlan0"
        assert args[1]["channel"] == 36
        assert args[1]["band"] == "5ghz"

    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_generate_config_2ghz(self, mock_gen):
        """Test config generation for 2.4 GHz"""
        mock_gen.return_value = "/tmp/test.conf"

        config = {
            "interface": "wlan0",
            "channel": 6,
            "frequency": 2437,
            "ssid": "Test",
        }
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        config_path = mgr.generate_config()

        assert config_path == "/tmp/test.conf"
        args = mock_gen.call_args
        assert args[1]["band"] == "2ghz"

    @mock.patch("os.path.exists")
    def test_start_binary_not_found(self, mock_exists):
        """Test error when hostapd binary missing"""
        mock_exists.return_value = False

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        with pytest.raises(HostapdNotFoundError, match="Hostapd binary not found"):
            mgr.start()

    @mock.patch("subprocess.Popen")
    @mock.patch("os.path.exists")
    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_start_success(self, mock_gen, mock_exists, mock_popen):
        """Test successful hostapd startup"""
        mock_gen.return_value = "/tmp/test.conf"
        mock_exists.return_value = True

        mock_process = mock.Mock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        mgr._get_bssid = mock.Mock()

        proc = mgr.start()

        assert proc == mock_process
        assert mgr.process == mock_process
        assert mgr.is_running()

    @mock.patch("subprocess.Popen")
    @mock.patch("os.path.exists")
    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_start_process_dies_immediately(self, mock_gen, mock_exists, mock_popen):
        """Test error when hostapd dies immediately"""
        mock_gen.return_value = "/tmp/test.conf"
        mock_exists.return_value = True

        mock_process = mock.Mock()
        mock_process.poll.return_value = 1
        mock_process.returncode = 1
        mock_process.communicate.return_value = ("", "Channel not allowed")
        mock_popen.return_value = mock_process

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        with pytest.raises(HostapdStartupError, match="died immediately"):
            mgr.start()

    def test_stop_no_process(self):
        """Test stop when no process running"""
        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        mgr.stop()

    def test_stop_graceful(self):
        """Test graceful stop"""
        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        mock_process = mock.Mock()
        mock_process.poll.return_value = None
        mgr.process = mock_process

        mgr.stop()

        mock_process.terminate.assert_called_once()
        mock_process.wait.assert_called_once()

    def test_stop_with_kill(self):
        """Test stop with SIGKILL after timeout"""
        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        mock_process = mock.Mock()
        mock_process.poll.return_value = None
        mock_process.wait.side_effect = [
            __import__("subprocess").TimeoutExpired("cmd", 5),
            None,
        ]
        mgr.process = mock_process

        mgr.stop(timeout=1)

        mock_process.terminate.assert_called_once()
        mock_process.kill.assert_called_once()

    def test_is_running_no_process(self):
        """Test is_running when no process"""
        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        assert not mgr.is_running()

    def test_get_bssid_none(self):
        """Test get_bssid when not set"""
        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        assert mgr.get_bssid() is None

    def test_cleanup(self):
        """Test cleanup removes temp files"""
        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            mgr.config_path = f.name
            f.write("test")

        assert os.path.exists(mgr.config_path)

        mgr.cleanup()

        assert not os.path.exists(mgr.config_path)


class TestCountryCodeIntegration:
    """
    Regression tests for country code parameter integration.

    These tests ensure the country_code parameter is properly passed through
    the hostapd configuration system and prevent accidental removal.
    """

    def test_generate_hostapd_config_includes_country_code_us(self):
        """Test that generated config includes country_code line for US"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            ssid="TestSSID",
            channel=36,
            band="5ghz",
            country_code="US",
        )

        with open(config_path) as f:
            config_content = f.read()

        assert "country_code=US" in config_content
        os.remove(config_path)

    def test_generate_hostapd_config_includes_country_code_gb(self):
        """Test that generated config includes country_code line for GB"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            ssid="TestSSID",
            channel=36,
            band="5ghz",
            country_code="GB",
        )

        with open(config_path) as f:
            config_content = f.read()

        assert "country_code=GB" in config_content
        os.remove(config_path)

    def test_generate_hostapd_config_includes_country_code_de(self):
        """Test that generated config includes country_code line for DE"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            ssid="TestSSID",
            channel=100,
            band="5ghz",
            country_code="DE",
        )

        with open(config_path) as f:
            config_content = f.read()

        assert "country_code=DE" in config_content
        os.remove(config_path)

    def test_hostapd_manager_constructor_requires_country_code(self):
        """Test that HostapdManager constructor requires country_code parameter"""
        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")

        mgr = HostapdManager(config, "US", log)

        assert mgr is not None

    def test_hostapd_manager_different_country_codes(self):
        """Test HostapdManager with various country codes"""
        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")

        country_codes = ["US", "GB", "DE", "FR", "JP", "AU", "CA"]

        for cc in country_codes:
            mgr = HostapdManager(config, cc, log)
            assert mgr is not None

    def test_country_code_affects_dfs_channels(self):
        """Test that country code is present when using DFS channels"""
        dfs_channel = 100

        config_path = generate_hostapd_config(
            interface="wlan0",
            ssid="TestSSID",
            channel=dfs_channel,
            band="5ghz",
            country_code="US",
        )

        with open(config_path) as f:
            config_content = f.read()

        assert "country_code=US" in config_content
        assert f"channel={dfs_channel}" in config_content
        os.remove(config_path)

    def test_country_code_2ghz_channels(self):
        """Test country code with 2.4 GHz channels"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            ssid="TestSSID",
            channel=6,
            band="2ghz",
            country_code="US",
        )

        with open(config_path) as f:
            config_content = f.read()

        assert "country_code=US" in config_content
        assert "channel=6" in config_content
        assert "hw_mode=g" in config_content
        os.remove(config_path)

    def test_country_code_5ghz_unii1_channels(self):
        """Test country code with 5 GHz UNII-1 channels"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            ssid="TestSSID",
            channel=36,
            band="5ghz",
            country_code="US",
        )

        with open(config_path) as f:
            config_content = f.read()

        assert "country_code=US" in config_content
        assert "channel=36" in config_content
        assert "hw_mode=a" in config_content
        os.remove(config_path)

    def test_country_code_5ghz_unii3_channels(self):
        """Test country code with 5 GHz UNII-3 channels"""
        config_path = generate_hostapd_config(
            interface="wlan0",
            ssid="TestSSID",
            channel=149,
            band="5ghz",
            country_code="US",
        )

        with open(config_path) as f:
            config_content = f.read()

        assert "country_code=US" in config_content
        assert "channel=149" in config_content
        os.remove(config_path)


class TestHostapdWatchdog:
    """Test hostapd process watchdog and error detection"""

    @mock.patch("subprocess.Popen")
    @mock.patch("os.path.exists")
    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_watchdog_thread_starts(self, mock_gen, mock_exists, mock_popen):
        """Test that watchdog thread is started on successful startup"""
        mock_gen.return_value = "/tmp/test.conf"
        mock_exists.return_value = True

        mock_process = mock.Mock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        mgr._get_bssid = mock.Mock()

        mgr.start()

        assert mgr._watchdog_thread is not None
        assert mgr._watchdog_thread.is_alive()
        assert mgr._watchdog_running

        mgr.cleanup()

    @mock.patch("subprocess.Popen")
    @mock.patch("os.path.exists")
    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_watchdog_stops_on_cleanup(self, mock_gen, mock_exists, mock_popen):
        """Test that watchdog thread is stopped during cleanup"""
        mock_gen.return_value = "/tmp/test.conf"
        mock_exists.return_value = True

        mock_process = mock.Mock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)
        mgr._get_bssid = mock.Mock()

        mgr.start()
        assert mgr._watchdog_running

        mgr.cleanup()

        import time

        time.sleep(0.5)

        assert not mgr._watchdog_running
        assert not mgr._watchdog_thread.is_alive()

    @mock.patch("subprocess.Popen")
    @mock.patch("os.path.exists")
    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_log_monitoring_detects_init_failure(
        self, mock_gen, mock_exists, mock_popen
    ):
        """Test that log monitoring detects 'Interface initialization failed'"""
        from io import StringIO

        mock_gen.return_value = "/tmp/test.conf"
        mock_exists.return_value = True

        mock_process = mock.Mock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345

        mock_stdout = StringIO(
            "wlan0: interface state UNINITIALIZED->COUNTRY_UPDATE\n"
            "Could not set channel for kernel driver\n"
            "Interface initialization failed\n"
        )
        mock_process.stdout = mock_stdout
        mock_process.stderr = StringIO("")

        mock_popen.return_value = mock_process

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        import threading

        stderr_done = threading.Event()

        def stream_stderr():
            mgr._stream_logs(mock_process.stderr, "HOSTAPD-ERR")
            stderr_done.set()

        def stream_stdout():
            mgr._stream_logs(mock_process.stdout, "HOSTAPD")

        stderr_thread = threading.Thread(target=stream_stderr, daemon=True)
        stdout_thread = threading.Thread(target=stream_stdout, daemon=True)

        mgr._startup_time = __import__("time").time()

        stderr_thread.start()
        stdout_thread.start()

        import time

        time.sleep(0.1)

        assert mgr._init_failed
        assert "Interface initialization failed" in mgr._init_error_msg

    @mock.patch("subprocess.Popen")
    @mock.patch("os.path.exists")
    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_log_monitoring_detects_ap_disabled(
        self, mock_gen, mock_exists, mock_popen
    ):
        """Test that log monitoring detects AP-DISABLED event"""
        from io import StringIO

        mock_gen.return_value = "/tmp/test.conf"
        mock_exists.return_value = True

        mock_process = mock.Mock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345

        mock_stdout = StringIO(
            "wlan0: interface state COUNTRY_UPDATE->DISABLED\nwlan0: AP-DISABLED\n"
        )
        mock_process.stdout = mock_stdout
        mock_process.stderr = StringIO("")

        mock_popen.return_value = mock_process

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        import threading
        import time

        def stream_stdout():
            mgr._stream_logs(mock_process.stdout, "HOSTAPD")

        mgr._startup_time = time.time()
        stdout_thread = threading.Thread(target=stream_stdout, daemon=True)
        stdout_thread.start()

        time.sleep(0.1)

        assert mgr._init_failed
        assert "AP-DISABLED" in mgr._init_error_msg

    def test_log_monitoring_ignores_errors_after_startup_window(self):
        """Test that errors after 10 seconds don't set init_failed flag"""
        import time
        from io import StringIO

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        mgr._startup_time = time.time() - 11

        mock_stdout = StringIO("Interface initialization failed\n")

        import threading

        def stream_stdout():
            mgr._stream_logs(mock_stdout, "HOSTAPD")

        stdout_thread = threading.Thread(target=stream_stdout, daemon=True)
        stdout_thread.start()

        time.sleep(0.1)

        assert not mgr._init_failed

    @mock.patch("subprocess.Popen")
    @mock.patch("os.path.exists")
    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_watchdog_ignores_exit_code_0(self, mock_gen, mock_exists, mock_popen):
        """Test that watchdog treats exit code 0 as clean shutdown (no error)"""
        mock_gen.return_value = "/tmp/test.conf"
        mock_exists.return_value = True

        mock_process = mock.Mock()
        mock_process.poll.side_effect = [None, None, 0]
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)
        mgr._get_bssid = mock.Mock()

        mgr.start()

        assert mgr._watchdog_thread is not None
        assert mgr._watchdog_running

        assert not mgr._init_failed

        import time

        time.sleep(1.5)

        assert not mgr._watchdog_running

        mgr._watchdog_stop.set()
        if mgr._watchdog_thread.is_alive():
            mgr._watchdog_thread.join(timeout=1)

    @mock.patch("subprocess.Popen")
    @mock.patch("os.path.exists")
    @mock.patch("profiler.config_generator.generate_hostapd_config")
    @mock.patch("os.kill")
    def test_watchdog_triggers_on_non_zero_exit(
        self, mock_kill, mock_gen, mock_exists, mock_popen
    ):
        """Test that watchdog triggers shutdown on non-zero exit code"""
        mock_gen.return_value = "/tmp/test.conf"
        mock_exists.return_value = True

        mock_process = mock.Mock()
        mock_process.poll.side_effect = [None, None, 1]
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)
        mgr._get_bssid = mock.Mock()

        mgr.start()

        import signal
        import time

        time.sleep(1.5)

        mock_kill.assert_called()
        call_args = mock_kill.call_args
        assert call_args[0][1] == signal.SIGUSR1

        mgr._watchdog_stop.set()
        if mgr._watchdog_thread and mgr._watchdog_thread.is_alive():
            mgr._watchdog_thread.join(timeout=1)

    @mock.patch("os.kill")
    @mock.patch("subprocess.Popen")
    @mock.patch("os.path.exists")
    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_watchdog_detects_init_failed_with_exit_0(
        self, mock_gen, mock_exists, mock_popen, mock_kill
    ):
        """
        Test that watchdog detects startup failure when _init_failed is True,
        even if hostapd exits with code 0.

        This covers the race condition where:
        1. start() checks pass (process alive, _init_failed still False)
        2. Error logged after start() returns, setting _init_failed = True
        3. Hostapd exits with code 0 (handled error gracefully)
        4. Watchdog must detect _init_failed and trigger shutdown
        """
        import signal
        from io import StringIO

        mock_gen.return_value = "/tmp/test.conf"
        mock_exists.return_value = True

        mock_process = mock.Mock()
        mock_process.poll.side_effect = [
            None,
            None,
            0,
        ]
        mock_process.pid = 12345

        mock_stdout = StringIO("Interface initialization failed\n")
        mock_process.stdout = mock_stdout
        mock_process.stderr = StringIO("")

        mock_popen.return_value = mock_process

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)
        mgr._get_bssid = mock.Mock()

        mgr._init_failed = True
        mgr._init_error_msg = "Interface initialization failed"

        mgr.start()

        import time

        time.sleep(1.5)

        mock_kill.assert_called()
        call_args = mock_kill.call_args
        assert call_args[0][1] == signal.SIGUSR1

        mgr._watchdog_stop.set()
        if mgr._watchdog_thread and mgr._watchdog_thread.is_alive():
            mgr._watchdog_thread.join(timeout=1)

    @mock.patch("subprocess.Popen")
    @mock.patch("os.path.exists")
    @mock.patch("profiler.config_generator.generate_hostapd_config")
    def test_start_catches_immediate_process_death(
        self, mock_gen, mock_exists, mock_popen
    ):
        """
        Test that start() still catches immediate process death (0-2s).

        This ensures immediate crashes are caught before watchdog starts.
        """
        mock_gen.return_value = "/tmp/test.conf"
        mock_exists.return_value = True

        mock_process = mock.Mock()
        mock_process.poll.return_value = 1
        mock_process.returncode = 1
        mock_popen.return_value = mock_process

        config = {"interface": "wlan0", "channel": 36, "ssid": "Test"}
        log = logging.getLogger("test")
        mgr = HostapdManager(config, "US", log)

        with pytest.raises(HostapdStartupError, match="died immediately"):
            mgr.start()

        assert mgr._watchdog_thread is None
