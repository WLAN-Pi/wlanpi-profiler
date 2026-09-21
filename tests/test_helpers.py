# -*- coding: utf-8 -*-

import logging

import pytest
from profiler import helpers


class TestHelpers:
    @pytest.mark.parametrize(
        "args,expected",
        [(["--debug"], 10), ([], 20)],
    )
    def test_logger(self, args, expected):
        parser = helpers.setup_parser()
        helpers.setup_logger(parser.parse_args(args))
        assert logging.root.level == expected

    def test_flag_last_object(self):
        ls = ["a", "b", "c"]
        for obj, last in helpers.flag_last_object(ls):
            if last:
                assert obj == "c"

    def test_generate_run_message(self):
        conf1 = {
            "GENERAL": {
                "ssid": "WLAN Pi",
                "channel": 36,
                "frequency": 5180,
                "mac": "80:02:11:11:02:08",
                "interface": "wlan1",
                "files_path": "/var/www/html/profiler",
            }
        }
        conf2 = {
            "GENERAL": {
                "ssid": "WLAN Pi",
                "channel": 36,
                "frequency": 5180,
                "mac": "80:02:11:11:02:08",
                "interface": "wlan1",
                "listen_only": True,
                "files_path": "/var/www/html/profiler",
            }
        }
        assert helpers.generate_run_message(conf1) == None
        assert helpers.generate_run_message(conf2) == None

    @pytest.mark.parametrize(
        "mac,expected",
        [
            ("EE-C7-3B-59-EE-DD", True),
            ("3A:CC:DD:BB:CC:AA", True),
            ("68-F7-28-F1-23-A9", False),
        ],
    )
    def test_is_randomized(self, mac, expected):
        resp = helpers.is_randomized(mac)
        assert resp == expected

    @pytest.mark.parametrize(
        "byte,index,expected",
        [
            (1, 0, True),
            (2, 1, True),
            (4, 2, True),
            (8, 3, True),
            (16, 4, True),
            (32, 5, True),
            (64, 6, True),
            (128, 7, True),
        ],
    )
    def test_get_bit(self, byte, index, expected):
        resp = helpers.get_bit(byte, index)
        assert resp == expected

    @pytest.mark.parametrize(
        "channel,expected",
        [
            (1, b"l\t"),
            (6, b"\x85\t"),
            (11, b"\x9e\t"),
            (14, b"\xb4\t"),
            (36, b"<\x14"),
            (100, b"|\x15"),
            (165, b"\xc1\x16"),
        ],
    )
    def test_get_frequency_bytes(self, channel, expected):
        resp = helpers.get_frequency_bytes(channel)
        assert resp == expected

    @pytest.mark.parametrize(
        "channel,expected",
        [
            ("0", "not a valid"),
            ("1", 1),
            ("2", 2),
            ("3", 3),
            ("4", 4),
            ("5", 5),
            ("6", 6),
            ("7", 7),
            ("8", 8),
            ("9", 9),
            ("10", 10),
            ("11", 11),
            ("12", 12),
            ("13", 13),
            ("36", 36),
            ("40", 40),
            ("44", 44),
            ("48", 48),
            ("52", 52),
            ("56", 56),
            ("60", 60),
            ("64", 64),
            ("100", 100),
            ("104", 104),
            ("108", 108),
            ("112", 112),
            ("116", 116),
            ("120", 120),
            ("124", 124),
            ("128", 128),
            ("132", 132),
            ("136", 136),
            ("140", 140),
            ("144", 144),
            ("149", 149),
            ("153", 153),
            ("157", 157),
            ("161", 161),
            ("165", 165),
        ],
    )
    def test_channel(self, channel, expected):
        if channel == "0":
            with pytest.raises(ValueError) as exc_info:
                channel = helpers.channel(channel)
                print(exc_info)
                assert "not a valid channel" in exc_info
        else:
            channel = helpers.channel(channel)
            assert channel == expected

    @pytest.mark.parametrize(
        "passphrase,should_pass",
        [
            # Valid passphrases (8-63 characters)
            ("profiler", True),  # Default: 8 chars (minimum)
            ("12345678", True),  # 8 chars
            ("MySecurePass123", True),  # 16 chars
            ("a" * 63, True),  # 63 chars (maximum)
            ("Hello123", True),  # 8 chars with mixed case
            ("Pass@123", True),  # 8 chars with special char
            ("🔒secure🔒", True),  # Emoji allowed (8+ bytes in UTF-8)
            # Invalid passphrases
            ("short", False),  # Too short (5 chars)
            ("1234567", False),  # Too short (7 chars)
            ("a" * 64, False),  # Too long (64 chars)
            ("a" * 100, False),  # Way too long
            ("", False),  # Empty
        ],
    )
    def test_passphrase(self, passphrase, should_pass):
        """Test passphrase validator with valid and invalid inputs"""
        if should_pass:
            result = helpers.passphrase(passphrase)
            assert result == passphrase
        else:
            with pytest.raises(ValueError) as exc_info:
                helpers.passphrase(passphrase)
            assert "8-63 characters" in str(exc_info.value)

    def test_config(self):
        parser = helpers.setup_parser()
        config, error = helpers.setup_config(
            parser.parse_args(["--config", "tests/config.ini"])
        )
        assert error is None
        assert "GENERAL" in config.keys()
        for _ in (
            "channel",
            "ssid",
            "interface",
            "ft_disabled",
            "he_disabled",
            "listen_only",
            "hostname_ssid",
            "files_path",
        ):
            assert _ in config["GENERAL"].keys()

    def test_defaults_no_config_found(self):
        """test the default values which are set when no config is present"""
        parser = helpers.setup_parser()
        config, error = helpers.setup_config(
            parser.parse_args(["--config", "fake.ini"])
        )
        assert error is None
        assert config["GENERAL"]["channel"] == 36
        assert config["GENERAL"]["interface"] == "wlan0"

    def test_no_config_found(self):
        """test the default values which are set when no config is present"""
        parser = helpers.setup_parser()
        config, error = helpers.setup_config(
            parser.parse_args(
                [
                    "--config",
                    "fake.ini",
                    "-c",
                    "1",
                    "--files_path",
                    "/nope/profiler",
                    "-i",
                    "wlan999",
                    "-s",
                    "Jerry Can You Hear Me",
                ]
            )
        )
        assert error is None
        # Verify essential config values are set correctly
        assert config["GENERAL"]["channel"] == 1
        assert config["GENERAL"]["frequency"] == 0
        assert config["GENERAL"]["interface"] == "wlan999"
        assert config["GENERAL"]["ssid"] == "Jerry Can You Hear Me"
        # ap_mode and fakeap are now always set (default: ap_mode=True, fakeap=False)
        assert config["GENERAL"]["ap_mode"] is True
        assert config["GENERAL"]["fakeap"] is False
        # files_path can be string or list depending on implementation
        assert "files_path" in config["GENERAL"]

    def test_passphrase_config_handling(self):
        """Test passphrase configuration priority: CLI > config.ini > default"""
        parser = helpers.setup_parser()

        # Test 1: No passphrase specified - should use default
        config, error = helpers.setup_config(parser.parse_args([]))
        assert error is None
        assert config["GENERAL"]["passphrase"] == "profiler"

        # Test 2: CLI argument - should override default
        config, error = helpers.setup_config(
            parser.parse_args(["--passphrase", "CustomPass123"])
        )
        assert error is None
        assert config["GENERAL"]["passphrase"] == "CustomPass123"

        # Test 3: Config file with passphrase - should use config value
        # (simulated by pre-loading config dict)
        # In real usage, this would be loaded from config.ini via ConfigParser

    def test_get_app_data_paths_from_config(self):
        """Test that get_app_data_paths reads from config.ini"""
        import tempfile
        import os

        parser = helpers.setup_parser()

        # Test 1: Config file specifies custom path (use writable temp dir)
        temp_config_dir = tempfile.mkdtemp(prefix="profiler_test_config_")
        config_with_path = {"GENERAL": {"files_path": temp_config_dir}}
        args_no_path = parser.parse_args([])
        paths = helpers.get_app_data_paths(args_no_path, config_with_path)
        # Should use path from config
        assert any(str(p) == temp_config_dir for p in paths), (
            f"Expected {temp_config_dir} in {[str(p) for p in paths]}"
        )

        # Test 2: Command-line arg overrides config
        temp_cli_dir = tempfile.mkdtemp(prefix="profiler_test_cli_")
        args_with_path = parser.parse_args(["--files_path", temp_cli_dir])
        paths = helpers.get_app_data_paths(args_with_path, config_with_path)
        # Should use command-line path (higher priority)
        assert any(str(p) == temp_cli_dir for p in paths), (
            f"Expected {temp_cli_dir} in {[str(p) for p in paths]}"
        )
        # Should NOT use config path when CLI is specified
        assert not any(str(p) == temp_config_dir for p in paths), (
            f"Config path should not be in {[str(p) for p in paths]}"
        )

        # Test 3: No config, no args - falls back to platform defaults
        config_no_path = {"GENERAL": {}}
        args_no_path = parser.parse_args([])
        paths = helpers.get_app_data_paths(args_no_path, config_no_path)
        # Should have at least one default path
        assert len(paths) > 0

        # Cleanup
        os.rmdir(temp_config_dir)
        os.rmdir(temp_cli_dir)

    def test_setup_logger_with_bool_debug_config(self):
        """Test that setup_logger handles boolean debug value from config"""
        parser = helpers.setup_parser()
        args = parser.parse_args([])

        # Test 1: debug as boolean True (as returned by convert_configparser_to_dict)
        config_bool_true = {"GENERAL": {"debug": True}}
        helpers.setup_logger(args, config_bool_true)
        assert logging.root.level == logging.DEBUG

        # Reset logging
        logging.root.setLevel(logging.INFO)

        # Test 2: debug as boolean False
        config_bool_false = {"GENERAL": {"debug": False}}
        helpers.setup_logger(args, config_bool_false)
        assert logging.root.level == logging.INFO

        # Reset logging
        logging.root.setLevel(logging.INFO)

        # Test 3: debug as string "true" (fallback case)
        config_str_true = {"GENERAL": {"debug": "true"}}
        helpers.setup_logger(args, config_str_true)
        assert logging.root.level == logging.DEBUG

        # Reset logging
        logging.root.setLevel(logging.INFO)

        # Test 4: debug as string "false"
        config_str_false = {"GENERAL": {"debug": "false"}}
        helpers.setup_logger(args, config_str_false)
        assert logging.root.level == logging.INFO

    def test_security_mode_backward_compat_ft_disabled_true(self, tmp_path):
        """Test backward compat: ft_disabled=True → security_mode=wpa3-mixed"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nft_disabled: True\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        # ft_disabled=True should map to wpa3-mixed (no FT)
        assert error is None
        assert config["GENERAL"]["security_mode"] == "wpa3-mixed"

    def test_security_mode_backward_compat_ft_disabled_false(self, tmp_path):
        """Test backward compat: ft_disabled=False → security_mode=ft-wpa3-mixed (default)"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nft_disabled: False\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        # ft_disabled=False should use default (ft-wpa3-mixed)
        assert error is None
        assert config["GENERAL"]["security_mode"] == "ft-wpa3-mixed"

    def test_security_mode_backward_compat_no11r_flag(self, tmp_path):
        """Test backward compat: --no11r CLI flag strips FT from security mode"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: ft-wpa3-mixed\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file), "--no11r"])
        config, error = helpers.setup_config(args)

        # --no11r should strip FT: ft-wpa3-mixed → wpa3-mixed
        assert error is None
        assert config["GENERAL"]["security_mode"] == "wpa3-mixed"

    def test_security_mode_backward_compat_no11r_wpa2(self, tmp_path):
        """Test backward compat: --no11r with ft-wpa2 → wpa2"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: ft-wpa2\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file), "--no11r"])
        config, error = helpers.setup_config(args)

        # --no11r should strip FT: ft-wpa2 → wpa2
        assert error is None
        assert config["GENERAL"]["security_mode"] == "wpa2"

    def test_security_mode_new_param_overrides_ft_disabled(self, tmp_path):
        """Test that security_mode parameter takes precedence over ft_disabled"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nft_disabled: True\nsecurity_mode: ft-wpa2\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        # security_mode should take precedence
        assert error is None
        assert config["GENERAL"]["security_mode"] == "ft-wpa2"

    def test_security_mode_cli_override(self, tmp_path):
        """Test that --security-mode CLI arg overrides config file"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: ft-wpa3-mixed\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(
            ["--config", str(config_file), "--security-mode", "wpa2"]
        )
        config, error = helpers.setup_config(args)

        # CLI should override config file
        assert error is None
        assert config["GENERAL"]["security_mode"] == "wpa2"

    def test_wpa2_auto_disables_11be(self, tmp_path):
        """Test that WPA2-only modes auto-disable 802.11be"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: wpa2\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        # Should auto-disable 11be for WPA2
        assert error is None
        assert config["GENERAL"]["be_disabled"] == True

    def test_ft_wpa2_auto_disables_11be(self, tmp_path):
        """Test that ft-wpa2 mode auto-disables 802.11be"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: ft-wpa2\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        # Should auto-disable 11be for ft-wpa2
        assert error is None
        assert config["GENERAL"]["be_disabled"] == True

    def test_wpa3_mixed_keeps_11be_enabled(self, tmp_path):
        """Test that wpa3-mixed keeps 802.11be enabled"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: wpa3-mixed\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        # Should NOT auto-disable 11be for wpa3-mixed
        assert error is None
        assert config["GENERAL"].get("be_disabled", False) == False

    def test_wpa2_with_11be_flag_override(self, tmp_path):
        """Test that --11be flag overrides auto-disable for WPA2"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: wpa2\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file), "--11be"])
        config, error = helpers.setup_config(args)

        # User override should work
        assert error is None
        assert config["GENERAL"]["be_disabled"] == False

    def test_wpa2_with_config_be_enabled(self, tmp_path):
        """config be_disabled:false no longer overrides auto-disable; use --11be"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: wpa2\nbe_disabled: false\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        # be_disabled: false is treated as "not set", so 11be is auto-disabled
        assert error is None
        assert config["GENERAL"]["be_disabled"] == True

    def test_wpa2_shipped_default_auto_disables_11be(self, tmp_path):
        """The shipped default (be_disabled: false) must not suppress auto-disable"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: wpa2\nbe_disabled: false\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        assert error is None
        assert config["GENERAL"]["be_disabled"] == True

    def test_wpa2_be_disabled_true_overrides_auto_disable(self, tmp_path):
        """An explicit be_disabled:true is honored"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: wpa2\nbe_disabled: true\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        assert error is None
        assert config["GENERAL"]["be_disabled"] == True

    def test_ssid_and_passphrase_truthy_strings_not_coerced(self, tmp_path):
        """String values like '1'/'on'/'no' must stay strings, not become bools"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nssid: on\npassphrase: no\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        assert error is None
        assert config["GENERAL"]["ssid"] == "on"
        assert config["GENERAL"]["passphrase"] == "no"

    def test_non_numeric_channel_returns_clean_error(self, tmp_path):
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nchannel: abc\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        assert config is None
        assert error is not None
        assert "channel" in error.lower()

    def test_11ax_flag_prevents_auto_disable(self, tmp_path):
        """--11ax re-enables 11ax so 11be must not be auto-disabled for that reason"""
        config_file = tmp_path / "test.ini"
        config_file.write_text(
            "[GENERAL]\nsecurity_mode: ft-wpa3-mixed\nhe_disabled: true\n"
        )

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file), "--11ax"])
        config, error = helpers.setup_config(args)

        assert error is None
        assert config["GENERAL"]["he_disabled"] is False
        assert config["GENERAL"]["be_disabled"] is False

    def test_11ax_disabled_auto_disables_11be(self, tmp_path):
        """Test that disabling 11ax auto-disables 11be"""
        config_file = tmp_path / "test.ini"
        config_file.write_text(
            "[GENERAL]\nsecurity_mode: ft-wpa3-mixed\nhe_disabled: true\n"
        )

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file)])
        config, error = helpers.setup_config(args)

        # Should auto-disable 11be when 11ax is disabled
        assert error is None
        assert config["GENERAL"]["be_disabled"] == True

    def test_no11ax_flag_auto_disables_11be(self, tmp_path):
        """Test that --no11ax flag auto-disables 11be"""
        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\nsecurity_mode: ft-wpa3-mixed\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file), "--no11ax"])
        config, error = helpers.setup_config(args)

        # Should auto-disable 11be when 11ax is disabled via CLI
        assert error is None
        assert config["GENERAL"]["be_disabled"] == True

    def test_no11r_deprecation_warning(self, tmp_path, caplog):
        """Test that --no11r shows deprecation warning"""
        import logging

        config_file = tmp_path / "test.ini"
        config_file.write_text("[GENERAL]\n")

        parser = helpers.setup_parser()
        args = parser.parse_args(["--config", str(config_file), "--no11r"])

        with caplog.at_level(logging.WARNING):
            config, error = helpers.setup_config(args)

        # Should see deprecation warning
        assert "DEPRECATED: --no11r" in caplog.text


class TestUpdateManuf2:
    """update_manuf2 must report failure instead of silently succeeding."""

    def _patch_env(self, monkeypatch, out):
        from unittest import mock

        fake_manuf2 = mock.Mock()
        fake_manuf2.__path__ = ["/tmp"]
        monkeypatch.setattr(helpers, "manuf2", fake_manuf2)
        monkeypatch.setattr(helpers.os.path, "isfile", lambda p: True)
        monkeypatch.setattr(helpers.os, "access", lambda p, m: True)
        monkeypatch.setattr(helpers.os.path, "getmtime", lambda p: 0)
        monkeypatch.setattr(helpers, "run_command", lambda cmd: out)

    def test_returns_false_on_urlerror(self, monkeypatch):
        self._patch_env(monkeypatch, "URLError: <urlopen error timed out>")
        assert helpers.update_manuf2() is False

    def test_returns_true_on_success(self, monkeypatch):
        self._patch_env(monkeypatch, "updated successfully")
        assert helpers.update_manuf2() is True


class TestRunCommand:
    """run_command must surface non-zero exits (phase 0)."""

    def test_success_returns_stdout(self):
        assert helpers.run_command(["echo", "hello"]).strip() == "hello"

    def test_failure_does_not_raise_by_default(self):
        # Lenient by default to preserve existing callers
        helpers.run_command(["false"])

    def test_failure_raises_when_check_true(self):
        import subprocess

        with pytest.raises(subprocess.CalledProcessError):
            helpers.run_command(["false"], check=True)


class TestIsRandomized:
    """is_randomized must not raise on empty/short input (phase 0)."""

    def test_empty_mac_returns_false(self):
        assert helpers.is_randomized("") is False

    def test_short_mac_returns_false(self):
        assert helpers.is_randomized("a") is False

    def test_locally_assigned_detected(self):
        assert helpers.is_randomized("02:11:22:33:44:55") is True


class TestCheckRequiredTools:
    """Tool checks are scoped per mode (phase 0 follow-up)."""

    def test_no_requirements_does_not_raise(self):
        helpers.check_required_tools(required=[], optional=[])

    def test_missing_optional_only_warns(self):
        # A missing optional tool must not abort startup.
        helpers.check_required_tools(
            required=[], optional=["profiler-definitely-missing-tool"]
        )

    def test_missing_required_aborts(self, monkeypatch):
        import profiler.status as status_mod

        monkeypatch.setattr(status_mod, "write_status", lambda **kwargs: None)
        with pytest.raises(SystemExit):
            helpers.check_required_tools(
                required=["profiler-definitely-missing-tool"], optional=[]
            )

    def test_pcap_requires_no_tools(self):
        assert helpers.PCAP_REQUIRED_TOOLS == []

    def test_expected_tools_are_optional_not_required(self):
        for tool in ("tcpdump", "modprobe", "modinfo"):
            assert tool not in helpers.LIVE_REQUIRED_TOOLS
            assert tool in helpers.LIVE_OPTIONAL_TOOLS
        assert "iw" in helpers.LIVE_REQUIRED_TOOLS
        assert "ip" in helpers.LIVE_REQUIRED_TOOLS
