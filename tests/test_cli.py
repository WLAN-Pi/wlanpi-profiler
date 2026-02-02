# -*- coding: utf-8 -*-


import pytest
from profiler import helpers
from profiler.__version__ import __version__
from profiler.interface import Interface, InterfaceError


@pytest.fixture
def parser():
    return helpers.setup_parser()


class TestArgParsing:
    def test_version(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["-V"])
        out, err = capsys.readouterr()
        assert out == f"{__version__}\n"
        assert err == ""

    def test_help(self, parser, capsys):
        """Test that -h/--help works without crashing"""
        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])
        out, err = capsys.readouterr()
        assert err == ""
        # Verify help text is actually generated
        assert "usage:" in out
        assert "wlanpi-profiler" in out or "profiler" in out
        assert "--security-mode" in out
        assert "--11be" in out  # Should be visible now
        assert "--no11r" not in out  # Should be hidden

    def test_help_short_flag(self, parser, capsys):
        """Test that -h works (short form)"""
        with pytest.raises(SystemExit):
            parser.parse_args(["-h"])
        out, err = capsys.readouterr()
        assert err == ""
        assert "usage:" in out

    def test_read_pcap_fail(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["--pcap"])
        out, err = capsys.readouterr()
        assert "expected one argument" in err

    def test_unknown_args(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["--notrealarg"])
        err = capsys.readouterr().err
        assert "error: unrecognized arguments:" in err

    def test_valid_ssid(self, parser, capsys):
        parser.parse_args(["-s", "WLAN Pi"])
        err = capsys.readouterr().err
        assert err == ""

    def test_invalid_ssid(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["-s", "this_is_a_really_long_string_really_too_long!!!"])
        err = capsys.readouterr().err
        assert "invalid ssid value" in err

    @pytest.mark.parametrize(
        "channel,expected",
        [(["-c", "1"], ""), (["-c", "6"], ""), (["-c", "11"], ""), (["-c", "36"], "")],
    )
    def test_valid_channel(self, channel, expected, parser, capsys):
        parser.parse_args(channel)
        _out, err = capsys.readouterr()
        assert err == expected

    def test_invalid_channel(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["-c", "22"])
        err = capsys.readouterr().err
        assert "invalid channel value" in err

    def test_invalid_interface(self, parser, capsys):
        with pytest.raises(InterfaceError):
            config = helpers.setup_config(
                parser.parse_args(["-i", "fakest_interface_ever"])
            )
            iface = Interface()
            iface.name = "fakest_iface_ever"
            iface.setup()

    @pytest.mark.parametrize(
        "args,expected",
        [
            (["--pcap", "fake_file_does_not_exist.pcap"], ""),
            (["--noAP"], ""),
            (["--11r"], ""),
            (["--no11r"], ""),
            (["--11ax"], ""),
            (["--no11ax"], ""),
            (["--noprep"], ""),
            (["--files_path", "/fake/path/does/not/exist"], ""),
            (["--clean"], ""),
            (["--yes"], ""),
            (["--oui_update"], ""),
            (["--hostname_ssid"], ""),
        ],
    )
    def test_valid_args(self, args, expected, parser, capsys):
        parser.parse_args(args)
        out, err = capsys.readouterr()
        assert err == expected

    def test_no_interface_prep_new_flag(self, parser):
        """Test that --no-interface-prep flag works"""
        args = parser.parse_args(["--no-interface-prep"])
        assert args.no_interface_prep is True

    def test_no_interface_prep_old_flag(self, parser):
        """Test that --noprep flag still works (backward compatibility)"""
        args = parser.parse_args(["--noprep"])
        assert args.no_interface_prep is True

    def test_no_interface_prep_in_help(self, parser, capsys):
        """Test that --no-interface-prep shows in help (but not --noprep)"""
        with pytest.raises(SystemExit):
            parser.parse_args(["-h"])
        out, err = capsys.readouterr()
        assert "--no-interface-prep" in out
        # Old flag should still work but be hidden in main help display
        # (argparse shows all aliases, so --noprep will appear)
