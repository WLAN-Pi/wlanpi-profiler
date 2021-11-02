# -*- coding: utf-8 -*-


import pytest
import subprocess

from profiler import helpers
from profiler.__version__ import __version__
from profiler.interface import Interface, InterfaceError


@pytest.fixture
def parser():
    return helpers.setup_parser()


class TestArgParsing:
    def test_version(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["", "-V"])
        out, err = capsys.readouterr()
        assert out == f"{__version__}\n"
        assert err == ""

    def test_help(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["", "--help"])
        out, err = capsys.readouterr()
        assert err == ""

    def test_read_pcap_fail(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["", "--read"])
        out, err = capsys.readouterr()
        assert "expected one argument" in err

    def test_unknown_args(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args("notrealarg")
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
        assert "invalid check_ssid value" in err

    @pytest.mark.parametrize(
        "frequency,expected",
        [(["-f", "5180"], ""), (["-c", "2412"], ""), (["-c", "2462"], ""), (["-c", "6135"], "")],
    )
    def test_valid_frequency(self, frequency, expected, parser, capsys):
        parser.parse_args(frequency)
        out, err = capsys.readouterr()
        assert err == expected

    def test_invalid_frequency(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["", "-f", "5170"])
        err = capsys.readouterr().err
        assert "invalid check_frequency value" in err

    def test_invalid_interface(self, parser, capsys):
       with pytest.raises(InterfaceError):
            config = helpers.setup_config(
                parser.parse_args(["-i", "fakest_interface_ever"])
            )
            Interface("fakest_interface_ever")

    @pytest.mark.parametrize(
        "args,expected",
        [
            (["--read", "fake_file_does_not_exist.pcap"], ""),
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
