# -*- coding: utf-8 -*-

import argparse, itertools, pathlib, sys

import pytest

from profiler2 import helpers
from profiler2.__version__ import __version__


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

    def test_pcap_fail(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["", "--pcap"])
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
        "channel,expected",
        [(["-c", "1"], ""), (["-c", "6"], ""), (["-c", "11"], ""), (["-c", "36"], "")],
    )
    def test_valid_channel(self, channel, expected, parser, capsys):
        parser.parse_args(channel)
        out, err = capsys.readouterr()
        assert err == expected

    def test_invalid_channel(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["", "-c", "15"])
        err = capsys.readouterr().err
        assert "invalid check_channel value" in err

    def test_invalid_interface(self, parser, capsys):
        with pytest.raises(SystemExit):
            config = helpers.setup_config(parser.parse_args(["-i", "fakest_interface_ever"]))
            helpers.validate(config)
        out, err = capsys.readouterr()
        assert err == ""

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
