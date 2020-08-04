# -*- coding: utf-8 -*-

import argparse, logging, sys

from unittest.mock import patch

import pytest

from profiler2 import helpers


class TestHelpers:
    @pytest.mark.parametrize(
        "args,expected",
        [(["--logging", "debug"], 10), (["--logging", "warning"], 30), ([], 20)],
    )
    def test_logger(self, args, expected):
        parser = helpers.setup_parser()
        helpers.setup_logger(parser.parse_args(args))
        assert logging.root.level == expected

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
                channel = helpers.check_channel(channel)
                print(exc_info)
                assert "not a valid channel" in exc_info
        else:
            channel = helpers.check_channel(channel)
            assert channel == expected

    def test_config(self):
        parser = helpers.setup_parser()
        config = helpers.setup_config(
            parser.parse_args(["--config", "tests/config.ini"])
        )
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
        """ test the default values which are set when no config is present """
        parser = helpers.setup_parser()
        config = helpers.setup_config(parser.parse_args(["--config", "fake.ini"]))
        assert config == dict(
            GENERAL=dict(
                channel=36,
                files_path="/var/www/html/profiler",
                interface="wlan0",
                ssid="WLAN Pi",
            )
        )

    def test_no_config_found(self):
        """ test the default values which are set when no config is present """
        parser = helpers.setup_parser()
        config = helpers.setup_config(
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
        assert config == dict(
            GENERAL=dict(
                channel=1,
                files_path="/nope/profiler",
                interface="wlan999",
                ssid="Jerry Can You Hear Me",
            )
        )
