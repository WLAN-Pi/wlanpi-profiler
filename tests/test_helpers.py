# -*- coding: utf-8 -*-

import logging
import multiprocessing as mp

import pytest
from profiler import helpers


class TestHelpers:
    @pytest.mark.parametrize(
        "args,expected",
        [(["--logging", "debug"], 10), (["--logging", "warning"], 30), ([], 20)],
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
        """test the default values which are set when no config is present"""
        parser = helpers.setup_parser()
        config = helpers.setup_config(parser.parse_args(["--config", "fake.ini"]))
        assert config == dict(
            GENERAL=dict(
                channel=36,
                frequency=0,
                files_path="/var/www/html/profiler",
                interface="wlan0",
                ssid="WLAN Pi",
            )
        )

    def test_no_config_found(self):
        """test the default values which are set when no config is present"""
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
                frequency=0,
                files_path="/nope/profiler",
                interface="wlan999",
                ssid="Jerry Can You Hear Me",
            )
        )
