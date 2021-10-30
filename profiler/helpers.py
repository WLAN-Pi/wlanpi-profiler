# -* coding: utf-8 -*-
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2020-2021 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.helpers
~~~~~~~~~~~~~~~~

provides init functions that are used to help setup the app.
"""

# standard library imports
import argparse
import configparser
import inspect
import json
import logging
import logging.config
import os
import shutil
import signal
import socket
import subprocess
import sys
from base64 import b64encode
from dataclasses import dataclass
from distutils.util import strtobool
from time import ctime
from typing import Any, Dict, List, Union

# third party imports
try:
    import manuf
except ModuleNotFoundError as error:
    if error.name == "manuf":
        print("required module manuf not found.")
    else:
        print(f"{error}")
    sys.exit(signal.SIGABRT)


def run_cli_cmd(cmd: List) -> str:
    """Run an arbitrary CLI command and return the results"""
    cp = subprocess.run(
        cmd,
        encoding="utf-8",
        shell=False,
        check=True,
        capture_output=True,
    )

    if cp.returncode == 0:
        if cp.stdout:
            return cp.stdout
        if cp.stderr:
            return cp.stderr
    return "completed process return code is non-zero"


# is tcpdump installed?
try:
    result = run_cli_cmd(["tcpdump", "--version"])
except OSError:
    print(
        "problem checking tcpdump version. is tcpdump installed and functioning? exiting..."
    )


# app imports
from .__version__ import __version__
from .constants import CHANNELS, CONFIG_FILE

FILES_PATH = "/var/www/html/profiler"


def setup_logger(args) -> None:
    """Configure and set logging levels"""
    if args.logging:
        if args.logging == "debug":
            logging_level = logging.DEBUG
        if args.logging == "warning":
            logging_level = logging.WARNING
    else:
        logging_level = logging.INFO

    default_logging = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {"format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"}
        },
        "handlers": {
            "default": {
                "level": logging_level,
                "formatter": "standard",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            }
        },
        "loggers": {"": {"handlers": ["default"], "level": logging_level}},
    }
    logging.config.dictConfig(default_logging)


def check_channel(value: str) -> int:
    """Check if channel is valid"""
    channel = int(value)
    error_msg = "%s is not a valid channel value" % channel
    if channel <= 0:
        raise ValueError(error_msg)
    if any(channel in band for band in CHANNELS.values()):
        return channel
    else:
        raise ValueError(error_msg)


def check_ssid(ssid: str) -> str:
    """Check if SSID is valid"""
    if len(ssid) > 32:
        raise ValueError("%s length is greater than 32" % ssid)
    return ssid


def setup_parser() -> argparse.ArgumentParser:
    """Set default values and handle arg parser"""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="wlanpi-profiler is an 802.11 client capabilities profiler. Read the manual with: man wlanpi-profiler",
    )
    parser.add_argument(
        "--pytest",
        dest="pytest",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-c",
        dest="channel",
        type=check_channel,
        help="set the operating channel to broadcast on",
    )
    parser.add_argument(
        "-i",
        dest="interface",
        help="set network interface for profiler",
    )
    ssid_group = parser.add_mutually_exclusive_group()
    ssid_group.add_argument(
        "-s", dest="ssid", type=check_ssid, help="set profiler SSID name"
    )
    parser.add_argument(
        "--config",
        type=str,
        metavar="FILE",
        default=CONFIG_FILE,
        help="customize path for configuration file (default: %(default)s)",
    )
    parser.add_argument(
        "--files_path",
        metavar="PATH",
        dest="files_path",
        default="/var/www/html/profiler",
        help="customize default directory where analysis is saved on local system (default: %(default)s)",
    )
    ssid_group.add_argument(
        "--hostname_ssid",
        dest="hostname_ssid",
        action="store_true",
        default=False,
        help="use the WLAN Pi's hostname as SSID name (default: %(default)s)",
    )
    parser.add_argument(
        "--logging",
        help="change logging output",
        nargs="?",
        choices=("debug", "warning"),
    )
    parser.add_argument(
        "--noprep",
        dest="no_interface_prep",
        action="store_true",
        default=False,
        help="disable interface preperation (default: %(default)s)",
    )
    ssid_group.add_argument(
        "--noAP",
        dest="listen_only",
        action="store_true",
        default=False,
        help="enable Rx only mode (default: %(default)s)",
    )
    dot11r_group = parser.add_mutually_exclusive_group()
    dot11r_group.add_argument(
        "--11r",
        dest="ft_enabled",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,  # "turn on 802.11r Fast Transition (FT) reporting (override --config <file>)",
    )
    dot11r_group.add_argument(
        "--no11r",
        dest="ft_disabled",
        action="store_true",
        default=False,
        help="turn off 802.11r Fast Transition (FT) reporting",
    )
    dot11ax_group = parser.add_mutually_exclusive_group()
    dot11ax_group.add_argument(
        "--11ax",
        dest="he_enabled",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,  # "turn on 802.11ax High Efficiency (HE) reporting (override --config <file>)",
    )
    dot11ax_group.add_argument(
        "--no11ax",
        dest="he_disabled",
        action="store_true",
        default=False,
        help="turn off 802.11ax High Efficiency (HE) reporting",
    )
    parser.add_argument(
        "--no_sniffer_filter",
        dest="no_sniffer_filter",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--clean",
        dest="clean",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--files",
        dest="files",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--yes", dest="yes", action="store_true", default=False, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--oui_update",
        dest="oui_update",
        action="store_true",
        default=False,
        help="initiates update of OUI database (requires Internet connection)",
    )
    parser.add_argument(
        "--read",
        metavar="PCAP",
        dest="pcap_analysis",
        help="read and analyze association request frames from pcap",
    )
    parser.add_argument("--version", "-V", action="version", version=f"{__version__}")
    return parser


def files_cleanup(directory: str, acknowledged: bool) -> None:
    """Purge files recursively"""
    log = logging.getLogger(inspect.stack()[0][3])

    from pathlib import Path

    result = list(Path(directory).rglob("*"))
    log.warning("Delete the following files: %s", ", ".join([str(x) for x in result]))

    if acknowledged:
        pass
    elif not input("Are you sure? (y/n): ").lower().strip()[:1] == "y":
        sys.exit(1)

    try:
        for _path in os.listdir(Path(directory)):
            path = Path(directory) / Path(_path)
            if path.is_file():
                print(f"Removing file: {path}")
                path.unlink()
            if path.is_dir():
                print(f"Removing directory: {path}")
                shutil.rmtree(path)
    except OSError:
        log.exception("issue removing files")


def setup_config(args) -> Dict:
    """Create the configuration (SSID, channel, interface, etc) for the Profiler"""
    log = logging.getLogger(inspect.stack()[0][3])

    config_found = False

    # load in config (a: from default location "/etc/wlanpi-profiler/config.ini" or b: from provided)
    if os.path.isfile(args.config):
        config_found = True
        parser = load_config(args.config)
        # we want to work with a dict whether we have config.ini or not
        config = convert_configparser_to_dict(parser)
    else:
        log.warning("can not find config at %s", args.config)
        config = {}

    if "GENERAL" not in config:
        config["GENERAL"] = {}

    # set defaults if configuration file was not found
    if not config_found:
        config["GENERAL"]["ssid"] = "WLAN Pi"
        config["GENERAL"]["channel"] = 36
        config["GENERAL"]["interface"] = "wlan0"

    # handle special config.ini settings
    if config["GENERAL"].get("hostname_ssid"):
        config["GENERAL"]["ssid"] = socket.gethostname()

    # handle args
    #  - args passed in take precedent over config.ini values
    #  - did user pass in options that over-ride defaults?
    if args.channel:
        config["GENERAL"]["channel"] = args.channel
    if args.interface:
        config["GENERAL"]["interface"] = args.interface
    if args.ssid:
        config["GENERAL"]["ssid"] = args.ssid
    elif args.hostname_ssid:
        config["GENERAL"]["ssid"] = socket.gethostname()
    if args.ft_enabled:
        config["GENERAL"]["ft_disabled"] = False
    if args.ft_disabled:
        config["GENERAL"]["ft_disabled"] = args.ft_disabled
    if args.he_enabled:
        config["GENERAL"]["he_disabled"] = False
    if args.he_disabled:
        config["GENERAL"]["he_disabled"] = args.he_disabled
    if args.listen_only:
        config["GENERAL"]["listen_only"] = args.listen_only
    if args.pcap_analysis:
        config["GENERAL"]["pcap_analysis"] = args.pcap_analysis
    if args.files_path:
        config["GENERAL"]["files_path"] = args.files_path
    else:
        config["GENERAL"]["files_path"] = FILES_PATH

    # ensure channel 1 is an integer and not a bool
    config["GENERAL"]["channel"] = int(config["GENERAL"]["channel"])

    return config


def convert_configparser_to_dict(config: configparser.ConfigParser) -> Dict:
    """
    Convert ConfigParser object to dictionary.

    The resulting dictionary has sections as keys which point to a dict of the
    section options as key => value pairs.

    If there is a string representation of truth, it is converted from str to bool.
    """
    _dict: "Dict[str, Any]" = {}
    for section in config.sections():
        _dict[section] = {}
        for key, _value in config.items(section):
            try:
                _value = bool(strtobool(_value))
            except ValueError:
                pass
            _dict[section][key] = _value
    return _dict


def load_config(config_file: str) -> configparser.ConfigParser:
    """Load in config from external file"""
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def validate(config) -> bool:
    """Validate minimum config to run is OK"""
    log = logging.getLogger(inspect.stack()[0][3])

    if not check_config_missing(config):
        return False

    try:
        check_ssid(config.get("GENERAL").get("ssid"))

        check_channel(config.get("GENERAL").get("channel"))

        verify_reporting_directories(config)
    except ValueError:
        log.error("%s", sys.exc_info()[1])
        sys.exit(signal.SIGABRT)

    return True


def is_randomized(mac) -> bool:
    """Check if MAC Address <format>:'00:00:00:00:00:00' is locally assigned"""
    return any(local == mac.lower()[1] for local in ["2", "6", "a", "e"])


def check_config_missing(config: Dict) -> bool:
    """Check that the minimal config items exist"""
    log = logging.getLogger(inspect.stack()[0][3])
    try:
        if "GENERAL" not in config:
            raise KeyError("missing general section from configuration")
        options = config["GENERAL"].keys()
        if "interface" not in options:
            raise KeyError("missing interface from config")
        if "channel" not in options:
            raise KeyError("missing channel from config")
        if "ssid" not in options:
            raise KeyError("missing ssid from config")

    except KeyError:
        log.error("%s", sys.exc_info()[1])
        return False
    return True


def update_manuf() -> bool:
    """Manuf wrapper to update manuf OUI flat file from Internet"""
    log = logging.getLogger(inspect.stack()[0][3])
    try:
        flat_file = os.path.join(manuf.__path__[0], "manuf")
        log.info("manuf file is located at %s", flat_file)
        log.info(
            "manuf file last modified at: %s",
            ctime(os.path.getmtime(flat_file)),
        )
        log.info("running 'sudo manuf --update'")
        cp = run_cli_cmd(["sudo", f"{sys.prefix}/bin/manuf", "--update"])
        log.info("%s", str(cp))
        log.info(
            "manuf file last modified at: %s",
            ctime(os.path.getmtime(flat_file)),
        )
    except OSError:
        log.exception("problem updating manuf. make sure manuf is installed...")
        print("exiting...")
        return False
    return True


def verify_reporting_directories(config: Dict) -> None:
    """Check reporting directories exist and create if not"""
    log = logging.getLogger(inspect.stack()[0][3])

    if "GENERAL" in config:
        files_path = config["GENERAL"].get("files_path")
        if not os.path.isdir(files_path):
            log.debug(os.makedirs(files_path))

        clients_dir = os.path.join(files_path, "clients")

        if not os.path.isdir(clients_dir):
            log.debug(os.makedirs(clients_dir))

        reports_dir = os.path.join(files_path, "reports")

        if not os.path.isdir(reports_dir):
            log.debug(os.makedirs(reports_dir))


def get_frequency_bytes(channel: int) -> bytes:
    """Take a channel number, converts it to a frequency, and finally to bytes"""
    if channel == 14:
        freq = 2484
    if channel < 14:
        freq = 2407 + (channel * 5)
    elif channel > 14:
        freq = 5000 + (channel * 5)

    return freq.to_bytes(2, byteorder="little")


class Base64Encoder(json.JSONEncoder):
    """A Base64 encoder for JSON"""

    # example usage: json.dumps(bytes(frame), cls=Base64Encoder)

    # pylint: disable=method-hidden
    def default(self, obj):
        """Perform default Base64 encode"""
        if isinstance(obj, bytes):
            return b64encode(obj).decode()
        return json.JSONEncoder.default(self, obj)


def get_wlanpi_version() -> str:
    """Retrieve system image verson"""
    wlanpi_version = "unknown"
    try:
        with open("/etc/wlanpi-release") as _file:
            lines = _file.read().splitlines()
            for line in lines:
                if "VERSION" in line:
                    wlanpi_version = "{0}".format(
                        line.split("=")[1].replace('"', "").replace("'", "").strip()
                    )
    except OSError:
        pass
    return wlanpi_version


def flag_last_object(seq):
    """Treat the last object in an iterable differently"""
    seq = iter(seq)  # ensure seq is an iterator
    _a = next(seq)
    for _b in seq:
        yield _a, False
        _a = _b
    yield _a, True


def generate_run_message(config: Dict) -> None:
    """Create message to display to users screen"""
    if config["GENERAL"].get("listen_only") is True:
        out = []
        out.append("Starting profiler in listen only mode:")
        out.append(
            f" - Listening for association frames with {config['GENERAL']['interface']} on channel {config['GENERAL']['channel']}"
        )
        out.append(" - Results are saved locally and printed to screen")
        out.append(" ")
        out.append("Instructions:")
        out.append(
            f" - Associate your Wi-Fi client to any AP on channel {config['GENERAL']['channel']}"
        )
        out.append(" - We should passively detect the association request")
        header_len = len(max(out, key=len))

        print(f"\n{'~' * header_len}")
        for line in out:
            print(line)
        print(f"{'~' * header_len}\n")
    else:
        out = []
        channel = config["GENERAL"]["channel"]
        interface = config["GENERAL"]["interface"]
        ssid = config["GENERAL"]["ssid"]
        if channel:
            out.append(
                f"Starting profiler AP with interface {interface} on channel {channel}:"
            )
        else:
            out.append(f"Starting profiler AP with interface {interface}")
        out.append(f" - Our fake AP SSID: {ssid}")
        out.append(" - Results are saved locally and printed to screen")
        out.append(" ")
        out.append("Instructions:")
        out.append(f" - Associate your Wi-Fi client to our SSID: {ssid}")
        out.append(" - Enter any random password to connect")
        out.append(" ")
        out.append(
            "The client will fail authentication but should send an association request"
        )
        header_len = len(max(out, key=len))

        print(f"\n{'=' * header_len}")
        for line in out:
            print(line)
        print(f"{'=' * header_len}\n")


@dataclass
class Capability:
    """Define custom fields for reporting"""

    name: str = ""
    value: Union[str, int] = ""
    db_key: str = ""
    db_value: Union[int, str, List[str]] = 0


def get_bit(byteval, index) -> bool:
    """Retrieve bit value from byte at provided index"""
    return (byteval & (1 << index)) != 0
