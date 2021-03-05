# -* coding: utf-8 -*-
#
# profiler2: a Wi-Fi client capability analyzer
# Copyright 2021 Josh Schmelzle
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
profiler2.helpers
~~~~~~~~~~~~~~~~~

provides init functions that are used to help setup the app.
"""

# standard library imports
import argparse
import configparser
import inspect
import logging
import logging.config
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from distutils.util import strtobool
from multiprocessing import Value
from time import ctime
from typing import Union

# third party imports
try:
    import manuf
    from scapy.all import (Dot11Elt, Scapy_Exception, get_if_hwaddr,
                           get_if_raw_hwaddr)
except ModuleNotFoundError as error:
    if error.name == "manuf":
        print(f"required module manuf not found. try installing manuf.")
    elif error.name == "scapy":
        print(
            "required module scapy not found. try installing scapy with `python -m pip install --pre scapy[basic]`."
        )
    else:
        print(f"{error}")
    sys.exit(signal.SIGABRT)

# is tcpdump installed?
try:
    result = subprocess.run(
        ["tcpdump", "--version"], shell=False, check=True, capture_output=True
    )
except Exception:
    print(
        "problem checking tcpdump version. is tcpdump installed and functioning? exiting..."
    )
    sys.exit(signal.SIGABRT)

# is netstat installed?
try:
    result = subprocess.run(
        ["netstat", "--version"], shell=False, check=True, capture_output=True
    )
except Exception:
    print(
        "problem checking netstat version. is netstat installed and functioning? exiting..."
    )
    sys.exit(signal.SIGABRT)

# app imports
from .__version__ import __version__
from .constants import CHANNELS, CONFIG_FILE

FILES_PATH = "/var/www/html/profiler"


def setup_logger(args) -> logging.Logger:
    """ Configure and set logging levels """
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
    # return logging.getLogger(__name__)


def check_channel(value: str) -> int:
    """ Check if channel is valid """
    channel = int(value)
    error_msg = "%s is not a valid channel value" % channel
    if channel <= 0:
        raise ValueError(error_msg)
    if channel in CHANNELS:
        return channel
    else:
        raise ValueError(error_msg)


def check_ssid(ssid: str) -> str:
    """ Check if SSID is valid """
    if len(ssid) > 32:
        raise ValueError("%s length is greater than 32" % ssid)
    return ssid


def check_interface(interface: str) -> str:
    """ Check that the interface we've been asked to run on actually exists """
    log = logging.getLogger(inspect.stack()[0][3])
    discovered_interfaces = []
    for iface in os.listdir("/sys/class/net"):
        iface_path = os.path.join("/sys/class/net", iface)
        if os.path.isdir(iface_path):
            if "phy80211" in os.listdir(iface_path):
                discovered_interfaces.append(iface)
    if interface not in discovered_interfaces:
        log.warning(
            "%s interface not found in phy80211 interfaces: %s",
            interface,
            ", ".join(discovered_interfaces),
        )
        raise ValueError(f"{interface} is not a valid interface")
    else:
        log.debug(
            "%s is in discovered phy80211 interfaces: %s",
            interface,
            ", ".join(discovered_interfaces),
        )
        return interface


def setup_parser() -> argparse:
    """ Set default values and handle arg parser """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            """
            a Wi-Fi client analyzer for identifying supported 802.11 capabilities
            """
        ),
    )
    parser.add_argument(
        "-i",
        dest="interface",
        help="set network interface for profiler (default: %(default)s)",
    )
    parser.add_argument(
        "--noprep",
        dest="no_interface_prep",
        action="store_true",
        default=False,
        help="disable interface preperation (default: %(default)s)",
    )
    parser.add_argument(
        "--pytest",
        dest="pytest",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-c", dest="channel", type=check_channel, help="802.11 channel to broadcast on"
    )
    ssid_group = parser.add_mutually_exclusive_group()
    ssid_group.add_argument(
        "-s", dest="ssid", type=check_ssid, help="set profiler SSID"
    )
    ssid_group.add_argument(
        "--hostname_ssid",
        dest="hostname_ssid",
        action="store_true",
        default=False,
        help="use the WLAN Pi's hostname as SSID name",
    )
    ssid_group.add_argument(
        "--noAP",
        dest="listen_only",
        action="store_true",
        default=False,
        help="enable listen only mode (Rx only)",
    )
    dot11r_group = parser.add_mutually_exclusive_group()
    dot11r_group.add_argument(
        "--11r",
        dest="ft_enabled",
        action="store_true",
        default=False,
        help="turn on 802.11r Fast Transition (FT) reporting (override --config file)",
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
        help="turn on 802.11ax High Efficiency (HE) reporting (override --config file)",
    )
    dot11ax_group.add_argument(
        "--no11ax",
        dest="he_disabled",
        action="store_true",
        default=False,
        help="turn off 802.11ax High Efficiency (HE) reporting",
    )
    parser.add_argument(
        "--pcap",
        metavar="<FILE>",
        dest="pcap_analysis",
        help="analyze first packet of pcap (expecting an association request frame)",
    )
    parser.add_argument(
        "--config",
        type=str,
        metavar="<FILE>",
        default=CONFIG_FILE,
        help="customize path for configuration file (default: %(default)s)",
    )
    parser.add_argument(
        "--files_path",
        metavar="<PATH>",
        dest="files_path",
        default="/var/www/html/profiler",
        help="customize default directory where analysis is saved on local system (default: %(default)s)",
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
        help="initiates Internet update of OUI database",
    )
    parser.add_argument(
        "--logging",
        help="change logging output",
        nargs="?",
        choices=("debug", "warning"),
    )
    parser.add_argument("--version", "-V", action="version", version=f"{__version__}")
    return parser


def files_cleanup(directory: str, acknowledged: bool) -> None:
    """ Purge files recursively """
    log = logging.getLogger(inspect.stack()[0][3])

    from pathlib import Path

    result = list(Path(directory).rglob("*"))
    print(f"Delete the following files: {', '.join([str(x) for x in result])}")

    if acknowledged:
        pass
    elif not input("Are you sure? (y/n): ").lower().strip()[:1] == "y":
        sys.exit(1)

    try:
        for p in os.listdir(Path(directory)):
            p = Path(directory) / Path(p)
            if p.is_file():
                print(f"Removing file: {p}")
                p.unlink()
            if p.is_dir():
                print(f"Removing directory: {p}")
                shutil.rmtree(p)
    except Exception:
        log.exception("issue removing files")


def setup_config(args) -> dict:
    """ Create the configuration (SSID, channel, interface, etc) for the Profiler """
    log = logging.getLogger(inspect.stack()[0][3])

    config_found = False

    # load in config (a: from default location "/etc/profiler2/config.ini" or b: from provided)
    if os.path.isfile(args.config):
        config_found = True
        parser = load_config(args.config)
        # we want to work with a dict whether we have config.ini or not
        config = convert_configparser_to_dict(parser)
    else:
        parser = None
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

    return config


def convert_configparser_to_dict(config: configparser.ConfigParser) -> dict:
    """
    Convert ConfigParser object to dictionary.

    The resulting dictionary has sections as keys which point to a dict of the
    section options as key => value pairs.

    If there is a string representation of truth, it is converted from str to bool.
    """
    _dict = {}
    for section in config.sections():
        _dict[section] = {}
        for key, value in config.items(section):
            try:
                value = bool(strtobool(value))
            except ValueError:
                pass
            _dict[section][key] = value
    return _dict


def load_config(config_file: str) -> configparser.ConfigParser:
    """ Load in config from external file """
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def validate(config: dict) -> bool:
    """ Validate minimum config to run is OK """
    log = logging.getLogger(inspect.stack()[0][3])

    if not check_config_missing(config):
        return False

    try:
        check_ssid(config.get("GENERAL").get("ssid"))

        check_channel(config.get("GENERAL").get("channel"))

        check_interface(config.get("GENERAL").get("interface"))

        verify_reporting_directories(config)
    except ValueError:
        log.error("%s", sys.exc_info()[1])
        sys.exit(signal.SIGABRT)

    return True


def prep_interface(interface: str, mode: str, channel: int) -> bool:
    """ Prepare the interface for monitor mode and injection """
    log = logging.getLogger(inspect.stack()[0][3])
    if mode in ("managed", "monitor"):
        commands = [
            ["ip", "link", "set", f"{interface}", "down"],
            ["iw", "dev", f"{interface}", "set", "type", f"{mode}"],
            ["ip", "link", "set", f"{interface}", "up"],
            ["iw", f"{interface}", "set", "channel", f"{channel}"],
        ]
        try:
            driver = subprocess.run(
                ["readlink", "-f", f"/sys/class/net/{interface}/device/driver"],
                encoding="utf-8",
                shell=False,
                check=True,
                capture_output=True,
            )
            mac = subprocess.run(
                ["cat", f"/sys/class/net/{interface}/address"],
                encoding="utf-8",
                shell=False,
                check=True,
                capture_output=True,
            )
            log.info(
                "mac: %s, driver: %s",
                mac.stdout.replace("\n", ""),
                driver.stdout.split("/")[-1].replace("\n", ""),
            )
            regdomain = subprocess.run(
                ["iw", "reg", "get"],
                encoding="utf-8",
                shell=False,
                check=True,
                capture_output=True,
            )
            regdomain = [
                line for line in regdomain.stdout.split("\n") if "country" in line
            ]

            if "UNSET" in "".join(regdomain):
                log.warn("UNSET REG DOMAIN DETECTED!")
            else:
                log.debug("reg domain: %s", regdomain)

            for cmd in commands:
                cp = subprocess.run(
                    cmd, encoding="utf-8", shell=False, capture_output=True
                )
                if cp.stderr:
                    raise OSError(f"problem running '{' '.join(cmd)}'\n{cp.stderr}")

            return True
        except Exception:
            log.error(
                "error setting wlan interface config %s",
                "\n".join(
                    [line for line in cp.stderr.split("\n") if line.strip() != ""]
                ),
            )
    else:
        log.error("failed to prep interface config...")
        return False


def check_config_missing(config: dict) -> bool:
    """ Check that the minimal config items exist """
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
    """ Manuf wrapper to update manuf OUI flat file from Internet """
    log = logging.getLogger(inspect.stack()[0][3])
    try:
        log.debug(
            "manuf flat file located at %s", os.path.join(manuf.__path__[0], "manuf")
        )
        log.debug(
            "manuf last modified time: %s",
            ctime(os.path.getmtime(os.path.join(manuf.__path__[0], "manuf"))),
        )
        log.debug("running 'sudo manuf --update'")
        cp = subprocess.run(
            ["sudo", "manuf", "--update"],
            encoding="utf-8",
            shell=False,
            check=True,
            capture_output=True,
        )
        log.info("%s", str(cp))
        log.debug(
            "manuf last modified time: %s",
            ctime(os.path.getmtime(os.path.join(manuf.__path__[0], "manuf"))),
        )
    except Exception:
        log.exception("problem updating manuf. make sure manuf is installed...")
        print("exiting...")
        return False
    return True


def verify_reporting_directories(config: dict) -> None:
    """ Check reporting directories exist and create if not """
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
    """ Take a channel number, converts it to a frequency, and finally to bytes """
    if channel == 14:
        freq = 2484
    if channel < 14:
        freq = 2407 + (channel * 5)
    elif channel > 14:
        freq = 5000 + (channel * 5)

    return freq.to_bytes(2, byteorder="little")


def build_fake_frame_ies(config: dict) -> Dot11Elt:
    """ Build base frame for beacon and probe resp """
    ssid = config.get("GENERAL").get("ssid")
    channel = int(config.get("GENERAL").get("channel"))
    ft_disabled = config.get("GENERAL").get("ft_disabled")
    he_disabled = config.get("GENERAL").get("he_disabled")

    ssid = bytes(ssid, "utf-8")
    essid = Dot11Elt(ID="SSID", info=ssid)

    rates_data = [140, 18, 152, 36, 176, 72, 96, 108]
    rates = Dot11Elt(ID="Rates", info=bytes(rates_data))

    channel = bytes([channel])
    dsset = Dot11Elt(ID="DSset", info=channel)

    dtim_data = b"\x05\x04\x00\x03\x00\x00"
    dtim = Dot11Elt(ID="TIM", info=dtim_data)

    ht_cap_data = b"\xef\x19\x1b\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ht_capabilities = Dot11Elt(ID=0x2D, info=ht_cap_data)

    if ft_disabled:
        rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x80\x00"
    else:
        mobility_domain_data = b"\x45\xc2\x00"
        mobility_domain = Dot11Elt(ID=0x36, info=mobility_domain_data)
        rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x8c\x00"

    rsn = Dot11Elt(ID=0x30, info=rsn_data)

    ht_info_data = (
        channel
        + b"\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    ht_information = Dot11Elt(ID=0x3D, info=ht_info_data)

    rm_enabled_data = b"\x02\x00\x00\x00\x00"
    rm_enabled_cap = Dot11Elt(ID=0x46, info=rm_enabled_data)

    extended_data = b"\x00\x00\x08\x00\x00\x00\x00\x40"
    extended = Dot11Elt(ID=0x7F, info=extended_data)

    vht_cap_data = b"\x32\x00\x80\x03\xaa\xff\x00\x00\xaa\xff\x00\x00"
    vht_capabilities = Dot11Elt(ID=0xBF, info=vht_cap_data)

    vht_op_data = b"\x00\x24\x00\x00\x00"
    vht_operation = Dot11Elt(ID=0xC0, info=vht_op_data)

    wmm_data = b"\x00\x50\xf2\x02\x01\x01\x8a\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"
    wmm = Dot11Elt(ID=0xDD, info=wmm_data)

    he_cap_data = b"\x23\x0d\x01\x00\x02\x40\x00\x04\x70\x0c\x89\x7f\x03\x80\x04\x00\x00\x00\xaa\xaa\xaa\xaa\x7b\x1c\xc7\x71\x1c\xc7\x71\x1c\xc7\x71\x1c\xc7\x71"
    he_capabilities = Dot11Elt(ID=0xFF, info=he_cap_data)

    he_op_data = b"\x24\xf4\x3f\x00\x19\xfc\xff"
    he_operation = Dot11Elt(ID=0xFF, info=he_op_data)

    spatial_reuse_data = b"\x27\x05\x00"
    spatial_reuse = Dot11Elt(ID=0xFF, info=spatial_reuse_data)

    mu_edca_data = b"\x26\x09\x03\xa4\x28\x27\xa4\x28\x42\x73\x28\x62\x72\x28"
    mu_edca_data = Dot11Elt(ID=0xFF, info=mu_edca_data)

    if ft_disabled:
        frame = (
            essid
            / rates
            / dsset
            / dtim
            / ht_capabilities
            / rsn
            / ht_information
            / rm_enabled_cap
            / extended
            / vht_capabilities
            / vht_operation
        )
    else:
        frame = (
            essid
            / rates
            / dsset
            / dtim
            / ht_capabilities
            / rsn
            / ht_information
            / mobility_domain
            / rm_enabled_cap
            / extended
            / vht_capabilities
            / vht_operation
        )
    if he_disabled:
        frame = frame / wmm
    else:
        frame = (
            frame / he_capabilities / he_operation / spatial_reuse / mu_edca_data / wmm
        )

    # for gathering data to validate tests:
    #
    # frame_bytes = bytes(frame)
    # print(frame_bytes)
    return frame


def flag_last_object(seq: iter):
    """ Treat the last object in an iterable differently """
    seq = iter(seq)  # ensure seq is an iterator
    _a = next(seq)
    for _b in seq:
        yield _a, False
        _a = _b
    yield _a, True


def next_sequence_number(sequence_number: Value) -> int:
    """ Update a sequence number of type multiprocessing Value """
    sequence_number.value = (sequence_number.value + 1) % 4096
    return sequence_number.value


def get_mac(interface: str) -> str:
    """ Get the mac address for a specified interface """
    try:
        mac = get_if_hwaddr(interface)
    except Scapy_Exception:
        mac = ":".join(format(x, "02x") for x in get_if_raw_hwaddr(interface)[1])
    return mac


def get_ssh_destination_ip() -> Union[str, bool]:
    """ Get the destination IP of SSH to display to user """
    log = logging.getLogger(inspect.stack()[0][3])
    try:
        cp = subprocess.run(["netstat", "-tnpa"], capture_output=True)
        for line in cp.stdout.splitlines():
            socket = str(line)
            if "22" in socket and "ESTABLISHED" in socket:
                dest_ip_re = re.search(r"(\d+?\.\d+?\.\d+?\.\d+?)\:22", socket)
                if dest_ip_re:
                    return dest_ip_re.group(1)
    except Exception:
        log.warning(
            "netstat for finding SSH session IP failed - this is expected when launched from the front panel menu system"
        )
        return False
    else:
        return False


def generate_run_message(config: dict) -> None:
    """ Create message to display to users screen """
    ssh_dest_ip = get_ssh_destination_ip()
    if config["GENERAL"].get("listen_only") is True:
        print(f"\n{'-' * 44}")
        print("Listening for association frames...")
        print(f"SSID: {config['GENERAL']['ssid']}")
        print(f"Channel: {config['GENERAL']['channel']}")
        print(f"Interface: {config['GENERAL']['interface']}")
        if ssh_dest_ip:
            print(f"Results: http://{ssh_dest_ip}/profiler/")
        print(f"{'-' * 44}\n")
    else:
        print("\n" + "-" * 44)
        print("Starting Profiler\n")
        print(f"SSID: {config['GENERAL']['ssid']}")
        print(f"Channel: {config['GENERAL']['channel']}")
        print(f"Interface: {config['GENERAL']['interface']}")
        if ssh_dest_ip:
            print(f"Results: http://{ssh_dest_ip}/profiler/")
        print(f"{'-' * 44}")
        print(f"\n{'#' * 100}")
        print("Instructions:")
        print(f" - Connect a Wi-Fi client to SSID: {config['GENERAL']['ssid']}")
        print(" - Enter any random 8 characters for the PSK")
        print(" - Goal is to get the client to send an association request")
        print(f"{'#' * 100}\n")


@dataclass
class Capability:
    """ Define custom fields for reporting """

    name: str = None
    value: str = None
    db_key: str = None
    db_value: int = 0


def get_bit(byteval, index) -> bool:
    """ retrieve bit value from byte at provided index """
    return (byteval & (1 << index)) != 0
