# -*- coding: utf-8 -*-
#
# profiler2: a Wi-Fi client capability analyzer
# Copyright (C) 2020 WLAN Pi Community.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
profiler2.helpers
~~~~~~~~~~~~~~~~~

provides init functions that are used to help setup the app.
"""

# standard library imports
import argparse, configparser, inspect, logging, logging.config, os, re, socket, subprocess, sys, textwrap
from dataclasses import dataclass
from datetime import timedelta
from multiprocessing import Value
from time import ctime
from typing import Union

# third party imports
try:
    import manuf
    from scapy.all import (
        RadioTap,
        Dot11Elt,
        get_if_hwaddr,
        get_if_raw_hwaddr,
        Scapy_Exception,
    )
except ModuleNotFoundError as error:
    if error.name == "manuf":
        print(f"{error}. please install manuf-ng... exiting...")
    elif error.name == "scapy":
        print(f"{error}. please install scapy... exiting...")
    else:
        print(f"{error}")
    sys.exit(-1)

# is tcpdump installed?
try:
    result = subprocess.run(
        ["tcpdump", "--version"], shell=False, check=True, capture_output=True
    )
except Exception:
    print(
        "problem checking tcpdump version. is tcpdump installed and functioning? exiting..."
    )
    sys.exit(-1)

# app imports
from .__version__ import __version__
from .constants import CHANNELS, CLIENTS_DIR, REPORTS_DIR, ROOT_DIR


def setup_logger(args) -> logging.Logger:
    """ Configure and set logging levels """
    if args.logging:
        if args.logging == "debug":
            logging_level = logging.DEBUG
        if args.logging == "info":
            logging_level = logging.INFO
    else:
        logging_level = logging.WARNING

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


def setup_parser() -> argparse:
    """ Set default values and handle arg parser """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            """
            a Wi-Fi client analyzer for identifying supported 802.11 capabilities
            """
        ),
        epilog=f"made with Python by the WLAN Pi Community",
        fromfile_prefix_chars="2",
    )
    parser.add_argument(
        "-i", dest="interface", help="set network interface for profiler"
    )
    parser.add_argument("-c", dest="channel", help="802.11 channel to broadcast on")
    ssid_group = parser.add_mutually_exclusive_group()
    ssid_group.add_argument(
        "-s", dest="ssid", help="set network identifier for profiler SSID"
    )
    ssid_group.add_argument(
        "--host_ssid",
        dest="hostname_as_ssid",
        action="store_true",
        default=False,
        help="use the WLAN Pi's hostname as profiler SSID",
    )
    parser.add_argument(
        "--file",
        metavar="<FILE>",
        dest="pcap_analysis_only",
        help="read first packet of pcap file expecting an association request frame",
    )
    config = os.path.join(os.path.dirname(os.path.realpath(__file__)), "config.ini")
    parser.add_argument(
        "--config",
        type=str,
        metavar="<FILE>",
        default=config,
        help="specify path for configuration file",
    )
    parser.add_argument(
        "--noAP",
        dest="listen_only",
        action="store_true",
        default=False,
        help="enable listen only mode (Rx only)",
    )
    parser.add_argument(
        "--no11ax",
        dest="he_enabled",
        action="store_false",
        help="turn off 802.11ax High Efficiency (HE) reporting",
    )
    parser.add_argument(
        "--no11r",
        dest="ft_enabled",
        action="store_false",
        help="turn off 802.11r Fast Transition (FT) reporting",
    )
    parser.add_argument(
        "--menu_mode",
        dest="menu_mode",
        action="store_true",
        default=False,
        help="enable WLAN Pi FPMS menu reporting",
    )
    parser.add_argument(
        "--menu_file",
        metavar="<FILE>",
        dest="menu_file",
        default="/tmp/profiler_menu_report.txt",
        help="change menu report file location for WLAN Pi FPMS",
    )
    parser.add_argument(
        "--crust",
        dest="crust",
        action="store_true",
        default=False,
        help="use the WLANPI-crust datastore",
    )
    parser.add_argument(
        "--files_root",
        metavar="<PATH>",
        dest="files_root",
        default="/var/www/html/files",
        help="default root directory for reporting and pcaps",
    )
    parser.add_argument(
        "--clean",
        dest="clean",
        action="store_true",
        default=False,
        help="cleans out the old CSV reports",
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
        help="increase output for debugging",
        nargs="?",
        choices=("debug", "info"),
    )
    parser.add_argument(
        "--version", "-V", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def report_cleanup(_dir) -> None:
    """ Purge reports """
    log = logging.getLogger(inspect.stack()[0][3])

    for _file in os.listdir(_dir):
        try:
            print(f"removing old file: {_file}")
            os.unlink(os.path.join(_dir, _file))
        except Exception as error:
            log.exception(f"issue removing file: {error}")


def setup_config(args) -> dict:
    """ Create the configuration (SSID, channel, interface, etc) for the Profiler """
    log = logging.getLogger(inspect.stack()[0][3])

    # load in config (a: from default location "/config.ini" or b: from provided)
    if os.path.isfile(args.config):
        parser = load_config(args.config)
    else:
        parser = None

    if not parser:
        # couldn't find default config.ini file or user provided config
        log.warning(f"couldn't find config at {args.config}")

    config = {}

    if parser:
        # we want to work with a dict whether we have config.ini or not.
        config = convert_configparser_to_dict(parser)

    if "GENERAL" not in config:
        config["GENERAL"] = {}

    # did user pass in options that over-ride defaults?
    if args.channel:
        config["GENERAL"]["channel"] = args.channel
    if args.interface:
        config["GENERAL"]["interface"] = args.interface
    if args.ssid:
        config["GENERAL"]["ssid"] = args.ssid
    elif args.hostname_as_ssid:
        config["GENERAL"]["ssid"] = socket.gethostname()
    if args.ft_enabled:
        config["GENERAL"]["ft_enabled"] = args.ft_enabled
    if args.he_enabled:
        config["GENERAL"]["he_enabled"] = args.he_enabled
    if args.listen_only:
        config["GENERAL"]["listen_only"] = args.listen_only
    if args.crust:
        config["GENERAL"]["crust"] = args.crust
    if args.menu_file:
        config["GENERAL"]["menu_file"] = args.menu_file
    if args.files_root:
        config["GENERAL"]["files_root"] = args.files_root
    if args.menu_file:
        config["GENERAL"]["menu_file"] = args.menu_file

    # validate config.
    if validate(config):
        log.debug(f"config: {config}")
        return config
    else:
        log.error("configuration validation failed... exiting...")
        sys.exit(-1)


def convert_configparser_to_dict(config: configparser.ConfigParser) -> dict:
    """
    Convert ConfigParser object to dictionary.

    The resulting dictionary has sections as keys which point to a dict of the
    section options as key => value pairs.
    """
    _dict = {}
    for section in config.sections():
        _dict[section] = {}
        for key, value in config.items(section):
            _dict[section][key] = value
    return _dict


def load_config(config_file: str) -> Union[configparser.ConfigParser, bool]:
    """ Load in config from external file """
    log = logging.getLogger(inspect.stack()[0][3])
    try:
        config = configparser.ConfigParser()
        config.read(config_file)
    except FileNotFoundError:
        log.exception("could not find config file")
    if config:
        return config
    else:
        return None


def validate(config: dict) -> bool:
    """ Make sure  """
    log = logging.getLogger(inspect.stack()[0][3])
    log.info("checking config")

    if not check_config_missing(config):
        return False

    if not is_fakeap_interface_valid(config):
        return False

    if not is_ssid_valid(config):
        return False

    if not is_channel_valid(config):
        return False

    verify_reporting_directories(config)

    log.info("finish checking config")

    return True


def prep_interface(interface: str, mode: str, channel: int) -> bool:
    """ Prepare the interface for monitor mode and injection """
    log = logging.getLogger(inspect.stack()[0][3])
    if mode in ("managed", "monitor"):
        commands = [
            ["airmon-ng", "check", "kill"],
            ["ip", "link", "set", f"{interface}", "down"],
            ["iw", "dev", f"{interface}", "set", "type", f"{mode}"],
            ["ip", "link", "set", f"{interface}", "up"],
            ["iw", f"{interface}", "set", "channel", f"{channel}"],
        ]
        try:
            [
                subprocess.run(c, shell=False, check=True, capture_output=True)
                for c in commands
            ]
            return True
        except Exception as error:
            log.error("error setting wlan interface config")
            log.exception(error)
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
        log.error(sys.exc_info()[1])
        return False
    return True


def update_manuf() -> bool:
    """ Ypdate manuf flat file from Internet """
    log = logging.getLogger(inspect.stack()[0][3])
    try:
        log.debug(
            f"manuf flat file located at {os.path.join(manuf.__path__[0], 'manuf')}"
        )
        log.debug(
            f"manuf last modified time: {ctime(os.path.getmtime(os.path.join(manuf.__path__[0], 'manuf')))}"
        )
        log.debug(f"running 'sudo manuf --update'")
        subprocess.run(
            ["sudo", "manuf", "--update"], shell=False, check=True, capture_output=True
        )
        log.debug(
            f"manuf last modified time: {ctime(os.path.getmtime(os.path.join(manuf.__path__[0], 'manuf')))}"
        )
    except Exception as error:
        print("problem updating manuf. make sure manuf-ng is installed...")
        print(f"{error}")
        print("exiting...")
        return False
    return True


def is_fakeap_interface_valid(config: dict) -> bool:
    """ Check that the interface we've been asked to run on actually exists """
    log = logging.getLogger(inspect.stack()[0][3])
    discovered_interfaces = []
    interface = config.get("GENERAL").get("interface")
    for iface in os.listdir("/sys/class/net"):
        if "phy80211" in os.listdir(os.path.join("/sys/class/net", iface)):
            discovered_interfaces.append(iface)
    if interface in discovered_interfaces:
        log.info(
            f"{interface} is in discovered interfaces: {', '.join(discovered_interfaces)}"
        )
        return True
    else:
        log.critical(
            f"interface {interface} is not in discovered interfaces: {discovered_interfaces}"
        )
        return False


def is_ssid_valid(config: dict) -> bool:
    """ Check profiler AP SSID is valid """
    log = logging.getLogger(inspect.stack()[0][3])

    ssid = config.get("GENERAL").get("ssid")
    log.info(f"ssid is {ssid}")
    if len(ssid) > 32:
        log.critical(f"ssid length cannot be greater than 32")
        return False
    return True


def is_channel_valid(config: dict) -> bool:
    """ Check profiler AP channel is valid """
    log = logging.getLogger(inspect.stack()[0][3])
    channel = config.get("GENERAL").get("channel")
    if int(channel) in CHANNELS:
        log.info(f"{channel} is a valid 802.11 channel")
        return True
    else:
        log.critical(f"channel {channel} is not a valid channel")
        return False


def verify_reporting_directories(config: dict):
    """ Check reporting directories exist and create if not """
    log = logging.getLogger(inspect.stack()[0][3])

    if "GENERAL" in config:
        files_root = config["GENERAL"].get("files_root")
        if not os.path.isdir(files_root):
            log.debug(os.makedirs(files_root))

        root_dir = os.path.join(files_root, ROOT_DIR)

        if not os.path.isdir(root_dir):
            log.debug(os.makedirs(root_dir))

        clients_dir = os.path.join(files_root, ROOT_DIR, CLIENTS_DIR)

        if not os.path.isdir(clients_dir):
            log.debug(os.makedirs(clients_dir))

        reports_dir = os.path.join(files_root, ROOT_DIR, REPORTS_DIR)

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


def build_fake_frame_ies(ssid: str, channel: int, args) -> Dot11Elt:
    """ Build base frame for beacon and probe resp """
    ssid = bytes(ssid, "utf-8")
    essid = Dot11Elt(ID="SSID", info=ssid)

    rates_data = [140, 18, 152, 36, 176, 72, 96, 108]
    rates = Dot11Elt(ID="Rates", info=bytes(rates_data))

    channel = bytes([channel])
    dsset = Dot11Elt(ID="DSset", info=channel)

    dtim_data = b"\x05\x04\x00\x03\x00\x00"
    dtim = Dot11Elt(ID="TIM", info=dtim_data)

    ht_cap_data = b"\xef\x19\x1b\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ht_capabilities = Dot11Elt(ID=0x2D, info=ht_cap_data)

    if args.ft_enabled:
        mobility_domain_data = b"\x45\xc2\x00"
        mobility_domain = Dot11Elt(ID=0x36, info=mobility_domain_data)
        rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x8c\x00"
    else:
        rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x80\x00"
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

    he_cap_data = b"\x23\x09\x01\x00\x02\x40\x00\x04\x70\x0c\x80\x02\x03\x80\x04\x00\x00\x00\xaa\xff\xaa\xff\x7b\x1c\xc7\x71\x1c\xc7\x71\x1c\xc7\x71\x1c\xc7\x71"
    he_capabilities = Dot11Elt(ID=0xFF, info=he_cap_data)

    he_op_data = b"\x24\xf4\x3f\x00\x19\xfc\xff"
    he_operation = Dot11Elt(ID=0xFF, info=he_op_data)

    if args.ft_enabled:
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
    else:
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
    if args.he_enabled:
        frame = frame / he_capabilities / he_operation / wmm
    else:
        frame = frame / wmm

    return frame


def flag_last_object(seq):
    """ Treat the last object in an iterable differently """
    seq = iter(seq)  # ensure this is an iterator
    _a = next(seq)
    for _b in seq:
        yield _a, False
        _a = _b
    yield _a, True


def bytes_to_int(x_bytes: bytes) -> int:
    """ Convert bytes to integer """
    return int.from_bytes(x_bytes, "big")


def next_sequence_number(sequence_number: Value):
    """ Update a sequence number of type multiprocessing Value """
    sequence_number.value = (sequence_number.value + 1) % 4096
    return sequence_number.value


def get_radiotap_header(channel: int):
    """ Build a pseudo radio tap header """
    radiotap_packet = RadioTap(
        present="Flags+Rate+Channel+dBm_AntSignal+Antenna",
        notdecoded=b"\x8c\00"
        + get_frequency_bytes(channel)
        + b"\xc0\x00\xc0\x01\x00\x00",
    )
    return radiotap_packet


def get_mac(interface: str) -> str:
    """ Get the mac address for a specified interface """
    try:
        mac = get_if_hwaddr(interface)
    except Scapy_Exception:
        mac = ":".join(format(x, "02x") for x in get_if_raw_hwaddr(interface)[1])
    return mac


def generate_menu_report(config: dict, client_count: int, last_manuf: str) -> None:
    """ Create report for WLAN Pi FPMS """
    log = logging.getLogger(inspect.stack()[0][3])
    menu_file = config.get("GENERAL").get("menu_file")
    channel = int(config.get("GENERAL").get("channel"))
    ft_enabled = config.get("GENERAL").get("ft_enabled")
    he_enabled = config.get("GENERAL").get("he_enabled")
    ssid = config.get("GENERAL").get("ssid")
    report = [
        "Status: running\r",
        f"Ch:{channel} 11r:{'Yes' if ft_enabled else 'No'} 11ax:{'Yes' if he_enabled else 'No'}\r",
        f"SSID: {ssid}\r",
        f"Clients:{client_count} ({last_manuf})",
    ]
    log.debug(f"report: {report}")
    with open(menu_file, "w") as file:
        for _ in report:
            file.write(_)


def get_ssh_destination_ip() -> Union[str, bool]:
    """ Get the destination IP of SSH to display to user """
    log = logging.getLogger(inspect.stack()[0][3])
    try:
        cp = subprocess.run(["netstat", "-tnpa"], capture_output=True)
        for _socket in cp.stdout.splitlines():
            _socket = str(_socket)
            if "22" in _socket and "ESTABLISHED" in _socket:
                dest_ip_re = re.search(r"(\d+?\.\d+?\.\d+?\.\d+?)\:22", _socket)
    except Exception as error:
        log.exception(
            "netstat for finding SSH session IP failed - this is expected when launched from the front panel menu system"
        )
        log.exception(f"{error}")
        return False
    else:
        return dest_ip_re.group(1)


def generate_run_message(config: dict) -> Union[str, bool]:
    """ Create message to display to users screen """
    ssh_dest_ip = get_ssh_destination_ip()
    if config["GENERAL"]["listen_only"] is True:
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


def convert_timestamp_to_uptime(timestamp) -> str:
    """
    Convert timestamp field from the 802.11 beacon or probe response frame to a
    human readable format. This frame is received by the WLAN interface.
    :param timestamp: unix integer representing an uptime timestamp
    :return: human readable uptime string
    """
    timestamp = timedelta(microseconds=timestamp)
    timestamp = timestamp - timedelta(microseconds=timestamp.microseconds)
    return (
        f"{str(timestamp.days).strip().zfill(2)}d "
        f"{str(timestamp).rpartition(',')[2].strip()}"
    )


@dataclass
class Capability:
    """ Define custom fields for reporting """

    name: str = None
    value: str = None
    db_key: str = None
    db_value: int = 0
