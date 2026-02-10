# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.helpers
~~~~~~~~~~~~~~~~

provides init functions that are used to help setup the app.
"""

import argparse
import configparser
import contextlib
import inspect
import json
import logging
import logging.config
import os
import platform
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import zlib
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path
from time import ctime
from typing import Any, Optional, Union

try:
    import grp
    import pwd
except ImportError:
    grp = None  # type: ignore[assignment]  # grp module not available on Windows
    pwd = None  # type: ignore[assignment]  # pwd module not available on Windows

try:
    import manuf2  # type: ignore[import-untyped]
except ModuleNotFoundError:
    manuf2 = None  # type: ignore[assignment]  # OUI lookups disabled but core works


__tools = [
    "tcpdump",
    "iw",
    "ip",  # iproute2
    "ethtool",
    "lspci",  # usbutils
    "lsusb",  # pciutils
    "modprobe",  # kmod
    "modinfo",  # kmod
    "wpa_cli",  # wpa_supplicant
]

is_wpa_cli_present = True


def check_required_tools():
    """Check if required tools are installed. Call this after arg parsing to allow -h/--help to work fast."""
    global is_wpa_cli_present
    logging.getLogger("check_required_tools")
    for tool in __tools:
        if shutil.which(tool) is None:
            if tool == "wpa_cli":
                # Only warn if wpa_supplicant is installed but wpa_cli is missing
                # If wpa_supplicant isn't installed, we don't need wpa_cli
                if shutil.which("wpa_supplicant") is not None:
                    print(
                        "\n[!] WARNING: wpa_cli not found but wpa_supplicant is installed.\n"
                        "    wpa_cli is used to stop wpa_supplicant on the interface.\n"
                        "    Please install wpa_cli (usually part of wpasupplicant package).\n"
                    )
                is_wpa_cli_present = False
                continue

            # For other critical tools, print and exit
            print(f"It looks like you do not have {tool} installed.")
            print("Please install using your distro's package manager.")

            # Write failure status before exiting
            from profiler.status import ProfilerState, StatusReason, write_status

            write_status(
                state=ProfilerState.FAILED,
                reason=StatusReason.MISSING_TOOLS,
                error=f"Required tool '{tool}' not found. Please install using your distro's package manager.",
            )
            sys.exit(signal.SIGABRT)


from .__version__ import __version__
from .constants import (
    CHANNELS,
    CONFIG_FILE,
    DEFAULT_PASSPHRASE,
    DEFAULT_SECURITY_MODE,
    LAST_PROFILE_TMP_FILE,
    SECURITY_MODES,
    SSID_TMP_FILE,
)

FILES_PATH = "/var/www/html/profiler"

# Group name for file permissions (webui runs as this user)
WLANPI_GROUP = "wlanpi"


def set_file_permissions(path: str, mode: int = 0o640, set_group: bool = True) -> bool:
    """
    Set file permissions and optionally change group ownership to wlanpi.

    This ensures files created by root (profiler service) can be read by
    the wlanpi user (webui service).

    Args:
        path: Path to the file
        mode: Permission mode (default: 0o640 = rw-r-----)
        set_group: If True, change group ownership to wlanpi

    Returns:
        True if successful, False if any operation failed
    """
    log = logging.getLogger(__name__)
    try:
        os.chmod(path, mode)

        if set_group and grp is not None:
            try:
                gid = grp.getgrnam(WLANPI_GROUP).gr_gid
                # -1 means don't change owner, only change group
                os.chown(path, -1, gid)
            except KeyError:
                # wlanpi group doesn't exist (e.g., development environment)
                log.debug(f"Group '{WLANPI_GROUP}' not found, skipping chown")
            except PermissionError:
                # Not running as root, can't change group
                log.debug(f"Cannot change group to '{WLANPI_GROUP}' (not root)")

        return True
    except OSError as e:
        log.warning(f"Failed to set permissions on {path}: {e}")
        return False


def set_directory_permissions(
    path: str, mode: int = 0o750, set_group: bool = True
) -> bool:
    """
    Set directory permissions and optionally change group ownership to wlanpi.

    Args:
        path: Path to the directory
        mode: Permission mode (default: 0o750 = rwxr-x---)
        set_group: If True, change group ownership to wlanpi

    Returns:
        True if successful, False if any operation failed
    """
    return set_file_permissions(path, mode, set_group)


def setup_logger(args, config=None) -> None:
    """Configure and set logging levels

    Priority order (highest to lowest):
    1. --debug command line flag
    2. PROFILER_DEBUG environment variable (for systemd drop-ins)
    3. debug option in config.ini [GENERAL] section
    """
    logging_level = logging.INFO

    # Check for debug flag from multiple sources (in priority order)
    if args.debug:
        logging_level = logging.DEBUG
    elif os.environ.get("PROFILER_DEBUG", "").lower() in ("1", "true", "yes"):
        logging_level = logging.DEBUG
        print("Debug logging enabled via PROFILER_DEBUG environment variable")
    elif config and config.get("GENERAL", {}).get("debug"):
        # Config value can be bool (from convert_configparser_to_dict) or string
        debug_value = config["GENERAL"]["debug"]
        if isinstance(debug_value, bool):
            is_debug = debug_value
        else:
            is_debug = str(debug_value).lower() in ("true", "yes", "1")

        if is_debug:
            logging_level = logging.DEBUG
            print("Debug logging enabled via config.ini")

    # Clear existing handlers to prevent duplicates when reconfiguring
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

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


def channel(value: str) -> int:
    """Check if channel is valid"""
    ch = int(value)
    if any(ch in band for band in CHANNELS.values()):
        return ch
    raise ValueError(f"{ch} is not a valid channel")


def ssid(ssid: str) -> str:
    """Check if SSID is valid (max 31 characters)"""
    if len(ssid) > 31:
        raise ValueError(f"SSID '{ssid}' exceeds 31 characters (got {len(ssid)})")
    return ssid


def passphrase(value: str) -> str:
    """Check if passphrase is valid (8-63 characters)"""
    if not 8 <= len(value) <= 63:
        raise ValueError(f"Passphrase must be 8-63 characters (got {len(value)})")
    return value


def is_valid_mac(mac: str) -> bool:
    """Check if a MAC address is valid (not corrupted).

    Filters out:
    - All zeros (00:00:00:00:00:00)
    - Broadcast (ff:ff:ff:ff:ff:ff)
    - Zero OUI (00:00:00:xx:xx:xx)
    - MACs with 5+ zero octets (likely corrupted, e.g., 00:00:00:00:00:40)

    Returns:
        True if MAC is valid, False otherwise
    """
    if not mac:
        return False

    mac_lower = mac.lower()

    # All zeros
    if mac_lower == "00:00:00:00:00:00":
        return False

    # Broadcast
    if mac_lower == "ff:ff:ff:ff:ff:ff":
        return False

    octets = mac_lower.split(":")
    if len(octets) != 6:
        return False

    # Zero OUI (first 3 octets all zeros)
    if octets[0] == "00" and octets[1] == "00" and octets[2] == "00":
        return False

    # 5+ zero octets (corruption pattern)
    zero_count = sum(1 for o in octets if o == "00")
    return zero_count < 5


def is_valid_ssid(ssid_str: str) -> bool:
    """Check if an SSID from a captured frame is valid (not corrupted).

    Filters out:
    - SSIDs longer than 32 bytes (802.11 max)
    - SSIDs with mostly non-printable characters (likely corrupted)

    Note: Empty SSIDs are valid (wildcard probes), so we allow them.

    Args:
        ssid_str: The decoded SSID string from a frame

    Returns:
        True if SSID appears valid, False if likely corrupted
    """
    # Empty SSID is valid (wildcard probe)
    if not ssid_str:
        return True

    # SSID max length is 32 bytes per 802.11 spec
    # Check byte length, not character count (UTF-8 can have multi-byte chars)
    try:
        ssid_bytes = ssid_str.encode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return False

    if len(ssid_bytes) > 32:
        return False

    # Count printable ASCII characters (0x20-0x7E)
    # Valid SSIDs should be mostly printable
    printable_count = sum(1 for c in ssid_str if 0x20 <= ord(c) <= 0x7E)

    # If less than 50% of characters are printable ASCII, likely corrupted
    # Exception: short SSIDs (1-2 chars) need all chars printable
    if len(ssid_str) <= 2:
        return printable_count == len(ssid_str)

    return printable_count >= len(ssid_str) * 0.5


def has_bad_fcs(frame) -> bool:
    """Check if a frame has a bad FCS (Frame Check Sequence).

    The FCS is a 4-byte CRC32 checksum at the end of 802.11 frames.
    A bad FCS indicates the frame was corrupted during transmission.

    Args:
        frame: A Scapy frame (should have Dot11 layer)

    Returns:
        True if the frame has FCS and it doesn't match the computed CRC32,
        False if no FCS present or if FCS is valid.
    """
    # Import here to avoid circular imports and allow module to work without scapy
    try:
        from scapy.layers.dot11 import Dot11FCS
    except ImportError:
        return False

    if not frame.haslayer(Dot11FCS):
        return False  # No FCS layer present, can't validate

    frame_fcs = frame.fcs

    # Calculate expected CRC32 of payload (excluding the 4-byte FCS)
    crc_bytes = struct.pack("I", zlib.crc32(bytes(frame.payload)[:-4]) & 0xFFFF_FFFF)
    expected_fcs = int.from_bytes(crc_bytes, byteorder="little")

    return frame_fcs != expected_fcs


def frequency(freq) -> int:
    """Check if the provided frequency is valid"""
    try:
        # make sure freq is an int
        freq = int(freq)
    except ValueError as err:
        raise ValueError(f"{freq} is not a number") from err

    freq_ranges = [(2412, 2484), (5180, 5905), (5955, 7115)]

    for band in freq_ranges:
        if band[0] <= freq <= band[1]:
            return freq

    raise ValueError(f"{freq} not found in these frequency ranges: {freq_ranges}")


def setup_parser() -> argparse.ArgumentParser:
    """Set default values and handle arg parser"""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="wlanpi-profiler is an 802.11 client capabilities profiler. If installed via package manager, read the manual with: man wlanpi-profiler",
    )

    # Add subcommands
    subparsers = parser.add_subparsers(dest="command", help="available commands")

    # 'test' subcommand for running hardware tests
    test_parser = subparsers.add_parser("test", help="run on-device hardware tests")
    test_parser.add_argument(
        "-v", "--verbose", action="store_true", help="verbose test output"
    )

    # For backward compatibility, if no subcommand is given, assume 'run' mode
    # This allows existing usage like "profiler -c 36 -i wlan0" to continue working
    parser.add_argument(
        "--pytest",
        dest="pytest",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )
    frequency_group = parser.add_mutually_exclusive_group()
    frequency_group.add_argument(
        "-c",
        dest="channel",
        type=channel,
        help="set the channel to broadcast on",
    )
    frequency_group.add_argument(
        "-f",
        dest="frequency",
        type=frequency,
        help="set the frequency to broadcast on",
    )
    parser.add_argument(
        "-i",
        dest="interface",
        help="set network interface for profiler",
    )
    ssid_group = parser.add_mutually_exclusive_group()
    ssid_group.add_argument("-s", dest="ssid", type=ssid, help="set profiler SSID name")
    parser.add_argument(
        "--passphrase",
        type=passphrase,
        help="set AP passphrase (8-63 chars, default: profiler)",
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
        action="append",
        type=Path,
        help="customize directories where analysis is saved (can be specified multiple times, default: /var/www/html/profiler and /root/.local/share/wlanpi-profiler)",
    )
    ssid_group.add_argument(
        "--hostname_ssid",
        dest="hostname_ssid",
        action="store_true",
        default=False,
        help="use the WLAN Pi's hostname as SSID name (default: %(default)s)",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="enable debug logging output",
    )
    parser.add_argument(
        "--expert",
        dest="expert",
        action="store_true",
        default=False,
        help="enable expert mode (includes hostapd debug output)",
    )
    parser.add_argument(
        "--no-interface-prep",
        "--noprep",  # Keep old name for backward compatibility
        dest="no_interface_prep",
        action="store_true",
        default=False,
        help="disable interface preparation (profiler will not configure interface to monitor mode)",
    )
    ssid_group.add_argument(
        "--listen-only",
        "--noAP",
        dest="listen_only",
        action="store_true",
        default=False,
        help="listen-only mode (passive Rx, no AP)",
    )
    # Note: --11r and --no11r are both hidden (deprecated in favor of --security-mode)
    # Don't use mutually_exclusive_group when both are SUPPRESS - causes argparse formatting issues
    parser.add_argument(
        "--11r",
        dest="ft_enabled",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,  # Hidden: use --security-mode instead
    )
    parser.add_argument(
        "--no11r",
        dest="ft_disabled",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,  # DEPRECATED: Hidden from help, use --security-mode instead
    )
    parser.add_argument(
        "--security-mode",
        dest="security_mode",
        type=str,
        choices=["wpa2", "ft-wpa2", "wpa3-mixed", "ft-wpa3-mixed"],
        help="security mode for AP: wpa2, ft-wpa2, wpa3-mixed, ft-wpa3-mixed (default: ft-wpa3-mixed). Note: 802.11be auto-disabled for wpa2/ft-wpa2 (Wi-Fi 7 requires WPA3)",
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
    dot11be_group = parser.add_mutually_exclusive_group()
    dot11be_group.add_argument(
        "--11be",
        dest="be_enabled",
        action="store_true",
        default=False,
        help="enable 802.11be Extremely High Throughput (Wi-Fi 7) reporting (override auto-disable for WPA2 modes)",
    )
    dot11be_group.add_argument(
        "--no11be",
        dest="be_disabled",
        action="store_true",
        default=False,
        help="turn off 802.11be Extremely High Throughput (EHT) reporting",
    )
    parser.add_argument(
        "--noprofilertlv",
        dest="profiler_tlv_disabled",
        action="store_true",
        default=False,
        help="disable generation of Profiler specific vendor IE",
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
        "--pcap",
        metavar="PCAP",
        dest="pcap_analysis",
        help="analyze association request frames from pcap",
    )
    parser.add_argument(
        "--no_bpf_filters",
        dest="no_bpf_filters",
        action="store_true",
        default=False,
        help="removes BPF filters from sniffer() but may impact profiler performance",
    )
    parser.add_argument(
        "--list_interfaces",
        dest="list_interfaces",
        action="store_true",
        default=False,
        help="print out a list of interfaces with an 80211 stack",
    )

    # Hostapd AP mode options
    ap_mode_group = parser.add_mutually_exclusive_group()
    ap_mode_group.add_argument(
        "--ap-mode",
        dest="ap_mode",
        action="store_true",
        default=False,
        help="use hostapd AP mode for fast discovery (requires monitor VIF support)",
    )
    ap_mode_group.add_argument(
        "--fakeap",
        dest="fakeap",
        action="store_true",
        default=False,
        help="use legacy FakeAP mode (Scapy/monitor-only, slower discovery but works with more adapters) (default behavior for bullseye branch)",
    )
    parser.add_argument(
        "--hostapd-config",
        metavar="FILE",
        dest="hostapd_config",
        help=argparse.SUPPRESS,
        # help="path to custom hostapd.conf (expert mode, requires --ap-mode)",
    )

    parser.add_argument("--version", "-V", action="version", version=f"{__version__}")
    return parser


def files_cleanup(directory: str, acknowledged: bool) -> None:
    """Purge files recursively"""
    log = logging.getLogger(inspect.stack()[0][3])

    result = list(Path(directory).rglob("*"))
    log.warning("Delete the following files: %s", ", ".join([str(x) for x in result]))

    if acknowledged:
        pass
    elif input("Are you sure? (y/n): ").lower().strip()[:1] != "y":
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


@dataclass
class NetworkInterface:
    """Class for our Network Interface object"""

    ifname: str = ""
    operstate: str = ""
    mac: str = ""


def get_data_from_iproute2(intf) -> NetworkInterface:
    """Get and parse output from iproute2 for a given interface"""
    # Get json output from `ip` command
    result = run_command(["ip", "-json", "address"])
    data = json.loads(result)
    interface_data = {}
    for item in data:
        name = item["ifname"]
        interface_data[name] = item
    # Build dataclass for storage and easier test assertion
    iface = NetworkInterface()
    if intf in interface_data:
        iface.operstate = interface_data[intf]["operstate"]
        iface.ifname = interface_data[intf]["ifname"]
        iface.mac = interface_data[intf]["address"].replace(":", "")
    return iface


def get_iface_mac(iface: str):
    """Check iproute2 output for <iface> and return a MAC with a format like 000000111111"""
    iface_data = get_data_from_iproute2(iface)
    iface_mac = None
    if iface_data and iface_data.mac:
        iface_mac = iface_data.mac.replace(":", "")
    if iface_mac:
        return iface_mac
    return ""


def setup_config(args) -> tuple[Optional[dict], Optional[str]]:
    """Create the configuration (SSID, channel, interface, etc) for the Profiler.

    Returns:
        tuple[Optional[dict], Optional[str]]: (config, error_message)
            - (config_dict, None) on success
            - (None, "error message") on failure
    """
    log = logging.getLogger(inspect.stack()[0][3])

    # load in config (a: from default location "/etc/wlanpi-profiler/config.ini" or b: from provided)
    if os.path.isfile(args.config):
        try:
            parser = load_config(args.config)

            # we want to work with a dict whether we have config.ini or not
            config = convert_configparser_to_dict(parser)
        except configparser.MissingSectionHeaderError:
            log.error("config file appears to be corrupt")
            config = {}
    else:
        log.warning("can not find config at %s", args.config)
        config = {}

    if "GENERAL" not in config:
        config["GENERAL"] = {}

    if "channel" not in config["GENERAL"]:
        config["GENERAL"]["channel"] = 36

    if "ssid" not in config["GENERAL"] or config["GENERAL"].get("ssid", "") == "":
        last_3_of_eth0_mac = f"{get_iface_mac('eth0')[-3:]}".strip()
        config["GENERAL"]["ssid"] = f"Profiler {last_3_of_eth0_mac}"

    if "interface" not in config["GENERAL"]:
        config["GENERAL"]["interface"] = "wlan0"

    # handle special config.ini settings
    if config["GENERAL"].get("hostname_ssid"):
        config["GENERAL"]["ssid"] = socket.gethostname()

    # handle args
    #  - args passed in take precedent over config.ini values
    #  - did user pass in options that over-ride defaults?
    if args.channel:
        config["GENERAL"]["channel"] = args.channel
    if args.frequency:
        config["GENERAL"]["frequency"] = args.frequency
        # user gave us freq, do not set value from config.ini
        config["GENERAL"]["channel"] = 0
    else:
        config["GENERAL"]["frequency"] = 0
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

    if not config["GENERAL"].get("security_mode"):
        # Check for deprecated ft_disabled first
        if config["GENERAL"].get("ft_disabled"):
            config["GENERAL"]["security_mode"] = "wpa3-mixed"
            log.warning(
                "ft_disabled=True is deprecated. Mapped to security_mode='wpa3-mixed'. "
                "Update config.ini to use security_mode instead."
            )
        else:
            config["GENERAL"]["security_mode"] = DEFAULT_SECURITY_MODE

    # CLI override
    if args.security_mode:
        config["GENERAL"]["security_mode"] = args.security_mode

    # Backward compat: --no11r CLI flag strips FT from security mode
    if args.ft_disabled:
        log.warning(
            "DEPRECATED: --no11r flag is deprecated. "
            "Use --security-mode to control 802.11r (FT) support instead. "
            "The --no11r flag will be removed in a future version."
        )
        current_mode = config["GENERAL"]["security_mode"]
        if current_mode == "ft-wpa3-mixed":
            config["GENERAL"]["security_mode"] = "wpa3-mixed"
            log.info("--no11r: Changed security_mode from ft-wpa3-mixed → wpa3-mixed")
        elif current_mode == "ft-wpa2":
            config["GENERAL"]["security_mode"] = "wpa2"
            log.info("--no11r: Changed security_mode from ft-wpa2 → wpa2")

    # Validate final security_mode
    if config["GENERAL"]["security_mode"] not in SECURITY_MODES:
        error_msg = (
            f"Invalid security_mode: {config['GENERAL']['security_mode']}. "
            f"Must be one of: {', '.join(SECURITY_MODES.keys())}"
        )
        log.error(error_msg)
        return None, error_msg

    # Auto-disable 802.11be for WPA2-only modes or when 11ax is disabled
    # (Wi-Fi 7 requires WPA3 and Wi-Fi 6 per IEEE spec)
    # Precedence: CLI args > config.ini > auto-defaults
    security_mode = config["GENERAL"]["security_mode"]
    wpa2_only_modes = ["wpa2", "ft-wpa2"]

    # Check if user explicitly configured be_disabled in config.ini or via CLI
    config_has_be_setting = "be_disabled" in config["GENERAL"]
    cli_has_be_setting = args.be_enabled or args.be_disabled

    # Check if 11ax will be disabled
    he_will_be_disabled = (
        config["GENERAL"].get("he_disabled", False) or args.he_disabled
    )

    # Auto-disable 11be if: (WPA2-only mode OR 11ax disabled) AND user hasn't overridden
    should_auto_disable_be = False
    auto_disable_reason = None

    if not config_has_be_setting and not cli_has_be_setting:
        if security_mode in wpa2_only_modes:
            should_auto_disable_be = True
            auto_disable_reason = f"security_mode '{security_mode}' uses WPA2-only (IEEE 802.11be requires WPA3)"
        elif he_will_be_disabled:
            should_auto_disable_be = True
            auto_disable_reason = (
                "802.11ax is disabled (IEEE 802.11be requires 802.11ax)"
            )

    if should_auto_disable_be:
        config["GENERAL"]["be_disabled"] = True
        log.warning(
            f"Auto-disabling 802.11be (Wi-Fi 7): {auto_disable_reason}. "
            f"Override with --11be flag or 'be_disabled: false' in config.ini for testing (non-standard)."
        )

    # User explicit overrides (CLI takes highest precedence)
    if args.he_enabled:
        config["GENERAL"]["he_disabled"] = False
    if args.he_disabled:
        config["GENERAL"]["he_disabled"] = args.he_disabled
    if args.be_enabled:
        config["GENERAL"]["be_disabled"] = False
        # Warn if enabling 11be with WPA2-only or when 11ax is disabled
        he_is_disabled = config["GENERAL"].get("he_disabled", False)
        if security_mode in wpa2_only_modes:
            log.warning(
                f"Enabling 802.11be with security_mode '{security_mode}' (WPA2-only). "
                f"This violates IEEE 802.11be spec which requires WPA3 or WPA3-transition. "
                f"Use for testing only."
            )
        elif he_is_disabled:
            log.warning(
                "Enabling 802.11be with 802.11ax disabled. "
                "This violates IEEE 802.11be spec which requires 802.11ax. "
                "Use for testing only."
            )
    if args.be_disabled:
        config["GENERAL"]["be_disabled"] = args.be_disabled

    # Ensure be_disabled has a default value if not set by auto-disable or user
    if "be_disabled" not in config["GENERAL"]:
        config["GENERAL"]["be_disabled"] = (
            False  # Default: 11be enabled for non-WPA2 modes
        )

    if args.profiler_tlv_disabled:
        config["GENERAL"]["profiler_tlv_disabled"] = args.profiler_tlv_disabled
    if args.listen_only:
        config["GENERAL"]["listen_only"] = args.listen_only
    if args.pcap_analysis:
        config["GENERAL"]["pcap_analysis"] = args.pcap_analysis
    if args.debug:
        config["GENERAL"]["debug"] = args.debug
    if args.expert:
        config["GENERAL"]["expert"] = args.expert
    if args.files_path:
        config["GENERAL"]["files_path"] = args.files_path
    elif "files_path" not in config["GENERAL"]:
        # Only use default if not specified in config.ini
        config["GENERAL"]["files_path"] = FILES_PATH

    # Handle passphrase (priority: CLI > config.ini > default)
    if args.passphrase:
        config["GENERAL"]["passphrase"] = args.passphrase
    elif "passphrase" not in config["GENERAL"]:
        # Only use default if not specified in config.ini
        config["GENERAL"]["passphrase"] = DEFAULT_PASSPHRASE

    # Handle hostapd mode options
    # Default to fakeap unless explicitly requesting ap_mode
    if args.ap_mode:
        config["GENERAL"]["ap_mode"] = True
        config["GENERAL"]["fakeap"] = False
    else:
        # Default: use fakeap
        config["GENERAL"]["fakeap"] = True
        config["GENERAL"]["ap_mode"] = False

    if args.hostapd_config:
        config["GENERAL"]["hostapd_config"] = args.hostapd_config

    # Validate hostapd mode options (this should never trigger now due to mutually_exclusive_group)
    if args.ap_mode and args.fakeap:
        error_msg = "Cannot specify both --ap-mode and --fakeap"
        log.error(error_msg)
        return None, error_msg

    if args.hostapd_config and args.fakeap:
        error_msg = "--hostapd-config cannot be used with --fakeap"
        log.error(error_msg)
        return None, error_msg

    # ensure channel 1 is an integer and not a bool
    try:
        ch = config.get("GENERAL").get("channel")
        if ch:
            ch = int(ch)
        config["GENERAL"]["channel"] = ch
    except KeyError:
        log.warning("config.ini does not have channel defined")

    return config, None


def strtobool(val):
    """Convert a string representation of truth to true (1) or false (0).
    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return 1
    elif val in ("n", "no", "f", "false", "off", "0"):
        return 0
    else:
        raise ValueError(f"invalid truth value {val}")


def convert_configparser_to_dict(config: configparser.ConfigParser) -> dict:
    """
    Convert ConfigParser object to dictionary.

    The resulting dictionary has sections as keys which point to a dict of the
    section options as key => value pairs.

    If there is a string representation of truth, it is converted from str to bool.
    """
    _dict: dict[str, Any] = {}
    for section in config.sections():
        _dict[section] = {}
        for key, _value in config.items(section):
            with contextlib.suppress(ValueError):
                _value = bool(strtobool(_value))  # type: ignore
            _dict[section][key] = _value
    return _dict


def load_config(config_file: str) -> configparser.ConfigParser:
    """Load in config from external file"""
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def validate(config) -> tuple[bool, Optional[str]]:
    """Validate minimum config to run is OK.

    Returns:
        tuple[bool, Optional[str]]: (success, error_message)
            - (True, None) on success
            - (False, "error message") on failure
    """
    log = logging.getLogger(inspect.stack()[0][3])

    missing_ok, missing_error = check_config_missing(config)
    if not missing_ok:
        return False, missing_error

    try:
        _ssid = config.get("GENERAL").get("ssid")
        if _ssid:
            ssid(_ssid)

        # Validate passphrase - warn in listen_only mode, fail in AP modes
        _passphrase = config.get("GENERAL").get("passphrase")
        if _passphrase:
            try:
                passphrase(_passphrase)
            except ValueError as e:
                if config.get("GENERAL").get("listen_only"):
                    log.warning(
                        f"Passphrase validation: {e} (ignored in listen-only mode)"
                    )
                else:
                    raise

        ch = config.get("GENERAL").get("channel")
        if ch:
            channel(ch)

        freq = config.get("GENERAL").get("frequency")
        if freq:
            frequency(freq)

        # Validate boolean config options
        # These should be bool after convert_configparser_to_dict, but if strtobool
        # failed (suppressed), they'll still be strings
        bool_options = [
            "he_disabled",
            "be_disabled",
            "ft_disabled",
            "listen_only",
            "debug",
            "expert",
            "hostname_ssid",
            "profiler_tlv_disabled",
        ]
        general = config.get("GENERAL", {})
        for opt in bool_options:
            val = general.get(opt)
            if val is not None and not isinstance(val, bool):
                raise ValueError(
                    f"'{opt}' must be a boolean (true/false/yes/no), got '{val}'"
                )

        # Validate hostapd mode
        if config.get("GENERAL").get("ap_mode"):
            from profiler.constants import HOSTAPD_BINARY

            # Check hostapd binary exists
            if not os.path.exists(HOSTAPD_BINARY):
                error_msg = f"Hostapd binary not found at {HOSTAPD_BINARY}"
                log.error(error_msg)
                log.error(
                    "This installation may be corrupted. Reinstall wlanpi-profiler."
                )
                log.error(
                    "Alternatively, use --fakeap mode (legacy injection-based AP)"
                )
                return False, error_msg

            # Check for 6 GHz channel attempts
            ch = config.get("GENERAL").get("channel")
            freq = config.get("GENERAL").get("frequency")

            if freq and freq >= 5955:  # 6 GHz band
                error_msg = (
                    f"Frequency {freq} MHz is in 6 GHz band (not currently supported)"
                )
                log.error(error_msg)
                log.error(
                    "6 GHz requires AFC (Automatic Frequency Coordination) not yet available"
                )
                log.error(
                    "Try a 5 GHz channel (e.g., 36, 40, 44) or 2.4 GHz channel (1-11)"
                )
                return False, error_msg

            if ch and ch >= 1 and ch <= 233:
                # Check if it's a 6 GHz channel (not in 2G or 5G lists)
                from profiler.constants import CHANNELS

                if ch not in CHANNELS["2G"] and ch not in CHANNELS["5G"]:
                    error_msg = (
                        f"Channel {ch} is in 6 GHz band (not currently supported)"
                    )
                    log.error(error_msg)
                    log.error(
                        "6 GHz requires AFC (Automatic Frequency Coordination) not yet available"
                    )
                    log.error(
                        "Try a 5 GHz channel (e.g., 36, 40, 44) or 2.4 GHz channel (1-11)"
                    )
                    return False, error_msg

        verify_reporting_directories(config)
    except ValueError as e:
        # Extract error message from ValueError args
        error_msg = str(e.args[0]) if e.args else str(e)
        log.error("%s", error_msg)
        return False, error_msg

    return True, None


def is_randomized(mac) -> bool:
    """Check if MAC Address <format>:'00:00:00:00:00:00' is locally assigned"""
    return any(local == mac.lower()[1] for local in ["2", "6", "a", "e"])


def check_config_missing(config: dict) -> tuple[bool, Optional[str]]:
    """Check that the minimal config items exist.

    Returns:
        tuple[bool, Optional[str]]: (success, error_message)
            - (True, None) on success
            - (False, "error message") on failure
    """
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

    except KeyError as e:
        error_msg = str(e.args[0]) if e.args else str(e)
        log.error("%s", error_msg)
        return False, error_msg
    return True, None


def run_command(cmd: list, suppress_output=False) -> str:
    """Run a single CLI command with subprocess and return stdout or stderr response"""
    cp = subprocess.run(
        cmd,
        encoding="utf-8",
        shell=False,
        check=False,
        capture_output=True,
    )

    if not suppress_output:
        if cp.stdout:
            return cp.stdout
        if cp.stderr:
            return cp.stderr

    return "completed process return code is non-zero with no stdout or stderr"


def update_manuf2() -> bool:
    """manuf2 wrapper to update manuf2 OUI flat file from Internet"""
    log = logging.getLogger(inspect.stack()[0][3])

    if manuf2 is None:
        print("manuf2 module not found. Install with: pip install manuf2")
        return False

    try:
        flat_file = os.path.join(manuf2.__path__[0], "manuf")

        # Security: Only allow manuf2 from trusted system paths (prevent privilege escalation)
        ALLOWED_MANUF2_PATHS = [
            "/usr/bin/manuf2",
            "/usr/local/bin/manuf2",
            "/opt/wlanpi-profiler/bin/manuf2",
        ]

        manuf2_location = None
        for path in ALLOWED_MANUF2_PATHS:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                manuf2_location = path
                log.debug("Found manuf2 at trusted path: %s", path)
                break

        if manuf2_location is None:
            log.error("manuf2 not found in trusted paths: %s", ALLOWED_MANUF2_PATHS)
            print("Error: manuf2 not found in trusted system paths")
            return False

        log.info("OUI database is located at %s", flat_file)
        log.info("manuf2 is located at %s", manuf2_location)
        log.info(
            "manuf2 file last modified at: %s",
            ctime(os.path.getmtime(flat_file)),
        )
        log.info("running 'sudo manuf2 --update'")
        out = run_command(["sudo", manuf2_location, "--update"])
        log.info("%s", str(out))
        if "URLError" not in out:
            log.info(
                "manuf2 file last modified at: %s",
                ctime(os.path.getmtime(flat_file)),
            )
    except OSError as e:
        log.debug("Failed to update manuf2 OUI database: %s", e)
        print(f"Failed to update manuf2 OUI database: {e}")
        return False
    return True


def create_user_xdg_data_dir(app_name):
    """Create XDG data directory with proper user ownership when running as root (Linux only)"""
    if pwd is None:
        # Not on Unix/Linux, skip this
        return None

    actual_user = os.environ.get("SUDO_USER", pwd.getpwuid(os.getuid()).pw_name)
    user_info = pwd.getpwnam(actual_user)

    user_home = Path(user_info.pw_dir)
    xdg_data_home = Path(os.environ.get("XDG_DATA_HOME", user_home / ".local/share"))
    app_dir = xdg_data_home / app_name

    app_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

    for path in [user_home / ".local", xdg_data_home, app_dir]:
        if path.exists():
            os.chown(path, user_info.pw_uid, user_info.pw_gid)

    return app_dir


def get_app_data_paths(args=None, config=None) -> list[Path]:
    """
    Returns writable application data directory paths based on the platform.
    Tests each candidate path for write permission before using it.
    Falls back to temp directory if no other paths are writable.

    Priority order for path selection:
    1. Command-line argument (--files_path)
    2. Config file setting (files_path in config.ini)
    3. Platform-specific defaults

    For cross-platform support:
    - Windows: %USERPROFILE%/AppData/Local/wlanpi-profiler or ~/.wlanpi-profiler
    - macOS: ~/Library/Application Support/wlanpi-profiler or ~/.wlanpi-profiler
    - Linux: /var/www/html/profiler, $XDG_DATA_HOME/wlanpi-profiler, or ~/.local/share/wlanpi-profiler

    Returns a list of Path objects for dual-location saving.
    """
    app_name = "wlanpi-profiler"
    system = platform.system()
    candidate_paths = []
    log = logging.getLogger(inspect.stack()[0][3])

    # Priority 1: Command-line argument (highest priority)
    has_explicit_path = False
    path_source = None
    if args and hasattr(args, "files_path") and args.files_path:
        if isinstance(args.files_path, list):
            candidate_paths.extend(
                [Path(p) if not isinstance(p, Path) else p for p in args.files_path]
            )
        else:
            candidate_paths.append(Path(args.files_path))
        has_explicit_path = True
        path_source = "command line"
    # Priority 2: Config file setting
    elif config and config.get("GENERAL", {}).get("files_path"):
        config_path = config["GENERAL"]["files_path"]
        candidate_paths.append(Path(config_path))
        has_explicit_path = True
        path_source = "config file"

    # Add platform-specific paths as fallbacks (only if no explicit path given)
    if not has_explicit_path:
        if system == "Windows":
            userprofile = os.environ.get("USERPROFILE")
            if userprofile:
                candidate_paths.append(
                    Path(userprofile) / "AppData" / "Local" / app_name
                )
            candidate_paths.append(Path.home() / f".{app_name}")
        elif system == "Darwin":
            candidate_paths.append(
                Path.home() / "Library" / "Application Support" / app_name
            )
            candidate_paths.append(Path.home() / f".{app_name}")
        elif system == "Linux":
            if os.path.exists("/var/www/html"):
                candidate_paths.append(Path("/var/www/html/profiler"))

            xdg_data_home = os.environ.get("XDG_DATA_HOME")
            if xdg_data_home:
                try:
                    create_user_xdg_data_dir(app_name)
                    candidate_paths.append(Path(xdg_data_home) / app_name)
                except (KeyError, PermissionError):
                    pass

            candidate_paths.append(Path.home() / ".local" / "share" / app_name)

        if not candidate_paths:
            candidate_paths.append(Path.home() / f".{app_name}")

    # Test each path for write permission
    writable_paths = []
    for path in candidate_paths:
        try:
            os.makedirs(path, exist_ok=True)

            test_file = path / ".profiler_test_write"
            try:
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
                if path_source:
                    log.info("Using files_path from %s: %s", path_source, path)
                else:
                    log.info("Using application directory: %s", path)
                writable_paths.append(path)
            except (OSError, PermissionError):
                continue
        except (OSError, PermissionError) as e:
            log.debug("Cannot use %s: %s", path, str(e))
            continue

    # Fall back to temp directory if nothing else works
    if not writable_paths:
        temp_dir = Path(tempfile.gettempdir()) / app_name
        try:
            os.makedirs(temp_dir, exist_ok=True)
            log.info("Falling back to temporary data directory: %s", temp_dir)
            writable_paths.append(temp_dir)
        except Exception as err:
            log.exception("Failed to create temporary data directory")
            raise RuntimeError(
                f"Cannot find a writable data directory for {app_name}"
            ) from err

    return writable_paths


def verify_reporting_directories(config: dict) -> None:
    """Check reporting directories exist and create if not"""
    log = logging.getLogger(inspect.stack()[0][3])

    if "GENERAL" in config:
        files_paths = config["GENERAL"].get("files_path")

        # Support both single path and list of paths
        if not isinstance(files_paths, list):
            files_paths = [files_paths]

        for files_path in files_paths:
            # Convert to string if it's a Path object
            files_path = str(files_path)

            try:
                if not os.path.isdir(files_path):
                    os.makedirs(files_path, exist_ok=True)
                    set_directory_permissions(files_path)
                    log.debug("Created directory: %s", files_path)
                else:
                    # Ensure existing directory has correct permissions
                    set_directory_permissions(files_path)
                    log.debug("Verified directory structure: %s", files_path)

                clients_dir = os.path.join(files_path, "clients")
                if not os.path.isdir(clients_dir):
                    os.makedirs(clients_dir, exist_ok=True)
                    set_directory_permissions(clients_dir)
                    log.debug("Created and configured directory: %s", clients_dir)
                else:
                    set_directory_permissions(clients_dir)

                reports_dir = os.path.join(files_path, "reports")
                if not os.path.isdir(reports_dir):
                    os.makedirs(reports_dir, exist_ok=True)
                    set_directory_permissions(reports_dir)
                    log.debug("Created and configured directory: %s", reports_dir)
                else:
                    set_directory_permissions(reports_dir)
            except (OSError, PermissionError) as e:
                log.warning(f"Cannot create directory {files_path}: {e}")
                # Continue to try other paths in the list


def get_frequency_bytes(channel: int) -> bytes:
    """Take a channel number, converts it to a frequency, and finally to bytes"""
    if channel == 14:
        freq = 2484
    elif 1 <= channel < 14:
        freq = 2407 + (channel * 5)
    elif channel > 14:
        freq = 5000 + (channel * 5)
    else:
        # Invalid channel (0 or negative)
        raise ValueError(f"Invalid channel number: {channel}")

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
                    wlanpi_version = "{}".format(
                        line.split("=")[1].replace('"', "").replace("'", "").strip()
                    )
    except OSError:
        pass
    return wlanpi_version


def get_processor_name() -> str:
    """
    Get processor name with fallback to /proc/cpuinfo parsing.

    platform.processor() returns empty string on many ARM Linux systems,
    so we parse /proc/cpuinfo to get the actual processor model.
    """
    import platform

    # Try platform.processor() first (works on some x86 systems)
    proc = platform.processor()
    if proc:
        return proc

    # Fallback: parse /proc/cpuinfo for Linux systems
    try:
        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read()

        # x86/x64: look for "model name"
        # ARM: look for "Hardware" field
        for line in cpuinfo.split("\n"):
            if "model name" in line.lower():
                return line.split(":", 1)[1].strip()
            if line.startswith("Hardware"):
                return line.split(":", 1)[1].strip()

        # ARM fallback: decode CPU part number to known ARM processor names
        cpu_part = None
        for line in cpuinfo.split("\n"):
            if line.startswith("CPU part"):
                cpu_part = line.split(":", 1)[1].strip()
                break

        if cpu_part:
            # Extracted subset of common ARM Cortex CPU part numbers (https://github.com/util-linux/util-linux/blob/master/sys-utils/lscpu-arm.c)
            arm_cpus = {
                "0xd03": "Cortex-A53",
                "0xd04": "Cortex-A35",
                "0xd05": "Cortex-A55",
                "0xd07": "Cortex-A57",
                "0xd08": "Cortex-A72",
                "0xd09": "Cortex-A73",
                "0xd0a": "Cortex-A75",
                "0xd0b": "Cortex-A76",
                "0xd0d": "Cortex-A77",
                "0xd0e": "Cortex-A76AE",
                "0xd41": "Cortex-A78",
                "0xd44": "Cortex-X1",
                "0xd46": "Cortex-A510",
                "0xd47": "Cortex-A710",
                "0xd48": "Cortex-X2",
                "0xd4b": "Cortex-A78AE",
                "0xd4c": "Cortex-X1C",
                "0xd4d": "Cortex-A715",
                "0xd4e": "Cortex-X3",
            }
            return arm_cpus.get(cpu_part, f"ARM CPU (part {cpu_part})")

    except (FileNotFoundError, PermissionError, OSError):
        pass

    # If all else fails, return empty string (matches platform.processor() behavior)
    return ""


def update_last_profile_record(mac: str):
    """Update Last Profile record on local filesystem"""
    log = logging.getLogger(inspect.stack()[0][3])

    # Write to legacy file (backward compatibility)
    # Skip if we don't have permission (e.g., running --pcap without root)
    try:
        with open(LAST_PROFILE_TMP_FILE, "w") as _file:
            _file.write(mac)
            log.debug("updated %s record with: %s", LAST_PROFILE_TMP_FILE, mac)
        set_file_permissions(LAST_PROFILE_TMP_FILE)
    except PermissionError:
        log.debug("skipping %s update (no permission)", LAST_PROFILE_TMP_FILE)

    # Also update info file (skip if no permission)
    from profiler.status import update_last_profile_in_info

    try:
        update_last_profile_in_info(mac)
    except PermissionError:
        log.debug("skipping info file update (no permission)")


def update_ssid_record(ssid: str):
    """Update SSID record on local filesystem"""
    log = logging.getLogger(inspect.stack()[0][3])

    with open(SSID_TMP_FILE, "w") as _file:
        _file.write(ssid)
        log.debug("updated %s record with: %s", SSID_TMP_FILE, ssid)
    set_file_permissions(SSID_TMP_FILE)


def flag_last_object(seq):
    """Treat the last object in an iterable differently.

    Yields (item, is_last) tuples where is_last is True for the final item.
    Handles empty sequences gracefully by yielding nothing.
    """
    seq = iter(seq)  # ensure seq is an iterator
    try:
        _a = next(seq)
    except StopIteration:
        return  # Empty sequence - nothing to yield
    for _b in seq:
        yield _a, False
        _a = _b
    yield _a, True


def generate_run_message(config: dict) -> None:
    """Create message to display to users screen"""
    interface = config["GENERAL"]["interface"]
    ap_mode = config["GENERAL"].get("ap_mode", False)
    listen_only = config["GENERAL"].get("listen_only", False)
    channel = config["GENERAL"]["channel"]
    frequency = config["GENERAL"]["frequency"]

    # Check listen_only FIRST - it takes priority over ap_mode
    # (ap_mode=True is the default, but --listen-only should override)
    if listen_only and not ap_mode:
        # True listen-only mode (no AP, just passive sniffing)
        out = []
        out.append(
            f"Starting profiler in listen-only mode on {interface} (channel {channel} / {frequency} MHz)"
        )
        out.append(" ")
        out.append("Getting started:")
        out.append(
            f" - Connect your client to any AP broadcasting on channel {channel}"
        )
        out.append(
            " - The profiler will capture association requests from nearby clients"
        )
        out.append(" - Reported capabilities may vary based on AP configuration")
        out.append(" - Results are saved locally and printed to the console")
        header_len = len(max(out, key=len))

        print(f"\n{'~' * header_len}")
        for line in out:
            print(line)
        print(f"{'~' * header_len}\n")
    elif ap_mode:
        from profiler.constants import SECURITY_MODES

        out = []
        ssid = config["GENERAL"]["ssid"]
        security_mode = config["GENERAL"].get("security_mode", "unknown")
        wpa_key_mgmt = SECURITY_MODES.get(security_mode, "unknown")
        ft_enabled = "FT-" in wpa_key_mgmt
        wpa3_enabled = "SAE" in wpa_key_mgmt
        he_disabled = config["GENERAL"].get("he_disabled", False)
        be_disabled = config["GENERAL"].get("be_disabled", False)

        out.append(
            f"Starting hostapd AP using {interface} on channel {channel} ({frequency})"
        )
        out.append(" ")
        out.append("Getting started:")
        out.append(f" - Associate your Wi-Fi client to SSID: {ssid}")
        out.append(f" - Passphrase: {config['GENERAL']['passphrase']}")
        out.append(f" - AP BSSID: {config['GENERAL']['mac']}")
        out.append(" - Results are saved locally and printed on the shell")
        out.append(" ")
        out.append("Security Configuration:")
        out.append(f"  Mode: {security_mode}")
        out.append(f"    WPA Key Management: {wpa_key_mgmt}")
        out.append("    WPA2: enabled")
        out.append(f"    WPA3: {'enabled' if wpa3_enabled else 'disabled'}")
        out.append(f"    802.11r (FT): {'enabled' if ft_enabled else 'disabled'}")
        out.append(" ")
        out.append("PHY Features:")
        out.append(f"  802.11ax (Wi-Fi 6): {'disabled' if he_disabled else 'enabled'}")
        out.append(f"  802.11be (Wi-Fi 7): {'disabled' if be_disabled else 'enabled'}")

        header_len = len(max(out, key=len))
        print(f"\n{'~' * header_len}")
        for line in out:
            print(line)
        print(f"{'~' * header_len}\n")
    else:
        # Legacy fakeAP mode
        from profiler.constants import SECURITY_MODES

        out = []
        ssid = config["GENERAL"]["ssid"]
        security_mode = config["GENERAL"].get("security_mode", "unknown")
        wpa_key_mgmt = SECURITY_MODES.get(security_mode, "unknown")
        ft_enabled = "FT-" in wpa_key_mgmt
        wpa3_enabled = "SAE" in wpa_key_mgmt
        he_disabled = config["GENERAL"].get("he_disabled", False)
        be_disabled = config["GENERAL"].get("be_disabled", False)

        out.append(
            f"Starting a fake AP using {interface} on channel {channel} ({frequency})"
        )
        out.append(" ")
        out.append("Getting started:")
        out.append(f" - Associate your Wi-Fi client to SSID: {ssid}")
        out.append(" - Enter any random password to connect")
        out.append(" - Authentication will fail, which is OK")
        out.append(
            f" - We will receive association request to {config['GENERAL']['mac']}"
        )
        out.append(" - Results are then saved locally and printed on the shell")
        out.append(" ")
        out.append("Security Configuration:")
        out.append(
            f"  Mode: {security_mode} | WPA2: yes | WPA3: {'yes' if wpa3_enabled else 'no'} | FT: {'yes' if ft_enabled else 'no'}"
        )
        out.append(
            f"  PHY: Wi-Fi 6: {'no' if he_disabled else 'yes'} | Wi-Fi 7: {'no' if be_disabled else 'yes'}"
        )

        header_len = len(max(out, key=len))

        print(f"\n{'~' * header_len}")
        for line in out:
            print(line)
        print(f"{'~' * header_len}\n")


@dataclass
class Capability:
    """Define custom fields for reporting"""

    name: str = ""
    value: Union[str, int] = ""
    db_key: str = ""
    db_value: Union[int, str, list[str]] = 0


def get_bit(byteval, index) -> bool:
    """Retrieve bit value from byte at provided index"""
    return (byteval & (1 << index)) != 0


def log_security_configuration(config: dict, log: logging.Logger) -> None:
    """
    Log final security configuration summary.

    Called after AP/FakeAP starts successfully or before listen-only mode begins.

    Args:
        config: Profiler configuration dict
        log: Logger instance
    """

    security_mode = config["GENERAL"].get("security_mode", "unknown")
    wpa_key_mgmt = SECURITY_MODES.get(security_mode, "unknown")

    # Determine feature states
    ft_enabled = "FT-" in wpa_key_mgmt
    wpa3_enabled = "SAE" in wpa_key_mgmt
    he_disabled = config["GENERAL"].get("he_disabled", False)
    be_disabled = config["GENERAL"].get("be_disabled", False)

    log.info("=" * 70)
    log.info("Security Configuration Summary")
    log.info("  Security Mode: %s", security_mode)
    log.info("    WPA Key Management: %s", wpa_key_mgmt)
    log.info("    WPA2: enabled")
    log.info("    WPA3: %s", "enabled" if wpa3_enabled else "disabled")
    log.info("    802.11r (FT): %s", "enabled" if ft_enabled else "disabled")
    log.info("  PHY Features")
    log.info("    802.11ax (Wi-Fi 6): %s", "disabled" if he_disabled else "enabled")
    log.info("    802.11be (Wi-Fi 7): %s", "disabled" if be_disabled else "enabled")

    # Add notes for non-standard configs
    wpa2_only_modes = ["wpa2", "ft-wpa2"]
    if not be_disabled and security_mode in wpa2_only_modes:
        log.info("  ⚠ NOTE: Wi-Fi 7 enabled with WPA2-only (non-standard, for testing)")
    if not be_disabled and he_disabled:
        log.info(
            "  ⚠ NOTE: Wi-Fi 7 enabled with Wi-Fi 6 disabled (non-standard, for testing)"
        )

    log.info("=" * 70)
