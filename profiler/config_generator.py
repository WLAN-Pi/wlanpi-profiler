# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2026 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.config_generator
~~~~~~~~~~~~~~~~~~~~~~~~~

Generate hostapd configuration files using Jinja2 templates
"""

import os
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from profiler.__version__ import __version__
from profiler.constants import HOSTAPD_CONFIG_DIR, SECURITY_MODES
from profiler.helpers import get_wlanpi_version


class ConfigGeneratorError(Exception):
    """Base exception for config generation errors"""


class TemplateNotFoundError(ConfigGeneratorError):
    """Template file not found"""


def get_template_dir() -> Path:
    """Get path to templates directory"""
    # Templates are in profiler/templates/
    module_dir = Path(__file__).parent
    return module_dir / "templates"


def build_vendor_ie_hex() -> str:
    """
    Build WLAN Pi profiler vendor-specific IE in hex format for hostapd.

    Format: DD<len>314159<subtype><TLVs>
    OUI: 31:41:59 (π digits)
    Subtype: 00
    TLV 0: Profiler version
    TLV 1: System version

    Returns:
        str: Hex string for hostapd vendor_elements parameter
    """
    oui = bytes([0x31, 0x41, 0x59])
    subtype = bytes([0x00])

    # TLV 0: Profiler version
    profiler_version = __version__
    profiler_version_data = profiler_version.encode("ascii")
    profiler_version_tlv = (
        bytes([0x00])  # Type
        + bytes([len(profiler_version_data)])  # Length
        + profiler_version_data  # Value
    )

    # TLV 1: System version
    system_version = get_wlanpi_version()
    system_version_data = system_version.encode("ascii")
    system_version_tlv = (
        bytes([0x01])  # Type
        + bytes([len(system_version_data)])  # Length
        + system_version_data  # Value
    )

    # Assemble vendor data
    vendor_data = oui + subtype + profiler_version_tlv + system_version_tlv

    # Build full IE: Element ID (DD) + Length + Data
    ie_length = len(vendor_data)
    full_ie = bytes([0xDD, ie_length]) + vendor_data

    # Convert to hex string (e.g., "dd0f31415900...")
    return full_ie.hex()


def calculate_center_frequency(channel: int, bandwidth: int) -> int:
    """
    Calculate VHT/HE center frequency segment 0 index.

    Args:
        channel: Primary channel number
        bandwidth: Channel width (20, 40, 80, 160 MHz)

    Returns:
        int: Center frequency segment 0 channel index
    """
    if bandwidth == 20:
        return channel
    elif bandwidth == 40:
        # For 40 MHz, center is +2 or -2 from primary
        if channel <= 7:  # 2.4 GHz (channels 1-13)
            return channel + 2
        else:  # 5 GHz
            return channel + 2
    elif bandwidth == 80:
        # For 80 MHz in 5 GHz
        if channel in [36, 40, 44, 48]:
            return 42
        elif channel in [52, 56, 60, 64]:
            return 58
        elif channel in [100, 104, 108, 112]:
            return 106
        elif channel in [116, 120, 124, 128]:
            return 122
        elif channel in [132, 136, 140, 144]:
            return 138
        elif channel in [149, 153, 157, 161]:
            return 155
        elif channel in [165, 169, 173]:
            return 171
        else:
            return channel + 6  # Fallback
    elif bandwidth == 160:
        # For 160 MHz in 5 GHz
        if channel in [36, 40, 44, 48, 52, 56, 60, 64]:
            return 50
        elif channel in [100, 104, 108, 112, 116, 120, 124, 128]:
            return 114
        elif channel in [149, 153, 157, 161, 165, 169, 173]:
            return 163
        else:
            return channel + 14  # Fallback
    else:
        return channel


def generate_hostapd_config(
    interface: str,
    channel: int,
    ssid: str,
    band: str,
    country_code: str,
    passphrase: str = "profiler",
    security_mode: str = "ft-wpa3-mixed",
    he_disabled: bool = False,
    be_disabled: bool = False,
    profiler_tlv_disabled: bool = False,
    output_path: Optional[str] = None,
    mac_address: Optional[str] = None,
) -> str:
    """
    Generate hostapd configuration file.

    Args:
        interface: WLAN interface name (e.g., 'wlan0')
        channel: Channel number (1-13 for 2.4 GHz, 36-165 for 5 GHz)
        ssid: Network SSID (max 32 chars)
        band: Frequency band ('2ghz' or '5ghz')
        country_code: Two-letter country code (e.g., 'US', 'GB', 'DE')
        passphrase: AP passphrase (8-63 chars, default: profiler)
        security_mode: Security mode (wpa2, ft-wpa2, wpa3-mixed, ft-wpa3-mixed)
        he_disabled: Disable 802.11ax (Wi-Fi 6)
        be_disabled: Disable 802.11be (Wi-Fi 7)
        profiler_tlv_disabled: Disable WLAN Pi profiler vendor IE (--noprofilertlv)
        output_path: Custom output path (default: /tmp/profiler_hostapd_{pid}.conf)

    Returns:
        str: Path to generated configuration file

    Raises:
        ConfigGeneratorError: If parameters invalid
        TemplateNotFoundError: If template file missing
    """
    if band not in ["2ghz", "5ghz", "6ghz"]:
        raise ConfigGeneratorError(
            f"Invalid band: {band}. Must be '2ghz', '5ghz', or '6ghz'"
        )

    if band == "6ghz":
        raise ConfigGeneratorError(
            "6 GHz band not currently supported. "
            "Use 5 GHz (e.g., channel 36) or 2.4 GHz (e.g., channel 6)."
        )

    if len(ssid) > 31:
        raise ConfigGeneratorError(f"SSID too long: {len(ssid)} chars (max 31)")

    if band == "2ghz" and not (1 <= channel <= 13):
        raise ConfigGeneratorError(f"Invalid 2.4 GHz channel: {channel}. Must be 1-14.")
    elif band == "5ghz" and channel not in [
        36,
        40,
        44,
        48,
        52,
        56,
        60,
        64,
        100,
        104,
        108,
        112,
        116,
        120,
        124,
        128,
        132,
        136,
        140,
        144,
        149,
        153,
        157,
        161,
        165,
    ]:
        raise ConfigGeneratorError(f"Invalid 5 GHz channel: {channel}")

    hw_mode = "g" if band == "2ghz" else "a"

    # Calculate center frequencies - operate at 20 MHz, advertise 160 MHz capability
    if band == "5ghz":
        # Operate at 20 MHz for maximum driver compatibility
        # Patches still advertise 160 MHz capability in beacons for client profiling
        # This allows clients to reveal their full capabilities without requiring
        # the AP hardware to actually support high bandwidth operation
        vht_oper_chwidth = 0  # 20/40 MHz operation
        vht_centr_freq = 0  # For 20 MHz, center freq must be 0 or omitted
        he_oper_chwidth = 0  # 20/40 MHz operation
        he_centr_freq = 0  # For 20 MHz, center freq must be 0 or omitted
        eht_oper_chwidth = 0  # 20/40 MHz operation
        eht_centr_freq = 0  # For 20 MHz, center freq must be 0 or omitted
    else:  # 2.4 GHz
        vht_oper_chwidth = 0  # No VHT in 2.4 GHz
        vht_centr_freq = channel
        he_oper_chwidth = 0  # 20/40 MHz max
        he_centr_freq = channel
        eht_oper_chwidth = 0
        eht_centr_freq = channel

    # Get interface MAC address if not provided
    if mac_address is None:
        try:
            with open(f"/sys/class/net/{interface}/address") as f:
                mac_address = f.read().strip()
        except FileNotFoundError:
            # Interface doesn't exist (e.g., in test environment)
            # Use a dummy MAC address for testing
            mac_address = "00:11:22:33:44:55"
        except Exception as e:
            raise ConfigGeneratorError(
                f"Failed to read MAC address for {interface}: {e}"
            ) from e

    # Validate country code
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        raise ConfigGeneratorError(
            f"Invalid country code: {country_code}. Must be 2-letter country code (e.g., 'US')."
        )

    # Validate security_mode
    if security_mode not in SECURITY_MODES:
        raise ConfigGeneratorError(
            f"Invalid security_mode: {security_mode}. "
            f"Must be one of: {', '.join(SECURITY_MODES.keys())}"
        )

    # Map security_mode to wpa_key_mgmt and feature flags
    wpa_key_mgmt = SECURITY_MODES[security_mode]
    ft_enabled = "FT-" in wpa_key_mgmt
    wpa3_enabled = "SAE" in wpa_key_mgmt

    template_data = {
        # Basic
        "interface": interface,
        "ssid": ssid,
        "channel": channel,
        "country_code": country_code,  # Passed from manager.py (detected via iw reg get)
        "hw_mode": hw_mode,
        "mac_address": mac_address,  # Interface MAC address for BSSID
        # Security
        "wpa_key_mgmt": wpa_key_mgmt,
        "ft_enabled": ft_enabled,
        "wpa3_enabled": wpa3_enabled,
        "mobility_domain": "BE11",
        "passphrase": passphrase,
        # 802.11 standards
        "ieee80211n_enabled": True,  # Always enable 802.11n
        "ieee80211ac_enabled": (
            band == "5ghz"
        ),  # VHT only in 5 GHz (independent of HE)
        "ieee80211ax_enabled": not he_disabled,
        "ieee80211be_enabled": (not he_disabled) and (not be_disabled),
        # VHT/HE/EHT parameters
        "vht_oper_chwidth": vht_oper_chwidth,
        "vht_oper_centr_freq_seg0_idx": vht_centr_freq,
        "he_oper_chwidth": he_oper_chwidth,
        "he_oper_centr_freq_seg0_idx": he_centr_freq,
        "eht_oper_chwidth": eht_oper_chwidth,
        "eht_oper_centr_freq_seg0_idx": eht_centr_freq,
        # Vendor-specific IE (WLAN Pi Profiler version advertisement)
        # Only include if not disabled via --noprofilertlv
        "vendor_elements": "" if profiler_tlv_disabled else build_vendor_ie_hex(),
    }

    try:
        template_dir = get_template_dir()
        env = Environment(loader=FileSystemLoader(template_dir))

        template_name = f"hostapd_{band}.conf.j2"
        template = env.get_template(template_name)

    except TemplateNotFound as err:
        raise TemplateNotFoundError(
            f"Template not found: {template_name}. "
            f"Expected location: {template_dir / template_name}"
        ) from err

    config_content = template.render(**template_data)

    if not output_path:
        output_path = os.path.join(
            HOSTAPD_CONFIG_DIR, f"profiler_hostapd_{os.getpid()}.conf"
        )

    try:
        with open(output_path, "w") as f:
            f.write(config_content)
        os.chmod(output_path, 0o600)
    except Exception as e:
        raise ConfigGeneratorError(f"Failed to write config file: {e}") from e

    return output_path
