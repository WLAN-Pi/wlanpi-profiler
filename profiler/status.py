# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024-2026 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.status
~~~~~~~~~~~~~~~

Manage profiler status and info files for external monitoring
"""

import contextlib
import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from profiler.__version__ import __version__
from profiler.constants import (
    _20MHZ_FREQUENCY_CHANNEL_MAP,
    INFO_FILE,
    LAST_SESSION_FILE,
    STATUS_FILE,
)
from profiler.helpers import set_file_permissions


def get_last_session_file_path() -> str:
    """Get persistent last-session file path."""
    return LAST_SESSION_FILE


def get_status_file_path() -> str:
    """Get runtime status file path."""
    return STATUS_FILE


def get_info_file_path() -> str:
    """Get runtime info file path."""
    return INFO_FILE


class ProfilerState(Enum):
    """Profiler lifecycle states"""

    STARTING = "starting"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"


class StatusReason(Enum):
    """Reason codes for state transitions"""

    # Running reasons
    STARTUP_COMPLETE = "startup_complete"

    # Stopped reasons (not written to file, just for logging)
    USER_REQUESTED = "user_requested"

    # Failed reasons
    COUNTRY_CODE_DETECTION = "country_code_detection"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"
    INTERFACE_VALIDATION = "interface_validation"
    CONFIG_VALIDATION = "config_validation"
    MISSING_TOOLS = "missing_tools"
    ALREADY_RUNNING = "already_running"
    FILE_NOT_FOUND = "file_not_found"  # PCAP file, config file, or other file not found
    HOSTAPD_CRASHED = "hostapd_crashed"
    HOSTAPD_START_FAILED = "hostapd_start_failed"
    FAKEAP_CRASHED = "fakeap_crashed"  # TxBeacons or Sniffer process failure
    UNKNOWN_ERROR = "unknown_error"


class CountryCodeError(Exception):
    """Country code detection failed"""


def detect_country_code() -> str:
    """
    Detect regulatory country code from system using iw reg get.

    This should be called EARLY in profiler startup, before expensive operations
    like interface setup, so we can fail fast if country code cannot be detected.

    Returns:
        str: Two-letter country code (e.g., 'US', 'GB', 'DE')

    Raises:
        CountryCodeError: If country code cannot be detected
    """
    log = logging.getLogger(__name__)

    try:
        # Run iw reg get to get regulatory domain
        result = subprocess.run(
            ["/usr/sbin/iw", "reg", "get"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            error_msg = f"Failed to run 'iw reg get': {result.stderr}"
            log.error(error_msg)
            raise CountryCodeError(error_msg)

        # Parse output looking for "country XX:" lines
        # Example: "country US: DFS-FCC"
        # We want valid 2-letter alpha codes, not numeric codes like "99"
        country_pattern = re.compile(r"^country ([A-Z]{2}):", re.MULTILINE)
        matches = country_pattern.findall(result.stdout)

        if not matches:
            error_msg = (
                "No valid country code found in 'iw reg get' output. "
                "Regulatory domain may not be set."
            )
            log.error(error_msg)
            raise CountryCodeError(error_msg)

        # Return the first valid 2-letter country code found
        country_code = matches[0]
        return country_code

    except subprocess.TimeoutExpired as err:
        error_msg = "Timeout while detecting country code (iw reg get)"
        log.error(error_msg)
        raise CountryCodeError(error_msg) from err
    except FileNotFoundError as err:
        error_msg = "iw command not found. Cannot detect regulatory domain."
        log.error(error_msg)
        raise CountryCodeError(error_msg) from err
    except Exception as err:
        error_msg = f"Unexpected error detecting country code: {err}"
        log.error(error_msg)
        raise CountryCodeError(error_msg) from err


_STARTUP_METHOD_CACHE = None


def detect_startup_method() -> str:
    """
    Detect how profiler was started (systemd vs CLI).

    Checks environment variables set by systemd to determine if profiler
    is running as a systemd service or from command line.

    This function caches its result on first call, so it can be called
    multiple times without re-detection.

    Returns:
        str: "systemd" if started by systemd, "cli" if started from terminal
    """
    global _STARTUP_METHOD_CACHE

    if _STARTUP_METHOD_CACHE is not None:
        return _STARTUP_METHOD_CACHE

    # systemd sets these environment variables when running services
    # JOURNAL_STREAM: systemd journal socket for logging
    # INVOCATION_ID: unique ID for this service invocation
    if os.environ.get("JOURNAL_STREAM") or os.environ.get("INVOCATION_ID"):
        _STARTUP_METHOD_CACHE = "systemd"
    else:
        _STARTUP_METHOD_CACHE = "cli"

    return _STARTUP_METHOD_CACHE


def write_status(
    state: ProfilerState,
    reason: Optional[StatusReason] = None,
    pid: Optional[int] = None,
    error: Optional[str] = None,
) -> None:
    """
    Write profiler status to JSON file.

    Args:
        state: Profiler state (starting, running, stopped, failed)
        reason: Reason code for this state
        pid: Process ID (for running state)
        error: Error message (for failed state)

    Note:
        startup_method is automatically detected via detect_startup_method()
    """
    status_file = get_status_file_path()

    # Ensure directory exists
    with contextlib.suppress(OSError):
        os.makedirs(os.path.dirname(status_file), mode=0o755, exist_ok=True)

    status_data: dict = {
        "schema_version": "1.0",
        "state": state.value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "startup_method": detect_startup_method(),  # Auto-detect (cached after first call)
    }

    if reason is not None:
        status_data["reason"] = reason.value
    if pid is not None:
        status_data["pid"] = pid
    if error is not None:
        status_data["error"] = error

    _write_json_atomic(status_file, status_data)


def write_info(
    phy: str,
    channel: int,
    country_code: str,
    ssid: str,
    bssid: str,
    mode: str,
    monitor_interface: str,
    ap_interface: Optional[str] = None,
    passphrase: Optional[str] = None,
    profiler_version: Optional[str] = None,
    last_profile: Optional[str] = None,
    last_profile_timestamp: Optional[str] = None,
    profile_count: int = 0,
    failed_profile_count: int = 0,
    total_clients_seen: int = 0,
    invalid_frame_count: int = 0,
    bad_fcs_count: int = 0,
) -> None:
    """
    Write profiler operational info to JSON file.

    Args:
        phy: PHY device name (e.g., 'phy0')
        channel: Channel number
        country_code: 2-letter country code
        ssid: SSID being broadcast
        bssid: AP MAC address (BSSID)
        mode: Operating mode (hostapd, fake_ap, listen_only)
        monitor_interface: Monitor mode interface (e.g., 'wlan0profiler', 'wlan0mon')
        ap_interface: AP mode interface (e.g., 'wlan0'), None for listen_only mode
        passphrase: WPA passphrase (None for listen_only mode)
        profiler_version: Profiler version string
        last_profile: Last profiled client MAC (optional)
        last_profile_timestamp: ISO timestamp of last profile (optional)
        profile_count: Number of clients profiled this session (default: 0)
        failed_profile_count: Clients that sent auth but never sent assoc (default: 0)
        total_clients_seen: Total unique MAC addresses observed (default: 0)
        invalid_frame_count: Frames filtered due to invalid/corrupted MAC addresses (default: 0)
        bad_fcs_count: Frames filtered due to bad FCS (checksum mismatch) (default: 0)
    """
    info_file = get_info_file_path()

    # Ensure directory exists
    with contextlib.suppress(OSError):
        os.makedirs(os.path.dirname(info_file), mode=0o755, exist_ok=True)

    # Calculate frequency from channel
    frequency = _get_frequency_from_channel(channel)

    if frequency is None:
        log = logging.getLogger(__name__)
        log.warning(
            f"Could not determine frequency for channel {channel}. "
            f"Frequency will be set to null in info file."
        )

    started_at = datetime.now(timezone.utc)

    info_data = {
        "schema_version": "1.0",
        "profiler_version": profiler_version,
        "phy": phy,
        "interfaces": {
            "ap": ap_interface,  # null for listen_only mode
            "monitor": monitor_interface,
        },
        "channel": channel,
        "frequency": frequency,  # May be null if unknown
        "country_code": country_code,
        "ssid": None if mode == "listen_only" else ssid,
        "bssid": None if mode == "listen_only" else bssid,
        "mode": mode,
        "passphrase": passphrase,  # null for listen_only mode
        "started_at": started_at.isoformat(),
        "uptime_seconds": 0,  # Will be updated by status updates
        "profile_count": profile_count,
        "failed_profile_count": failed_profile_count,
        "total_clients_seen": total_clients_seen,
        "invalid_frame_count": invalid_frame_count,
        "bad_fcs_count": bad_fcs_count,
        "last_profile": last_profile,  # null if no profiles yet
        "last_profile_timestamp": last_profile_timestamp,  # null if no profiles yet
    }

    _write_json_atomic(info_file, info_data)


def update_last_profile_in_info(mac: str) -> None:
    """
    Update last_profile, timestamp, count, and uptime in info file.

    Args:
        mac: Client MAC address
    """
    log = logging.getLogger(__name__)
    info_file = get_info_file_path()

    try:
        # Read existing info file
        info_data = _read_json(info_file)
        if info_data is None:
            log.debug("Info file doesn't exist yet, skipping last_profile update")
            return

        # Update last_profile field
        info_data["last_profile"] = mac

        # Update last_profile_timestamp
        now = datetime.now(timezone.utc)
        info_data["last_profile_timestamp"] = now.isoformat()

        # Increment profile_count
        current_count = info_data.get("profile_count", 0)
        info_data["profile_count"] = current_count + 1

        # Update uptime_seconds
        if "started_at" in info_data:
            # Handle both 'Z' suffix and '+00:00' for UTC timestamps
            started_at_str = info_data["started_at"].replace("Z", "+00:00")
            started_at = datetime.fromisoformat(started_at_str)
            uptime = (now - started_at).total_seconds()
            info_data["uptime_seconds"] = int(uptime)

        # Write back atomically
        _write_json_atomic(info_file, info_data)
        log.debug(
            f"Updated info: last_profile={mac}, profile_count={info_data['profile_count']}, uptime={info_data.get('uptime_seconds', 0)}s"
        )

    except Exception as e:
        log.warning(f"Failed to update last_profile in info file: {e}")


def update_monitoring_metrics_in_info(
    total_clients_seen: Optional[int] = None,
    failed_profile_count: Optional[int] = None,
    invalid_frame_count: Optional[int] = None,
    bad_fcs_count: Optional[int] = None,
) -> None:
    """
    Update monitoring metrics in info file (atomic operation).

    Args:
        total_clients_seen: Total unique MAC addresses observed (optional, only updates if provided)
        failed_profile_count: Clients that sent auth but never sent assoc (optional, only updates if provided)
        invalid_frame_count: Frames filtered due to invalid/corrupted MAC addresses (optional, only updates if provided)
        bad_fcs_count: Frames filtered due to bad FCS (checksum mismatch) (optional, only updates if provided)
    """
    log = logging.getLogger(__name__)
    info_file = get_info_file_path()

    try:
        # Read existing info file
        info_data = _read_json(info_file)
        if info_data is None:
            log.debug("Info file doesn't exist yet, skipping monitoring metrics update")
            return

        # Update metrics if provided
        if total_clients_seen is not None:
            info_data["total_clients_seen"] = total_clients_seen

        if failed_profile_count is not None:
            info_data["failed_profile_count"] = failed_profile_count

        if invalid_frame_count is not None:
            info_data["invalid_frame_count"] = invalid_frame_count

        if bad_fcs_count is not None:
            info_data["bad_fcs_count"] = bad_fcs_count

        # Update uptime_seconds
        now = datetime.now(timezone.utc)
        if "started_at" in info_data:
            # Handle both 'Z' suffix and '+00:00' for UTC timestamps
            started_at_str = info_data["started_at"].replace("Z", "+00:00")
            started_at = datetime.fromisoformat(started_at_str)
            uptime = (now - started_at).total_seconds()
            info_data["uptime_seconds"] = int(uptime)

        # Write back atomically
        _write_json_atomic(info_file, info_data)
        log.debug(
            f"Updated monitoring metrics: total_clients_seen={info_data.get('total_clients_seen', 0)}, "
            f"failed_profile_count={info_data.get('failed_profile_count', 0)}, "
            f"invalid_frame_count={info_data.get('invalid_frame_count', 0)}, "
            f"bad_fcs_count={info_data.get('bad_fcs_count', 0)}"
        )

    except Exception as e:
        log.warning(f"Failed to update monitoring metrics in info file: {e}")


def delete_status() -> None:
    """Delete status file (called on clean shutdown)."""
    _delete_file(get_status_file_path())


def delete_info() -> None:
    """Delete info file (called on shutdown)."""
    _delete_file(get_info_file_path())


def get_status() -> Optional[dict]:
    """
    Read and parse status file.

    Returns:
        dict: Parsed status data, or None if file doesn't exist or parse fails
    """
    return _read_json(get_status_file_path())


def get_info() -> Optional[dict]:
    """
    Read and parse info file.

    Returns:
        dict: Parsed info data, or None if file doesn't exist or parse fails
    """
    return _read_json(get_info_file_path())


def is_process_alive(pid: int) -> bool:
    """
    Check if a process is still running.

    Args:
        pid: Process ID to check

    Returns:
        bool: True if process exists, False otherwise
    """
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _get_frequency_from_channel(channel: int) -> Optional[int]:
    """
    Get frequency (MHz) from channel number.

    This is critical for 6 GHz support where channel numbers overlap
    with 2.4 GHz (e.g., channel 1 in 2.4 GHz vs channel 1 in 6 GHz).

    Args:
        channel: Channel number

    Returns:
        Frequency in MHz, or None if not found
    """
    # Reverse lookup in frequency map
    for freq, ch in _20MHZ_FREQUENCY_CHANNEL_MAP.items():
        if ch == channel:
            return freq
    return None


def _write_json_atomic(filepath: str, data: dict) -> None:
    """
    Write JSON to file atomically (write to temp, then rename).
    Cleans up temp file on failure.

    Args:
        filepath: Target file path
        data: Dictionary to write as JSON
    """
    log = logging.getLogger(__name__)
    temp_file = f"{filepath}.tmp"

    try:
        with open(temp_file, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")  # Trailing newline

        # Set permissions before rename so final file has correct perms
        set_file_permissions(temp_file)

        # Atomic rename
        os.rename(temp_file, filepath)

    except Exception as e:
        log.warning(f"Failed to write {filepath}: {e}")
        # Clean up temp file on failure
        with contextlib.suppress(Exception):
            if os.path.exists(temp_file):
                os.remove(temp_file)


def _read_json(filepath: str) -> Optional[dict]:
    """
    Read and parse JSON file.

    Args:
        filepath: File to read

    Returns:
        Parsed JSON dict, or None if file doesn't exist or parse fails
    """
    try:
        if not os.path.exists(filepath):
            return None

        with open(filepath) as f:
            return json.load(f)
    except Exception:
        return None


def _delete_file(filepath: str) -> None:
    """Safely delete a file if it exists."""
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
    except Exception:
        pass


def write_last_session(
    exit_status: str,
    exit_code: int,
    start_time: str,
    exit_reason: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    """
    Write persistent last-session file for post-mortem analysis.

    This file records the final state of a profiler session when it shuts down,
    allowing diagnosis of crashes or unexpected exits after the fact.

    Only called for live capture mode (requires root).
    Path: /var/lib/wlanpi-profiler/last-session.json
    """
    log = logging.getLogger(__name__)
    session_file = get_last_session_file_path()

    # Ensure directory exists
    with contextlib.suppress(OSError):
        os.makedirs(os.path.dirname(session_file), mode=0o755, exist_ok=True)

    # Build session data
    info_data = get_info()
    if not info_data:
        info_data = {}

    ended_at = datetime.now(timezone.utc).isoformat()
    started_at = start_time

    try:
        start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
        duration_seconds = int((end_dt - start_dt).total_seconds())
    except Exception:
        duration_seconds = 0

    session_data = {
        "schema_version": "1.0",
        "profiler_version": __version__,
        "session": {
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": duration_seconds,
        },
        "exit": {
            "status": exit_status,
            "code": exit_code,
            "reason": exit_reason,
            "message": error_message,
        },
        "configuration": {
            "mode": info_data.get("mode"),
            "phy": info_data.get("phy"),
            "interfaces": info_data.get("interfaces"),
            "channel": info_data.get("channel"),
            "frequency": info_data.get("frequency"),
            "country_code": info_data.get("country_code"),
            "ssid": info_data.get("ssid"),
            "bssid": info_data.get("bssid"),
        },
        "metrics": {
            "profile_count": info_data.get("profile_count", 0),
            "failed_profile_count": info_data.get("failed_profile_count", 0),
            "total_clients_seen": info_data.get("total_clients_seen", 0),
            "invalid_frame_count": info_data.get("invalid_frame_count", 0),
            "bad_fcs_count": info_data.get("bad_fcs_count", 0),
            "last_profile": info_data.get("last_profile"),
            "last_profile_timestamp": info_data.get("last_profile_timestamp"),
        },
    }

    _write_json_atomic(session_file, session_data)
    log.info(f"Last session file written: {exit_status} (code {exit_code})")


def read_last_session() -> Optional[dict]:
    """
    Read persistent last-session file.

    Path: /var/lib/wlanpi-profiler/last-session.json
    """
    return _read_json(get_last_session_file_path())
