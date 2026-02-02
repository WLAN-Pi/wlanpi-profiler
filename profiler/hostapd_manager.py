# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024-2026 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.hostapd_manager
~~~~~~~~~~~~~~~~~~~~~~~~~

Manages hostapd process lifecycle for AP mode
"""

import logging
import os
import subprocess
import threading
import time
from typing import Optional

from profiler.constants import (
    HOSTAPD_BINARY,
    HOSTAPD_CLI_BINARY,
    PROFILER_CTRL_INTERFACE,
)


class HostapdError(Exception):
    """Base exception for hostapd operations"""


class HostapdNotFoundError(HostapdError):
    """Hostapd binary not found at expected path"""


class HostapdConfigError(HostapdError):
    """Invalid configuration parameters"""


class HostapdStartupError(HostapdError):
    """Hostapd failed to start"""


class HostapdDriverError(HostapdError):
    """Driver doesn't support required features"""


class HostapdManager:
    """Manages hostapd subprocess for AP mode"""

    def __init__(self, config: dict, country_code: str, logger: logging.Logger):
        """
        Initialize hostapd manager.

        Args:
            config: Profiler configuration dict (from helpers.setup_config)
            country_code: Two-letter country code (e.g., 'US', 'GB', 'DE')
            logger: Logger instance
        """
        self.config = config
        self.country_code = country_code
        self.log = logger
        self.process: Optional[subprocess.Popen] = None
        self.config_path: Optional[str] = None
        # Use ap_interface (wlan0) if available, otherwise fall back to interface
        self.interface = config.get("ap_interface", config.get("interface", "wlan0"))
        self.bssid: Optional[str] = None
        self._log_threads: list[threading.Thread] = []  # Track log streaming threads

        # Watchdog thread for monitoring process health
        self._watchdog_thread: Optional[threading.Thread] = None
        self._watchdog_stop = threading.Event()
        self._watchdog_running = False

        # Log monitoring for fatal errors
        self._init_failed = False
        self._init_error_msg: Optional[str] = None
        self._startup_time: Optional[float] = None

    def _stream_logs(self, stream, prefix: str):
        """
        Stream logs from hostapd stdout/stderr to profiler logger.
        Also monitors for fatal errors during startup window.

        Args:
            stream: File-like object (stdout or stderr)
            prefix: Log prefix (e.g., "HOSTAPD", "HOSTAPD-ERR")
        """
        FATAL_ERRORS = [
            "Interface initialization failed",
            "Could not set channel for kernel driver",
            "Failed to set beacon",
            "Could not set interface flags",
        ]

        FATAL_EVENTS = [
            "AP-DISABLED",
            "CTRL-EVENT-TERMINATING",
        ]

        STARTUP_WINDOW = 10  # Monitor for fatal errors in first 10 seconds

        try:
            for line in stream:
                line = line.strip()
                if not line:
                    continue

                # Check if we're in startup window
                in_startup = (
                    self._startup_time
                    and (time.time() - self._startup_time) < STARTUP_WINDOW
                )

                # Detect fatal errors during startup
                if in_startup:
                    # Check for fatal error messages
                    for error_pattern in FATAL_ERRORS:
                        if error_pattern in line:
                            self._init_failed = True
                            self._init_error_msg = line
                            self.log.error(f"[{prefix}] FATAL: {line}")
                            break

                    # Check for fatal events
                    if not self._init_failed:
                        for event_pattern in FATAL_EVENTS:
                            if event_pattern in line:
                                self._init_failed = True
                                self._init_error_msg = line
                                self.log.error(f"[{prefix}] FATAL EVENT: {line}")
                                break

                # Regular logging
                if "error" in line.lower() or "failed" in line.lower():
                    self.log.error(f"[{prefix}] {line}")
                elif "warning" in line.lower():
                    self.log.warning(f"[{prefix}] {line}")
                elif "DFS" in line:
                    # Highlight our DFS bypass messages
                    self.log.info(f"[{prefix}] {line}")
                else:
                    # Most hostapd messages (including PROFILER:) are debug-level
                    self.log.debug(f"[{prefix}] {line}")
        except Exception as e:
            self.log.debug(f"Log streaming thread ({prefix}) stopped: {e}")

    def _watchdog(self):
        """
        Background thread that monitors hostapd process health indefinitely.
        Triggers profiler shutdown if hostapd exits unexpectedly or fails during startup.

        Uses SIGUSR1 to signal the main process, ensuring proper error handling
        distinct from intentional shutdowns (SIGINT/SIGTERM).
        """
        self.log.debug("Hostapd watchdog thread started")
        self._watchdog_running = True

        poll_interval = 1.0  # Check every 1 second

        while not self._watchdog_stop.is_set():
            if self.process is None:
                break

            # Check if process has exited
            exit_code = self.process.poll()
            if exit_code is not None:
                # Process has exited - determine if this is an error or intentional shutdown

                # Case 1: Fatal error detected in logs (during startup window)
                # This covers scenarios where hostapd logs errors but exits with code 0
                if self._init_failed:
                    self.log.error(
                        f"Hostapd failed during startup (exit code: {exit_code})"
                    )
                    self.log.error(
                        f"Fatal error detected in logs: {self._init_error_msg}"
                    )

                    error_detail = (
                        f"Hostapd initialization failed: {self._init_error_msg}"
                    )

                    from profiler.status import (
                        ProfilerState,
                        StatusReason,
                        write_status,
                    )

                    write_status(
                        state=ProfilerState.FAILED,
                        reason=StatusReason.HOSTAPD_START_FAILED,
                        error=error_detail,
                    )

                    import os
                    import signal

                    self.log.error(
                        "Triggering profiler shutdown due to hostapd startup failure"
                    )
                    time.sleep(0.1)  # Ensure status file write completes
                    os.kill(os.getpid(), signal.SIGUSR1)

                    self._watchdog_running = False
                    break

                # Case 2: Clean exit (exit code 0, no errors detected in logs)
                # This is intentional shutdown (cleanup() called)
                if exit_code == 0:
                    self.log.debug("Hostapd exited cleanly (exit code: 0)")
                    self._watchdog_running = False
                    break

                # Case 3: Non-zero exit code (unexpected crash/failure)
                # Runtime crash after startup window, or immediate failure
                self.log.error(
                    f"Hostapd process died unexpectedly (exit code: {exit_code})"
                )

                # Build detailed error message
                error_detail = f"Hostapd exited with code {exit_code}"
                if exit_code == -11:
                    error_detail += " (SIGSEGV - segmentation fault/crash)"
                elif exit_code == -15:
                    error_detail += " (SIGTERM - terminated)"
                elif exit_code == -9:
                    error_detail += " (SIGKILL - killed)"
                elif exit_code == 1:
                    error_detail += " (configuration error or initialization failure)"

                from profiler.status import ProfilerState, StatusReason, write_status

                write_status(
                    state=ProfilerState.FAILED,
                    reason=StatusReason.HOSTAPD_CRASHED,
                    error=error_detail,
                )

                import os
                import signal

                self.log.error("Triggering profiler shutdown due to hostapd failure")
                time.sleep(0.1)  # Ensure status file write completes
                os.kill(os.getpid(), signal.SIGUSR1)

                self._watchdog_running = False
                break

            # Sleep for interval (but wake on stop signal)
            self._watchdog_stop.wait(timeout=poll_interval)

        self.log.debug("Hostapd watchdog thread stopped")
        self._watchdog_running = False

    def generate_config(self) -> str:
        """
        Generate hostapd configuration file using Jinja2 template.

        Returns:
            str: Path to generated config file

        Raises:
            HostapdConfigError: If configuration parameters invalid
        """
        from profiler.config_generator import generate_hostapd_config

        try:
            # Determine band from channel/frequency
            channel = self.config.get("channel")
            frequency = self.config.get("frequency")

            if frequency:
                if frequency < 2500:
                    band = "2ghz"
                elif frequency < 5900:
                    band = "5ghz"
                else:
                    band = "6ghz"
            elif channel:
                if channel <= 14:
                    band = "2ghz"
                elif channel <= 173:
                    band = "5ghz"
                else:
                    band = "6ghz"
            else:
                # Default to 5 GHz
                band = "5ghz"
                channel = 36

            # Generate config
            self.config_path = generate_hostapd_config(
                interface=self.interface,
                channel=channel,
                ssid=self.config.get("ssid", "Profiler"),
                band=band,
                country_code=self.country_code,
                passphrase=self.config.get("passphrase", "profiler"),
                security_mode=self.config.get("security_mode", "ft-wpa3-mixed"),
                he_disabled=self.config.get("he_disabled", False),
                be_disabled=self.config.get("be_disabled", False),
                profiler_tlv_disabled=self.config.get("profiler_tlv_disabled", False),
                mac_address=self.config.get("mac"),
            )

            self.log.info(f"Generated hostapd config: {self.config_path}")

            return self.config_path

        except Exception as e:
            raise HostapdConfigError(f"Failed to generate config: {e}") from e

    def start(self) -> subprocess.Popen:
        """
        Start hostapd subprocess.

        Returns:
            subprocess.Popen: Hostapd process handle

        Raises:
            HostapdNotFoundError: If hostapd binary not found
            HostapdStartupError: If hostapd fails to start
        """
        # Check binary exists
        if not os.path.exists(HOSTAPD_BINARY):
            raise HostapdNotFoundError(
                f"Hostapd binary not found at {HOSTAPD_BINARY}. "
                "This installation may be corrupted. Reinstall wlanpi-profiler."
            )

        # Generate config if not already done
        if not self.config_path:
            self.generate_config()

        # Start hostapd
        if not self.config_path:
            raise HostapdError("Config path not set - call generate_config() first")

        try:
            os.makedirs(PROFILER_CTRL_INTERFACE, mode=0o755, exist_ok=True)
            self.log.debug(
                f"Created ctrl_interface directory: {PROFILER_CTRL_INTERFACE}"
            )
        except Exception as e:
            self.log.warning(f"Failed to create ctrl_interface directory: {e}")

        try:
            # Build hostapd command - add -d flag for expert mode to show MSG_DEBUG messages
            hostapd_cmd = [HOSTAPD_BINARY]
            if self.config.get("expert", False):
                hostapd_cmd.append("-d")  # Enable debug output for PROFILER messages
            hostapd_cmd.append(self.config_path)

            # Record startup time for log monitoring
            self._startup_time = time.time()

            self.log.info(f"Starting hostapd: {' '.join(hostapd_cmd)}")
            self.process = subprocess.Popen(
                hostapd_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered for real-time streaming
            )

            # Start log streaming threads
            stdout_thread = threading.Thread(
                target=self._stream_logs,
                args=(self.process.stdout, "HOSTAPD"),
                daemon=True,
                name="hostapd-stdout",
            )
            stderr_thread = threading.Thread(
                target=self._stream_logs,
                args=(self.process.stderr, "HOSTAPD-ERR"),
                daemon=True,
                name="hostapd-stderr",
            )
            stdout_thread.start()
            stderr_thread.start()
            self._log_threads = [stdout_thread, stderr_thread]
            self.log.debug("Started hostapd log streaming threads")

            # Wait a moment for startup
            time.sleep(2)

            # Check if process died immediately
            if self.process.poll() is not None:
                exit_code = self.process.returncode

                # Provide helpful error messages based on exit code
                error_msg = (
                    f"Hostapd died immediately after startup.\nExit code: {exit_code}\n"
                )

                if exit_code == -11:  # SIGSEGV
                    error_msg += (
                        "Exit code -11 (SIGSEGV) suggests hostapd crashed.\n"
                        "This often happens when:\n"
                        "  - Interface is already in use by another AP\n"
                        "  - Previous profiler instance didn't clean up properly\n"
                        "Try: sudo pkill -9 profiler; sudo pkill -9 hostapd\n"
                        "Then restart profiler.\n"
                    )
                elif exit_code == 1:
                    error_msg += "Configuration error or interface already in use.\n"

                # Note: Stderr already logged by streaming thread, no need to include here
                error_msg += "(See hostapd logs above for details)"
                raise HostapdStartupError(error_msg)

            self.log.info(f"Hostapd started successfully (PID: {self.process.pid})")

            # Start watchdog thread to monitor process health indefinitely
            self._watchdog_stop.clear()
            self._watchdog_thread = threading.Thread(
                target=self._watchdog,
                daemon=True,  # Thread dies with main process
                name="hostapd-watchdog",
            )
            self._watchdog_thread.start()
            self.log.debug("Started hostapd process watchdog thread")

            # Get BSSID from interface
            self._get_bssid()

            return self.process

        except FileNotFoundError as err:
            raise HostapdNotFoundError(
                f"Hostapd binary not found: {HOSTAPD_BINARY}"
            ) from err
        except subprocess.TimeoutExpired as err:
            raise HostapdStartupError("Timeout waiting for hostapd startup") from err
        except Exception as err:
            raise HostapdStartupError(f"Failed to start hostapd: {err}") from err

    def stop(self, timeout: int = 5):
        """
        Gracefully stop hostapd (SIGTERM → SIGKILL).

        Args:
            timeout: Seconds to wait before SIGKILL
        """
        if not self.process:
            return

        try:
            if self.process.poll() is None:
                self.log.info(f"Stopping hostapd (PID: {self.process.pid})...")
                self.process.terminate()

                # Wait for graceful shutdown
                try:
                    self.process.wait(timeout=timeout)
                    self.log.info("Hostapd stopped gracefully")
                except subprocess.TimeoutExpired:
                    self.log.warning(
                        f"Hostapd didn't stop after {timeout}s, killing..."
                    )
                    self.process.kill()
                    self.process.wait(timeout=2)
                    self.log.info("Hostapd killed")
        except Exception as e:
            self.log.error(f"Error stopping hostapd: {e}")

    def is_running(self) -> bool:
        """Check if hostapd process is alive"""
        if not self.process:
            return False
        return self.process.poll() is None

    def get_bssid(self) -> Optional[str]:
        """
        Get AP BSSID (MAC address).

        Returns:
            str: MAC address in format "aa:bb:cc:dd:ee:ff" or None if not available
        """
        return self.bssid

    def _get_bssid(self):
        """
        Read actual transmitted BSSID from hostapd control interface.

        When MLD mode (mld_ap=1) is enabled, hostapd may use a different
        BSSID than the interface MAC. We query hostapd_cli for the actual BSSID.
        """
        try:
            result = subprocess.run(
                [
                    HOSTAPD_CLI_BINARY,
                    "-p",
                    PROFILER_CTRL_INTERFACE,
                    "-i",
                    self.interface,
                    "status",
                ],
                capture_output=True,
                text=True,
                timeout=2,
            )

            if result.returncode == 0:
                # Parse output for "bssid[0]=aa:bb:cc:dd:ee:ff"
                for line in result.stdout.split("\n"):
                    if line.startswith("bssid[0]="):
                        self.bssid = line.split("=")[1].strip().lower()
                        self.log.debug(f"AP BSSID from hostapd_cli: {self.bssid}")
                        return

            # Fallback: Read interface MAC (may not be accurate with MLD)
            result = subprocess.run(
                ["ip", "link", "show", self.interface],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "link/ether" in line:
                        self.bssid = line.split()[1]
                        self.log.warning(
                            f"Using interface MAC as BSSID: {self.bssid} "
                            "(hostapd_cli failed, may be incorrect with MLD mode)"
                        )
                        break
        except Exception as e:
            self.log.warning(f"Failed to get BSSID: {e}")

    def cleanup(self):
        """Cleanup temp files and resources"""
        self.log.debug("Cleaning up hostapd...")

        if self._watchdog_thread and self._watchdog_running:
            self.log.debug("Stopping hostapd watchdog thread...")
            self._watchdog_stop.set()
            # Give thread time to exit gracefully (reduced timeout for faster shutdown)
            self._watchdog_thread.join(timeout=1)

        self.stop()

        if self.config_path and os.path.exists(self.config_path):
            try:
                os.remove(self.config_path)
                self.log.debug(f"Removed temp config: {self.config_path}")
            except Exception as e:
                self.log.warning(f"Failed to remove temp config: {e}")

        ctrl_socket = f"{PROFILER_CTRL_INTERFACE}/{self.interface}"
        if os.path.exists(ctrl_socket):
            try:
                os.remove(ctrl_socket)
                self.log.debug(f"Removed ctrl_interface socket: {ctrl_socket}")
            except Exception as e:
                self.log.warning(f"Failed to remove ctrl_interface socket: {e}")

        self.log.info("Hostapd cleanup complete")
