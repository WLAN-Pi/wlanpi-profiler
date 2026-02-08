# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024-2026 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com


"""
profiler.manager
~~~~~~~~~~~~~~~~

handle profiler
"""

import argparse
import contextlib
import inspect
import logging
import multiprocessing as mp
import os
import platform
import signal
import sys
from datetime import datetime
from multiprocessing import Queue
from time import sleep

from . import helpers
from .__version__ import __version__
from .constants import _20MHZ_FREQUENCY_CHANNEL_MAP, SSID_TMP_FILE

# NOTE: scapy imports lazy loaded to speed up -h/--help response

# Conditional imports for Linux-only live capture features
# Interface and HostapdManager are only needed for live capture mode
Interface = None
InterfaceError = Exception
if sys.platform.startswith("linux"):
    with contextlib.suppress(ImportError):
        from .interface import Interface, InterfaceError


__PIDS: list[tuple[str, int]] = []
__PIDS.append(("main", os.getpid()))
__IFACE = Interface() if Interface is not None else None
__HOSTAPD_MGR = None  # Global hostapd manager for cleanup
__RUNNING_PROCESSES: list[mp.Process] = []  # Global list of child processes for cleanup

# Session start time for state file (set in start(), used by signal handlers)
_session_start_time: str = ""
# Track if we're in pcap analysis mode (set in start(), used by exception handlers)
_pcap_analysis_mode: bool = False


def removeVif() -> None:
    """Remove the vif we created if exists"""
    if __IFACE and __IFACE.requires_vif and not __IFACE.removed:
        log = logging.getLogger(inspect.stack()[0][3])
        log.debug("Removing monitor vif ...")
        __IFACE.reset_interface()
        __IFACE.removed = True


def receiveSignal(signum: int, _frame) -> None:
    """Handle noisy keyboardinterrupt"""
    # Stop hostapd watchdog immediately to prevent race condition
    # (watchdog might see AP-DISABLED and trigger failure before we finish cleanup)
    if __HOSTAPD_MGR is not None:
        __HOSTAPD_MGR._watchdog_stop.set()

    for name, pid in __PIDS:
        # We only want to print exit messages once as multiple processes close
        if name == "main" and os.getpid() == pid:
            try:
                if signum == 2:
                    print("\nDetected SIGINT or Control-C ...")
                if signum == 15:
                    print("Detected SIGTERM ...")
            except BrokenPipeError:
                pass  # stdout closed, ignore

            # Terminate all child processes
            log = logging.getLogger("manager")
            for process in __RUNNING_PROCESSES[
                :
            ]:  # Use slice to avoid modification during iteration
                try:
                    log.debug(
                        f"Terminating process {process.name} (PID: {process.pid})"
                    )
                    process.terminate()
                    process.join(timeout=2)
                    if process.is_alive():
                        log.debug(
                            f"Force killing process {process.name} (PID: {process.pid})"
                        )
                        process.kill()
                        process.join(timeout=1)
                except (OSError, ProcessLookupError) as e:
                    # Expected when process already terminated
                    with contextlib.suppress(BrokenPipeError, ValueError):
                        log.debug(f"Error terminating process {process.name}: {e}")
                except (BrokenPipeError, ValueError):
                    # Logger closed during cleanup, ignore
                    pass

            if os.path.isfile(SSID_TMP_FILE):
                os.remove(SSID_TMP_FILE)

            # Write last-session file BEFORE deleting runtime files
            from profiler.status import delete_info, delete_status, write_last_session

            if _session_start_time:
                write_last_session(
                    exit_status="success",
                    exit_code=0,
                    start_time=_session_start_time,
                )

            delete_status()
            delete_info()

            # Cleanup interface (suppress logging errors)
            if __IFACE and __IFACE.requires_vif:
                with contextlib.suppress(BrokenPipeError, ValueError):
                    removeVif()

            # Cleanup hostapd if running (suppress logging errors)
            if __HOSTAPD_MGR is not None:
                with contextlib.suppress(BrokenPipeError, ValueError):
                    __HOSTAPD_MGR.cleanup()

            if signum in (2, 15):
                sys.exit(0)
            else:
                sys.exit(1)


def receiveWatchdogSignal(_signum: int, _frame) -> None:
    """
    Handle SIGUSR1 from hostapd watchdog indicating hostapd failure.

    This is only triggered by the watchdog thread when hostapd dies unexpectedly
    or fails during startup. Always exits with code 1 indicating error.
    """
    # If watchdog was told to stop, this is a graceful shutdown - ignore
    if __HOSTAPD_MGR is not None and __HOSTAPD_MGR._watchdog_stop.is_set():
        return

    for name, pid in __PIDS:
        if name == "main" and os.getpid() == pid:
            with contextlib.suppress(BrokenPipeError):
                print("Hostapd watchdog detected failure, shutting down...")

            # terminate all child processes
            log = logging.getLogger("manager")
            for process in __RUNNING_PROCESSES[:]:
                try:
                    log.debug(
                        f"Terminating process {process.name} (PID: {process.pid})"
                    )
                    process.terminate()
                    process.join(timeout=2)
                    if process.is_alive():
                        log.debug(
                            f"Force killing process {process.name} (PID: {process.pid})"
                        )
                        process.kill()
                        process.join(timeout=1)
                except (OSError, ProcessLookupError) as e:
                    with contextlib.suppress(BrokenPipeError, ValueError):
                        log.debug(f"Error terminating process {process.name}: {e}")
                except (BrokenPipeError, ValueError):
                    pass

            if os.path.isfile(SSID_TMP_FILE):
                os.remove(SSID_TMP_FILE)

            # Read status for error details, write state file, then cleanup
            from profiler.status import (
                delete_info,
                delete_status,
                get_status,
                write_last_session,
            )

            exit_reason = None
            error_message = None
            current_status = get_status()
            if current_status:
                exit_reason = current_status.get("reason")
                error_message = current_status.get("error")

            if _session_start_time:
                write_last_session(
                    exit_status="failed",
                    exit_code=1,
                    start_time=_session_start_time,
                    exit_reason=exit_reason,
                    error_message=error_message,
                )

            delete_status()
            delete_info()

            if __IFACE and __IFACE.requires_vif:
                with contextlib.suppress(BrokenPipeError, ValueError):
                    removeVif()

            if __HOSTAPD_MGR is not None:
                with contextlib.suppress(BrokenPipeError, ValueError):
                    __HOSTAPD_MGR.cleanup()

            sys.exit(1)


signal.signal(signal.SIGINT, receiveSignal)
signal.signal(signal.SIGTERM, receiveSignal)
signal.signal(signal.SIGUSR1, receiveWatchdogSignal)


def are_we_root() -> bool:
    """Do we have root permissions?"""
    return os.geteuid() == 0


def start(args: argparse.Namespace) -> None:
    """Main entry point for the WLAN Pi Profiler application."""
    global _session_start_time, _pcap_analysis_mode
    from datetime import timezone

    _session_start_time = datetime.now(timezone.utc).isoformat()
    _pcap_analysis_mode = getattr(args, "pcap_analysis", False)
    log = logging.getLogger(inspect.stack()[0][3])

    try:
        _start_impl(args, log)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        # Write state file for non-zero exits in live mode only
        # Skip for: normal exit (0), pytest, needs root (126), pcap analysis
        if e.code not in (0, "pytest", 126) and not _pcap_analysis_mode:
            from profiler.status import (
                get_status,
                write_last_session,
            )

            current_status = get_status()
            exit_reason = None
            error_message = None
            if current_status:
                exit_reason = current_status.get("reason")
                error_message = current_status.get("error")

            write_last_session(
                exit_status="failed",
                exit_code=1,
                start_time=_session_start_time,
                exit_reason=exit_reason,
                error_message=error_message,
            )
        raise
    except Exception as e:
        log.exception(f"Uncaught exception: {e}")
        # Only write last-session file for live mode
        if not _pcap_analysis_mode:
            from profiler.status import write_last_session

            write_last_session(
                exit_status="interrupted",
                exit_code=1,
                start_time=_session_start_time,
                exit_reason="uncaught_exception",
                error_message=str(e),
            )
        raise


def _start_impl(args: argparse.Namespace, log: logging.Logger) -> None:
    """Implementation of start() - separated for exception handling."""
    if args.pytest:
        sys.exit("pytest")

    # Only require root for live capture mode, not for pcap analysis
    if not args.pcap_analysis and not are_we_root():
        log.error("profiler must be run with root permissions... exiting...")
        log.error("Note: analyzing pcap files with --pcap does not require root")
        # Exit code 126 = "command invoked cannot execute" (standard Unix convention)
        # This is not a real session failure, so we skip writing state files for this code
        sys.exit(126)

    # Write initial status as early as possible (after root check, before tool checks)
    # This allows service monitoring to detect failures
    if not args.pcap_analysis:
        from profiler.status import ProfilerState, write_status

        write_status(state=ProfilerState.STARTING, pid=os.getpid())

    # Check required tools after arg parsing (allows -h/--help to work quickly)
    helpers.check_required_tools()

    # Check for already-running profiler instances
    try:
        import subprocess

        # Check for python processes running profiler
        # Pattern matches: /opt/wlanpi-profiler/bin/python /usr/local/bin/profiler
        result = subprocess.run(
            ["pgrep", "-f", "python.*bin/profiler"], capture_output=True, text=True
        )
        if result.returncode == 0:
            pids = result.stdout.strip().split("\n")
            current_pid = os.getpid()
            other_pids = []
            for pid_str in pids:
                try:
                    pid = int(pid_str.strip())
                    if pid == current_pid:
                        continue

                    # Check command line for 'test' subcommand or if it's the parent
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        cmdline_bytes = f.read()
                        cmdline = cmdline_bytes.decode().replace("\0", " ")

                    log.debug(f"Checking process {pid}: {cmdline}")

                    if "test" in cmdline:
                        log.debug(f"Ignoring profiler test process (PID: {pid})")
                        continue

                    # Also check parent PID
                    if pid == os.getppid():
                        log.debug(f"Ignoring parent process (PID: {pid})")
                        continue
                except (OSError, ValueError):
                    pass

                other_pids.append(str(pid))

            if other_pids:
                log.warning(
                    f"Found existing profiler process(es): {', '.join(other_pids)}"
                )
                log.warning(
                    "Another profiler instance may be running. "
                    "This could cause conflicts with interface/hostapd."
                )
                log.warning(
                    "If profiler crashed previously, you may need to: "
                    "sudo pkill -9 profiler; sudo pkill -9 hostapd"
                )
    except (OSError, subprocess.SubprocessError) as e:
        # Expected if pgrep/pkill not available or subprocess fails
        log.debug(f"Could not check for existing profiler instances: {e}")

    helpers.setup_logger(args)

    # Collect environment info into structured JSON for easy parsing
    env_info = {
        "profiler": {
            "version": __version__,
        },
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "compiler": platform.python_compiler(),
            "build": platform.python_build(),
            "executable": sys.executable,
        },
        "system": {
            "platform": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "processor": helpers.get_processor_name(),
        },
        "runtime": {
            "timestamp": datetime.now().isoformat(),
            "utc_offset": datetime.now().astimezone().strftime("%z"),
        },
    }

    # Add CPU count
    try:
        env_info["system"]["cpu_count"] = mp.cpu_count()
    except NotImplementedError:
        env_info["system"]["cpu_count"] = "unavailable"

    # Lazy import scapy to speed up -h/--help response
    try:
        import scapy  # type: ignore

        env_info["dependencies"] = {"scapy": scapy.__version__}
    except (AttributeError, ImportError) as e:
        env_info["dependencies"] = {"scapy": f"not available ({str(e)})"}

    # Log as single JSON entry for easy parsing
    import json

    log.debug("Environment: %s", json.dumps(env_info))

    # Keep simple version log for human readability
    log.info(
        "Profiler v%s | Python %s | %s %s",
        __version__,
        platform.python_version(),
        platform.system(),
        platform.machine(),
    )

    # Arguments (keep separate as it's user-provided)
    log.debug("Arguments: %s", vars(args))

    if args.oui_update:
        # run manuf oui update and exit
        sys.exit(0) if helpers.update_manuf2() else sys.exit(-1)

    # Load config first (needed for files_path)
    config, config_error = helpers.setup_config(args)
    if config is None:
        log.error("configuration setup failed... exiting...")
        from profiler.status import ProfilerState, StatusReason, write_status

        write_status(
            state=ProfilerState.FAILED,
            reason=StatusReason.CONFIG_VALIDATION,
            error=config_error or "Configuration setup failed",
        )
        sys.exit(-1)

    assert config is not None  # Help mypy understand config is not None after the check

    # Set up multi-path file saving (now with config available)
    files_paths = helpers.get_app_data_paths(args, config)
    if not args.files_path:
        args.files_path = files_paths

    # Update config with writable paths (in case original path wasn't writable)
    config["GENERAL"]["files_path"] = files_paths

    # Re-configure logger now that we have config (to pick up debug setting from config.ini)
    helpers.setup_logger(args, config)

    if args.clean and args.files:
        files_path = config["GENERAL"].get("files_path")
        clients_dir = os.path.join(str(files_path[0]), "clients")
        helpers.files_cleanup(clients_dir, args.yes)
        # Clean up status file before exit (utility command, not a real profiler run)
        from profiler.status import delete_status

        delete_status()
        sys.exit(0)

    if args.clean:
        files_path = config["GENERAL"].get("files_path")
        reports_dir = os.path.join(str(files_path[0]), "reports")
        helpers.files_cleanup(reports_dir, args.yes)
        # Clean up status file before exit (utility command, not a real profiler run)
        from profiler.status import delete_status

        delete_status()
        sys.exit(0)

    if args.list_interfaces:
        if __IFACE is None:
            log.error("List interfaces not supported on this platform")
            # Clean up status file before exit (utility command, not a real profiler run)
            from profiler.status import delete_status

            delete_status()
            sys.exit(-1)
        __IFACE.print_interface_information()
        # Clean up status file before exit (utility command, not a real profiler run)
        from profiler.status import delete_status

        delete_status()
        sys.exit(0)

    global __RUNNING_PROCESSES
    running_processes = __RUNNING_PROCESSES  # Use global list for signal handler access
    finished_processes = []
    queue: Queue[str] = Queue()
    pcap_analysis = config.get("GENERAL").get("pcap_analysis")
    parent_pid = os.getpid()
    log.debug("%s pid %s", __name__, parent_pid)

    if pcap_analysis:
        log.info(
            "not starting beacon or sniffer because user requested pcap file analysis"
        )
        helpers.verify_reporting_directories(config)

        # Lazy import scapy for pcap analysis
        import scapy  # type: ignore
        from scapy.all import rdpcap  # type: ignore

        # Validate PCAP file before analysis to prevent path traversal attacks
        log.debug("Validating PCAP file: %s", pcap_analysis)

        # Check if file exists
        if not os.path.exists(pcap_analysis):
            log.error("PCAP file does not exist: %s", pcap_analysis)
            print(f"Error: PCAP file not found: {pcap_analysis}")
            sys.exit(1)

        # Check if path is a regular file (not directory, symlink, device, etc.)
        if not os.path.isfile(pcap_analysis):
            log.error("PCAP path is not a regular file: %s", pcap_analysis)
            print(f"Error: Path is not a regular file: {pcap_analysis}")
            sys.exit(1)

        # Check file extension (only allow common PCAP formats)
        valid_extensions = (".pcap", ".pcapng", ".cap")
        if not pcap_analysis.lower().endswith(valid_extensions):
            log.error(
                "Invalid PCAP file extension: %s (must be .pcap, .pcapng, or .cap)",
                pcap_analysis,
            )
            print(
                f"Error: Invalid file extension. Must be one of: {', '.join(valid_extensions)}"
            )
            sys.exit(1)

        # Check file size (10 MB limit to prevent DoS)
        MAX_PCAP_SIZE = 10 * 1024 * 1024  # 10 MB
        try:
            file_size = os.path.getsize(pcap_analysis)
            if file_size > MAX_PCAP_SIZE:
                log.error(
                    "PCAP file too large: %d bytes (max %d MB)",
                    file_size,
                    MAX_PCAP_SIZE // (1024 * 1024),
                )
                print(
                    f"Error: PCAP file too large ({file_size} bytes). Maximum size is {MAX_PCAP_SIZE // (1024 * 1024)} MB"
                )
                sys.exit(1)
        except OSError as e:
            log.error("Error checking PCAP file size: %s", e)
            print(f"Error: Cannot access PCAP file: {e}")
            sys.exit(1)

        # Prevent path traversal - resolve to absolute path and check for suspicious patterns
        abs_path = os.path.abspath(pcap_analysis)
        if ".." in pcap_analysis:
            log.error(
                "Potential path traversal detected (.. in path): %s", pcap_analysis
            )
            print(f"Error: Path traversal patterns not allowed: {pcap_analysis}")
            sys.exit(1)

        log.info("PCAP file validation passed: %s (%d bytes)", abs_path, file_size)

        try:
            frames = rdpcap(abs_path)
        except FileNotFoundError:
            log.exception("could not find file %s", abs_path)
            print("exiting...")
            sys.exit(1)

        for frame in frames:
            # extract frames that are Association or Reassociation Request frames
            if frame.haslayer(scapy.layers.dot11.Dot11AssoReq) or frame.haslayer(
                scapy.layers.dot11.Dot11ReassoReq
            ):
                # Filter invalid/corrupted MAC addresses
                if not helpers.is_valid_mac(frame.addr2):
                    continue
                # put frame into the multiprocessing queue for the profiler to analyze
                queue.put(frame)
    else:
        valid, validation_error = helpers.validate(config)
        if valid:
            log.debug("config %s", config)
        else:
            log.error("configuration validation failed... exiting...")
            from profiler.status import ProfilerState, StatusReason, write_status

            write_status(
                state=ProfilerState.FAILED,
                reason=StatusReason.CONFIG_VALIDATION,
                error=validation_error or "Configuration validation failed",
            )
            sys.exit(-1)

        # import status functions for use throughout startup
        # status already written earlier (after root check, before tool validation)
        # ensures status file exists even if early checks fail
        from profiler.status import (
            CountryCodeError,
            ProfilerState,
            StatusReason,
            detect_country_code,
            write_status,
        )

        listen_only = config.get("GENERAL", {}).get("listen_only")

        from .fakeap import Sniffer, TxBeacons

        boot_time = datetime.now().timestamp()

        lock = mp.Lock()
        sequence_number = mp.Value("i", 0)

        iface_name = config.get("GENERAL", {}).get("interface")
        if not iface_name:
            log.error("Interface not specified in configuration")
            from profiler.status import ProfilerState, StatusReason, write_status

            write_status(
                state=ProfilerState.FAILED,
                reason=StatusReason.CONFIG_VALIDATION,
                error="Interface not specified in configuration",
            )
            sys.exit(-1)
        __IFACE.name = iface_name

        try:
            if args.no_interface_prep:
                log.warning(
                    "user provided `--noprep` argument meaning profiler will not handle staging the interface"
                )
                # get channel from `iw`
                __IFACE.no_interface_prep = True
                __IFACE.setup()

                # setup should have detected a mac address
                config["GENERAL"]["mac"] = __IFACE.mac
                # need to set channel in config for banner
                if __IFACE.channel:
                    config["GENERAL"]["channel"] = __IFACE.channel
                # need to set freq in config for banner
                if __IFACE.frequency:
                    config["GENERAL"]["frequency"] = __IFACE.frequency
                log.debug("finish interface setup with no staging ...")
            else:
                # get channel from config setup by helpers.py (either passed in via CLI option or config.ini)
                channel = int(config.get("GENERAL").get("channel"))
                freq = int(config.get("GENERAL").get("frequency"))
                if channel != 0:
                    # channel was provided, map it:
                    for freq, ch in _20MHZ_FREQUENCY_CHANNEL_MAP.items():
                        if channel == ch:
                            __IFACE.frequency = freq
                            __IFACE.channel = ch
                            break
                if freq != 0:
                    # freq was provided
                    __IFACE.channel = _20MHZ_FREQUENCY_CHANNEL_MAP.get(freq, 0)
                    if __IFACE.channel != 0:
                        __IFACE.frequency = freq
                    else:
                        raise InterfaceError(
                            "could not determine channel from frequency (%s)", freq
                        )
                # if we made it here, make sure the config matches up
                config["GENERAL"]["channel"] = __IFACE.channel
                config["GENERAL"]["frequency"] = __IFACE.frequency

                # run interface setup
                __IFACE.setup()

                # setup should have detected a mac address
                config["GENERAL"]["mac"] = __IFACE.mac

                # Check if using hostapd AP mode (before staging interface)
                ap_mode = config.get("GENERAL").get("ap_mode", False)

                if listen_only:
                    # Listen-only mode: create monitor interface for passive sniffing
                    log.debug("Staging interface for listen-only mode")
                    if __IFACE.requires_vif:
                        config["GENERAL"]["interface"] = __IFACE.mon
                    __IFACE.stage_interface_listen_only()
                    log.debug("finish interface setup and staging for listen-only...")
                elif ap_mode:
                    # Hostapd mode: set wlan0 to AP mode, create wlan0profiler for sniffing
                    log.debug("Staging interface for hostapd AP mode")
                    # Store original interface name for hostapd (wlan0)
                    config["GENERAL"]["ap_interface"] = __IFACE.name
                    if __IFACE.requires_vif:
                        # Update interface config so sniffer subprocess uses monitor interface (wlan0profiler)
                        config["GENERAL"]["interface"] = __IFACE.mon
                    __IFACE.stage_interface_hostapd()
                    log.debug("finish interface setup and staging for hostapd...")
                else:
                    # FakeAP mode: create monitor interface and stage for injection
                    if __IFACE.requires_vif:
                        # we require using a mon interface, update config so our subprocesses find it
                        config["GENERAL"]["interface"] = __IFACE.mon
                    __IFACE.stage_interface_fakeap()
                    log.debug("finish interface setup and staging ...")
        except InterfaceError as e:
            log.exception("problem interface staging ... exiting ...", exc_info=True)
            write_status(
                state=ProfilerState.FAILED,
                reason=StatusReason.INTERFACE_VALIDATION,
                error=str(e),
            )
            sys.exit(-1)

        # Detect country code AFTER interface staging (LAR for iwlwifi requires interface up)
        try:
            country_code = detect_country_code()
            log.info(f"Detected country code: {country_code}")
        except CountryCodeError as e:
            log.error(f"Failed to detect country code: {e}")
            write_status(
                state=ProfilerState.FAILED,
                reason=StatusReason.COUNTRY_CODE_DETECTION,
                error=str(e),
            )
            sys.exit(-1)

        # Validate channel for AP modes (hostapd and fakeAP) after LAR scan
        # This ensures No IR/Disabled/Radar flags have been cleared, or we exit and attempt to display a helpful message
        if not listen_only:
            try:
                __IFACE.validate_channel_for_ap(country_code)
            except InterfaceError as e:
                log.error(str(e))
                write_status(
                    state=ProfilerState.FAILED,
                    reason=StatusReason.INTERFACE_VALIDATION,
                    error=str(e),
                )
                # Clean up VIF if it was created
                if __IFACE.requires_vif and hasattr(__IFACE, "mon"):
                    removeVif()
                sys.exit(-1)

        # ap_mode already determined earlier (before interface staging)
        if listen_only:
            # In true listen-only mode, we're not running an AP
            # Override ap_mode for banner generation
            config["GENERAL"]["ap_mode"] = False
            helpers.generate_run_message(config)
            log.warning(
                "beacon process not started because user requested listen only mode"
            )

            # Note: No security configuration to log in listen-only mode
            # (we're just sniffing, not running an AP)

            # Write info file for listen_only mode
            from profiler.status import write_info

            write_status(
                state=ProfilerState.RUNNING,
                reason=StatusReason.STARTUP_COMPLETE,
                pid=os.getpid(),
            )
            write_info(
                phy=__IFACE.phy,
                channel=config["GENERAL"]["channel"],
                country_code=country_code,
                ssid=config["GENERAL"]["ssid"],
                bssid=config["GENERAL"]["mac"],
                mode="listen_only",
                monitor_interface=config["GENERAL"]["interface"],
                ap_interface=None,  # No AP interface in listen-only mode
                passphrase=None,  # No passphrase in listen-only mode
                profiler_version=__version__,
            )
        elif ap_mode:
            # NEW: Hostapd mode
            log.info("Starting in hostapd AP mode")
            from .hostapd_manager import HostapdError, HostapdManager

            global __HOSTAPD_MGR

            # In hostapd mode, sniffer should be listen-only (no TX responses)
            # Hostapd handles all TX (beacons, probe responses, auth, assoc)
            config["GENERAL"]["listen_only"] = True
            log.debug("Sniffer set to listen-only mode (hostapd handles all TX)")

            # update ssid record for sharing with other apps like FPMS for QR code generation
            helpers.update_ssid_record(config.get("GENERAL").get("ssid"))

            try:
                __HOSTAPD_MGR = HostapdManager(config["GENERAL"], country_code, log)
                __HOSTAPD_MGR.start()
                # Note: hostapd_manager.py already logs successful start, no need to log again here

                # Update config with actual BSSID from hostapd (important for MLD mode)
                if __HOSTAPD_MGR.bssid:
                    config["GENERAL"]["mac"] = __HOSTAPD_MGR.bssid

                # NOW print the banner with correct BSSID (includes security config)
                helpers.generate_run_message(config)

                # Hostapd started successfully - update status and write info file
                from profiler.status import write_info

                write_status(
                    state=ProfilerState.RUNNING,
                    reason=StatusReason.STARTUP_COMPLETE,
                    pid=os.getpid(),
                )

                write_info(
                    phy=__IFACE.phy,
                    channel=config["GENERAL"]["channel"],
                    country_code=country_code,
                    ssid=config["GENERAL"]["ssid"],
                    bssid=config["GENERAL"]["mac"],
                    mode="hostapd",
                    monitor_interface=config["GENERAL"]["interface"],
                    ap_interface=config["GENERAL"]["ap_interface"],
                    passphrase=config["GENERAL"]["passphrase"],
                    profiler_version=__version__,
                )

            except HostapdError as e:
                log.error(f"Failed to start hostapd: {e}")
                write_status(
                    state=ProfilerState.FAILED,
                    reason=StatusReason.HOSTAPD_START_FAILED,
                    error=str(e),
                )
                if __IFACE.requires_vif:
                    removeVif()
                sys.exit(1)
        else:
            # EXISTING: fakeAP mode
            log.info("Starting in legacy fakeAP mode")
            log.debug("beacon process")

            # Print banner for fakeAP mode (BSSID is interface MAC)
            helpers.generate_run_message(config)

            # update ssid record for sharing with other apps like FPMS for QR code generation
            helpers.update_ssid_record(config.get("GENERAL").get("ssid"))

            # Write info file for fakeAP mode
            from profiler.status import write_info

            write_status(
                state=ProfilerState.RUNNING,
                reason=StatusReason.STARTUP_COMPLETE,
                pid=os.getpid(),
            )
            write_info(
                phy=__IFACE.phy,
                channel=config["GENERAL"]["channel"],
                country_code=country_code,
                ssid=config["GENERAL"]["ssid"],
                bssid=config["GENERAL"]["mac"],
                mode="fake_ap",
                monitor_interface=config["GENERAL"]["interface"],
                ap_interface=config["GENERAL"][
                    "interface"
                ],  # Same interface for fake_ap
                passphrase=config["GENERAL"]["passphrase"],
                profiler_version=__version__,
            )

            # TxBeacons is a Process subclass, so instantiate it directly (not as target)
            txbeacons = TxBeacons(config, boot_time, lock, sequence_number)
            running_processes.append(txbeacons)
            txbeacons.start()
            __PIDS.append(("txbeacons", txbeacons.pid))  # type: ignore

        log.debug("sniffer process")
        # Sniffer is a Process subclass, so instantiate it directly (not as target)
        sniffer = Sniffer(config, boot_time, lock, sequence_number, queue, args)
        running_processes.append(sniffer)
        sniffer.start()
        __PIDS.append(("sniffer", sniffer.pid))  # type: ignore

    from .profiler import Profiler

    log.debug("profiler process")
    profiler = mp.Process(name="profiler", target=Profiler, args=(config, queue))
    running_processes.append(profiler)
    profiler.start()
    __PIDS.append(("profiler", profiler.pid))  # type: ignore

    shutdown = False

    # keep main process alive until all subprocesses are finished or closed
    while running_processes:
        sleep(0.1)
        # Iterate over copy to avoid modifying list during iteration (race condition fix)
        for process in running_processes[:]:
            # if exitcode is None, it has not stopped yet.
            if process.exitcode is not None:
                # Check if this is an abnormal exit (non-zero exit code)
                if process.exitcode != 0:
                    # Interpret exit code for better diagnostics
                    if process.exitcode == -9:
                        error_detail = f"Process {process.name} was killed (SIGKILL)"
                    elif process.exitcode == -15:
                        error_detail = f"Process {process.name} terminated (SIGTERM)"
                    elif process.exitcode == -11:
                        error_detail = f"Process {process.name} crashed (SIGSEGV)"
                    elif process.exitcode < 0:
                        error_detail = f"Process {process.name} killed by signal {-process.exitcode}"
                    else:
                        error_detail = f"Process {process.name} exited with code {process.exitcode}"

                    log.error(error_detail)
                    log.error("To investigate:")
                    log.error(
                        "  - Enable debug: Add 'debug: True' to /etc/wlanpi-profiler/config.ini [GENERAL] section"
                    )
                    # Only suggest journalctl if running as systemd service
                    if os.environ.get("JOURNAL_STREAM") or os.environ.get(
                        "INVOCATION_ID"
                    ):
                        log.error(
                            "  - View journal logs: journalctl -u wlanpi-profiler --no-pager"
                        )

                    from profiler.status import (
                        ProfilerState,
                        StatusReason,
                        get_status,
                        write_last_session,
                        write_status,
                    )

                    write_status(
                        state=ProfilerState.FAILED,
                        reason=(
                            StatusReason.HOSTAPD_CRASHED
                            if process.name == "hostapd"
                            else StatusReason.UNKNOWN_ERROR
                        ),
                        pid=os.getpid(),
                        error=error_detail,
                    )

                    # Write last-session file before cleanup
                    current_status = get_status()
                    exit_reason = None
                    if current_status:
                        exit_reason = current_status.get("reason")

                    if _session_start_time:
                        write_last_session(
                            exit_status="failed",
                            exit_code=1,
                            start_time=_session_start_time,
                            exit_reason=exit_reason,
                            error_message=error_detail,
                        )

                if __IFACE.requires_vif and not __IFACE.removed:
                    removeVif()
                    if os.path.isfile(SSID_TMP_FILE):
                        os.remove(SSID_TMP_FILE)

                if __HOSTAPD_MGR is not None:
                    __HOSTAPD_MGR.cleanup()

                from profiler.status import delete_info, delete_status

                delete_status()
                delete_info()
                log.debug("shutdown %s process (%s)", process.name, process.exitcode)
                running_processes.remove(process)
                finished_processes.append(process)
                shutdown = True

            if shutdown:
                process.kill()
                process.join()
