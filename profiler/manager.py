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
from datetime import UTC, datetime
from multiprocessing import Queue
from time import sleep
from typing import Any

from . import helpers
from .__version__ import __version__
from .constants import _20MHZ_FREQUENCY_CHANNEL_MAP, SSID_TMP_FILE

Interface: Any = None
InterfaceError: Any = Exception
if sys.platform.startswith("linux"):
    with contextlib.suppress(ImportError):
        from .interface import Interface, InterfaceError


__PIDS: list[tuple[str, int | None]] = []
__PIDS.append(("main", os.getpid()))
__IFACE: Any = Interface() if Interface is not None else None
__HOSTAPD_MGR: Any = None
__RUNNING_PROCESSES: list[mp.Process] = []

_session_start_time: str = ""
_read_only_mode: bool = False


def removeVif() -> None:
    """Remove the vif we created and restore the primary interface"""
    if (
        __IFACE
        and __IFACE.name
        and not __IFACE.removed
        and not __IFACE.no_interface_prep
    ):
        log = logging.getLogger(inspect.stack()[0][3])
        log.debug("Restoring interface ...")
        __IFACE.reset_interface()
        __IFACE.removed = True


def _shutdown(
    exit_code: int,
    exit_status: str,
    keep_status: bool = False,
    error_message: str | None = None,
) -> None:
    """Terminate children, stop hostapd, restore the interface, then exit.

    Shared by the SIGINT/SIGTERM and hostapd-watchdog handlers.
    """
    if __HOSTAPD_MGR is not None:
        __HOSTAPD_MGR._watchdog_stop.set()

    log = logging.getLogger("manager")
    for process in __RUNNING_PROCESSES[:]:
        try:
            log.debug(f"Terminating process {process.name} (PID: {process.pid})")
            process.terminate()
            process.join(timeout=2)
            if process.is_alive():
                log.debug(f"Force killing process {process.name} (PID: {process.pid})")
                process.kill()
                process.join(timeout=1)
        except (OSError, ProcessLookupError) as e:
            with contextlib.suppress(BrokenPipeError, ValueError):
                log.debug(f"Error terminating process {process.name}: {e}")
        except (BrokenPipeError, ValueError):
            pass

    if _read_only_mode:
        os._exit(exit_code)

    # Stop hostapd before restoring the primary interface, so the type change
    # is not attempted while hostapd still owns the AP vif.
    if __HOSTAPD_MGR is not None:
        with contextlib.suppress(BrokenPipeError, ValueError):
            __HOSTAPD_MGR.cleanup()

    if __IFACE and __IFACE.name:
        with contextlib.suppress(BrokenPipeError, ValueError):
            removeVif()

    with contextlib.suppress(OSError):
        os.remove(SSID_TMP_FILE)

    from profiler.status import (
        delete_info,
        delete_status,
        get_status,
        write_last_session,
    )

    exit_reason = None
    if exit_status == "failed":
        current_status = get_status()
        if current_status:
            exit_reason = current_status.get("reason")
            error_message = error_message or current_status.get("error")

    if _session_start_time:
        write_last_session(
            exit_status=exit_status,
            exit_code=0 if exit_status == "success" else 1,
            start_time=_session_start_time,
            exit_reason=exit_reason,
            error_message=error_message,
        )

    if not keep_status:
        delete_status()
        delete_info()

    sys.exit(exit_code)


def receiveSignal(signum: int, _frame: Any) -> None:
    """Handle noisy keyboardinterrupt"""
    for name, pid in __PIDS:
        if name == "main" and os.getpid() == pid:
            try:
                if signum == 2:
                    print("\nDetected SIGINT or Control-C ...")
                if signum == 15:
                    print("Detected SIGTERM ...")
            except BrokenPipeError:
                pass

            _shutdown(0 if signum in (2, 15) else 1, "success")


def receiveWatchdogSignal(_signum: int, _frame: Any) -> None:
    """Handle SIGUSR1 from hostapd watchdog indicating hostapd failure.

    This is only triggered by the watchdog thread when hostapd dies unexpectedly
    or fails during startup. Always exits with code 1 indicating error.
    """
    if __HOSTAPD_MGR is not None and __HOSTAPD_MGR._watchdog_stop.is_set():
        return

    for name, pid in __PIDS:
        if name == "main" and os.getpid() == pid:
            with contextlib.suppress(BrokenPipeError):
                print("Hostapd watchdog detected failure, shutting down...")
            _shutdown(1, "failed", keep_status=True)


signal.signal(signal.SIGINT, receiveSignal)
signal.signal(signal.SIGTERM, receiveSignal)
signal.signal(signal.SIGUSR1, receiveWatchdogSignal)


def are_we_root() -> bool:
    """Do we have root permissions?"""
    return os.geteuid() == 0


def apply_ap_capability_gate(
    general: dict[str, Any], caps: dict[str, bool], iface: Any, log: logging.Logger
) -> None:
    """Downgrade 11ax/11be to what the phy can actually do in AP mode.

    hostapd 2.12 exits ("MLD: Not supported by the driver") if asked for
    ieee80211be on a non-EHT phy (MT7921, MT7612U, ...). Mutates ``general``.
    """
    if not general.get("he_disabled") and not caps["he"]:
        log.warning(
            "%s (%s) has no 802.11ax AP support; auto-disabling 11ax and 11be",
            iface.name,
            iface.driver,
        )
        general["he_disabled"] = True
        general["be_disabled"] = True
    elif not general.get("be_disabled") and not caps["eht"]:
        log.warning(
            "%s (%s) has no 802.11be AP support; auto-disabling 11be",
            iface.name,
            iface.driver,
        )
        general["be_disabled"] = True


def start(args: argparse.Namespace) -> None:
    """Main entry point for the WLAN Pi Profiler application."""
    global _session_start_time, _read_only_mode

    _session_start_time = datetime.now(UTC).isoformat()
    _read_only_mode = bool(
        getattr(args, "pcap_analysis", False) or getattr(args, "list_interfaces", False)
    )
    log = logging.getLogger(inspect.stack()[0][3])

    try:
        _start_impl(args, log)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        if e.code not in (0, "pytest", 126) and not _read_only_mode:
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
        if not _read_only_mode:
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

    read_only = args.pcap_analysis or args.list_interfaces

    if not read_only and not are_we_root():
        log.error("profiler must be run with root permissions... exiting...")
        log.error("Note: --pcap and --list-interfaces do not require root")
        sys.exit(126)

    if not read_only:
        from profiler.status import ProfilerState, write_status

        write_status(state=ProfilerState.STARTING, pid=os.getpid())

    if args.list_interfaces:
        helpers.check_required_tools(
            required=helpers.LIVE_REQUIRED_TOOLS, optional=[], record_status=False
        )
    elif args.pcap_analysis or args.clean or args.oui_update:
        helpers.check_required_tools(required=helpers.PCAP_REQUIRED_TOOLS, optional=[])
    else:
        helpers.check_required_tools()

    try:
        import subprocess

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

                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        cmdline_bytes = f.read()
                        cmdline = cmdline_bytes.decode().replace("\0", " ")

                    log.debug(f"Checking process {pid}: {cmdline}")

                    if "test" in cmdline:
                        log.debug(f"Ignoring profiler test process (PID: {pid})")
                        continue

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
        log.debug(f"Could not check for existing profiler instances: {e}")

    helpers.setup_logger(args)

    env_info: dict[str, Any] = {
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

    try:
        env_info["system"]["cpu_count"] = mp.cpu_count()
    except NotImplementedError:
        env_info["system"]["cpu_count"] = "unavailable"

    try:
        import scapy

        env_info["dependencies"] = {"scapy": scapy.__version__}
    except (AttributeError, ImportError) as e:
        env_info["dependencies"] = {"scapy": f"not available ({e!s})"}

    import json

    log.debug("Environment: %s", json.dumps(env_info))

    log.info(
        "Profiler v%s | Python %s | %s %s",
        __version__,
        platform.python_version(),
        platform.system(),
        platform.machine(),
    )

    log.debug("Arguments: %s", vars(args))

    if args.list_interfaces:
        if __IFACE is None:
            log.error("List interfaces not supported on this platform")
            sys.exit(-1)
        __IFACE.print_interface_information()
        sys.exit(0)

    if args.oui_update:
        from profiler.status import delete_status

        success = helpers.update_manuf2()
        delete_status()
        sys.exit(0) if success else sys.exit(-1)

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

    assert config is not None

    files_paths = helpers.get_app_data_paths(args, config)
    if not args.files_path:
        args.files_path = files_paths

    config["GENERAL"]["files_path"] = files_paths

    helpers.setup_logger(args, config)

    if args.clean and args.files:
        files_path = config["GENERAL"].get("files_path")
        clients_dir = os.path.join(str(files_path[0]), "clients")
        helpers.files_cleanup(clients_dir, args.yes)
        from profiler.status import delete_status

        delete_status()
        sys.exit(0)

    if args.clean:
        files_path = config["GENERAL"].get("files_path")
        reports_dir = os.path.join(str(files_path[0]), "reports")
        helpers.files_cleanup(reports_dir, args.yes)
        from profiler.status import delete_status

        delete_status()
        sys.exit(0)

    global __RUNNING_PROCESSES
    running_processes = __RUNNING_PROCESSES
    finished_processes = []
    queue: Queue[Any] = Queue()
    pcap_analysis = (config.get("GENERAL") or {}).get("pcap_analysis")
    parent_pid = os.getpid()
    log.debug("%s pid %s", __name__, parent_pid)

    if pcap_analysis:
        log.info(
            "not starting beacon or sniffer because user requested pcap file analysis"
        )
        helpers.verify_reporting_directories(config)

        import scapy
        from scapy.all import rdpcap

        log.debug("Validating PCAP file: %s", pcap_analysis)

        if not os.path.exists(pcap_analysis):
            log.error("PCAP file does not exist: %s", pcap_analysis)
            print(f"Error: PCAP file not found: {pcap_analysis}")
            sys.exit(1)

        if not os.path.isfile(pcap_analysis):
            log.error("PCAP path is not a regular file: %s", pcap_analysis)
            print(f"Error: Path is not a regular file: {pcap_analysis}")
            sys.exit(1)

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

        MAX_PCAP_SIZE = 10 * 1024 * 1024
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
            if frame.haslayer(scapy.layers.dot11.Dot11AssoReq) or frame.haslayer(
                scapy.layers.dot11.Dot11ReassoReq
            ):
                if (
                    not helpers.is_valid_mac(frame.addr2)
                    or frame[scapy.layers.dot11.Dot11].proto != 0
                ):
                    continue
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

        ap_mode = (config.get("GENERAL") or {}).get("ap_mode", False)
        unsupported = __IFACE.monitor_unsupported()
        if not unsupported and not listen_only and not ap_mode:
            unsupported = __IFACE.fakeap_unsupported()
        if unsupported:
            log.error(unsupported)
            write_status(
                state=ProfilerState.FAILED,
                reason=StatusReason.INTERFACE_VALIDATION,
                error=unsupported,
            )
            sys.exit(-1)

        try:
            if args.no_interface_prep:
                log.warning(
                    "user provided `--noprep` argument meaning profiler will not handle staging the interface"
                )
                __IFACE.no_interface_prep = True
                __IFACE.setup()

                config["GENERAL"]["mac"] = __IFACE.mac
                if __IFACE.channel:
                    config["GENERAL"]["channel"] = __IFACE.channel
                if __IFACE.frequency:
                    config["GENERAL"]["frequency"] = __IFACE.frequency
                log.debug("finish interface setup with no staging ...")
            else:
                channel = int((config.get("GENERAL") or {}).get("channel") or 0)
                freq = int((config.get("GENERAL") or {}).get("frequency") or 0)
                if channel != 0:
                    for freq, ch in _20MHZ_FREQUENCY_CHANNEL_MAP.items():
                        if channel == ch:
                            __IFACE.frequency = freq
                            __IFACE.channel = ch
                            break
                if freq != 0:
                    __IFACE.channel = _20MHZ_FREQUENCY_CHANNEL_MAP.get(freq, 0)
                    if __IFACE.channel != 0:
                        __IFACE.frequency = freq
                    else:
                        raise InterfaceError(
                            "could not determine channel from frequency (%s)", freq
                        )
                config["GENERAL"]["channel"] = __IFACE.channel
                config["GENERAL"]["frequency"] = __IFACE.frequency

                __IFACE.setup()

                config["GENERAL"]["mac"] = __IFACE.mac

                if listen_only:
                    log.debug("Staging interface for listen-only mode")
                    if __IFACE.requires_vif:
                        config["GENERAL"]["interface"] = __IFACE.mon
                    __IFACE.stage_interface_listen_only()
                    log.debug("finish interface setup and staging for listen-only...")
                elif ap_mode:
                    log.debug("Staging interface for hostapd AP mode")
                    config["GENERAL"]["ap_interface"] = __IFACE.name
                    if __IFACE.requires_vif:
                        config["GENERAL"]["interface"] = __IFACE.mon
                    __IFACE.stage_interface_hostapd()
                    log.debug("finish interface setup and staging for hostapd...")
                else:
                    __IFACE.stage_interface_fakeap()
                    config["GENERAL"]["interface"] = __IFACE.mon or __IFACE.name
                    log.debug("finish interface setup and staging ...")
        except InterfaceError as e:
            log.exception("problem interface staging ... exiting ...", exc_info=True)
            write_status(
                state=ProfilerState.FAILED,
                reason=StatusReason.INTERFACE_VALIDATION,
                error=str(e),
            )
            removeVif()
            sys.exit(-1)

        try:
            country_code = detect_country_code(__IFACE.phy)
            log.info(f"Detected country code: {country_code}")
        except CountryCodeError as e:
            log.error(f"Failed to detect country code: {e}")
            write_status(
                state=ProfilerState.FAILED,
                reason=StatusReason.COUNTRY_CODE_DETECTION,
                error=str(e),
            )
            removeVif()
            sys.exit(-1)

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
                removeVif()
                sys.exit(-1)

        if listen_only:
            config["GENERAL"]["ap_mode"] = False
            helpers.generate_run_message(config)
            log.warning(
                "beacon process not started because user requested listen only mode"
            )

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
                ap_interface=None,
                passphrase=None,
                profiler_version=__version__,
            )
        elif ap_mode:
            log.info("Starting in hostapd AP mode")
            from .hostapd_manager import HostapdError, HostapdManager

            global __HOSTAPD_MGR

            config["GENERAL"]["listen_only"] = True
            log.debug("Sniffer set to listen-only mode (hostapd handles all TX)")

            helpers.update_ssid_record((config.get("GENERAL") or {}).get("ssid") or "")

            apply_ap_capability_gate(
                config["GENERAL"], __IFACE.get_ap_capabilities(), __IFACE, log
            )

            try:
                __HOSTAPD_MGR = HostapdManager(config["GENERAL"], country_code, log)
                __HOSTAPD_MGR.start()

                if __HOSTAPD_MGR.bssid:
                    config["GENERAL"]["mac"] = __HOSTAPD_MGR.bssid

                helpers.generate_run_message(config)

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
                if __HOSTAPD_MGR is not None:
                    __HOSTAPD_MGR.cleanup()
                removeVif()
                sys.exit(1)
        else:
            log.info("Starting in legacy fakeAP mode")
            log.debug("beacon process")

            helpers.generate_run_message(config)

            helpers.update_ssid_record((config.get("GENERAL") or {}).get("ssid") or "")

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
                ap_interface=config["GENERAL"]["interface"],
                passphrase=config["GENERAL"]["passphrase"],
                profiler_version=__version__,
            )

            txbeacons = TxBeacons(config, boot_time, lock, sequence_number)
            running_processes.append(txbeacons)
            txbeacons.start()
            __PIDS.append(("txbeacons", txbeacons.pid))

        log.debug("sniffer process")
        sniffer = Sniffer(config, boot_time, lock, sequence_number, queue, args)
        running_processes.append(sniffer)
        sniffer.start()
        __PIDS.append(("sniffer", sniffer.pid))

    from .profiler import Profiler

    log.debug("profiler process")
    profiler = mp.Process(name="profiler", target=Profiler, args=(config, queue))
    running_processes.append(profiler)
    profiler.start()
    __PIDS.append(("profiler", profiler.pid))

    shutdown = False
    session_failed = False

    while running_processes:
        sleep(0.1)
        for process in running_processes[:]:
            if process.exitcode is not None:
                if process.exitcode != 0:
                    session_failed = True
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

                if __HOSTAPD_MGR is not None:
                    __HOSTAPD_MGR.cleanup()

                if __IFACE and __IFACE.name and not __IFACE.removed:
                    removeVif()

                with contextlib.suppress(OSError):
                    os.remove(SSID_TMP_FILE)

                from profiler.status import delete_info, delete_status

                if not session_failed:
                    delete_status()
                    delete_info()
                log.debug("shutdown %s process (%s)", process.name, process.exitcode)
                running_processes.remove(process)
                finished_processes.append(process)
                shutdown = True

            if shutdown:
                process.kill()
                process.join()

    if session_failed:
        sys.exit(1)
