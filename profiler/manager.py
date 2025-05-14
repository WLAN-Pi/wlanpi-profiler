# -*- coding: utf-8 -*-
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com


"""
profiler.manager
~~~~~~~~~~~~~~~~

handle profiler
"""

import argparse
import inspect
import logging
import multiprocessing as mp
import os
import platform
import signal
import sys
from datetime import datetime
from logging.handlers import QueueListener
from multiprocessing import Queue
from time import sleep

from . import helpers
from .__version__ import __version__
from .constants import _20MHZ_FREQUENCY_CHANNEL_MAP, SSID_TMP_FILE
from .interface import Interface, InterfaceError

# things break when we use spawn
# from multiprocessing import set_start_method
# set_start_method("spawn")


__PIDS = []
__PIDS.append(("main", os.getpid()))
__IFACE = None


def removeVif():
    """Remove the vif we created if exists"""
    if __IFACE is not None:
        if __IFACE.requires_vif and not __IFACE.removed:
            log = logging.getLogger(inspect.stack()[0][3])
            log.debug("Removing monitor vif ...")
            __IFACE.reset_interface()
            __IFACE.removed = True


def receiveSignal(signum, _frame):
    """Handle noisy keyboardinterrupt"""
    for name, pid in __PIDS:
        # We only want to print exit messages once as multiple processes close
        if name == "main" and os.getpid() == pid:
            if os.path.isfile(SSID_TMP_FILE):
                os.remove(SSID_TMP_FILE)
            if __IFACE is not None:
                if __IFACE.requires_vif:
                    removeVif()
            if signum == 2:
                print("\nDetected SIGINT or Control-C ...")
            if signum == 15:
                print("Detected SIGTERM ...")

        # if name is not "main":
        #     sys.exit(signum)


signal.signal(signal.SIGINT, receiveSignal)
signal.signal(signal.SIGTERM, receiveSignal)


def are_we_root() -> bool:
    """Do we have root permissions?"""
    if os.geteuid() == 0:
        return True
    else:
        return False


def start(args: argparse.Namespace):
    """I didn't come here to tell you how this is going to end. I came here to tell you how it's going to begin."""
    global __IFACE
    log = logging.getLogger(inspect.stack()[0][3])

    if args.pytest:
        sys.exit("pytest")
    log.debug("args: %s", args)

    info = {
        "app_version": __version__,
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_compiler": platform.python_compiler(),
        "python_build": platform.python_build(),
        "python_executable": sys.executable,
        "cpu_count": os.cpu_count(),
        "current_time": datetime.now().isoformat(),
    }

    try:
        utc_offset = datetime.now().astimezone().utcoffset().total_seconds() / 3600
        info["utc_offset"] = f"{utc_offset:.0f}"
    except Exception:
        info["utc_offset"] = "unknown"

    for k, v in info.items():
        log.debug("%s: %s", k, v)

    if not args.pcap_analysis:
        if "linux" not in sys.platform:
            log.error(
                "Tx mode is only supported on Linux with an injection capable NIC... exiting..."
            )
            sys.exit(-1)

        helpers.check_tools()

        if not are_we_root():
            log.error("profiler must be run with root permissions... exiting...")
            sys.exit(-1)

        __IFACE = Interface()

    class ScapyWarningFilter(logging.Filter):
        def filter(self, record):
            return "No IPv4 address found on" not in record.getMessage()

    scapy_runtime_logger = logging.getLogger("scapy.runtime")
    scapy_runtime_logger.addFilter(ScapyWarningFilter())

    import scapy  # type: ignore
    from scapy.all import rdpcap  # type: ignore

    scapy_version = ""
    try:
        scapy_version = scapy.__version__
        log.debug("scapy version is %s", scapy_version)
    except AttributeError:
        log.exception("could not get version information from scapy.__version__")

    if args.oui_update:
        # run manuf oui update and exit
        sys.exit(0) if helpers.update_manuf2() else sys.exit(-1)

    config = helpers.setup_config(args)

    if args.clean and args.files:
        clients_dir = os.path.join(config["GENERAL"].get("files_path"), "clients")
        helpers.files_cleanup(clients_dir, args.yes)
        sys.exit(0)

    if args.clean:
        reports_dir = os.path.join(config["GENERAL"].get("files_path"), "reports")
        helpers.files_cleanup(reports_dir, args.yes)
        sys.exit(0)

    if args.list_interfaces:
        if __IFACE is not None:
            __IFACE.print_interface_information()
            sys.exit(0)
        else:
            log.error("List interfaces not supported on this platform")
            sys.exit(-1)

    running_processes = []
    finished_processes = []
    queue: "Queue[str]" = Queue()
    pcap_analysis = config.get("GENERAL").get("pcap_analysis")
    parent_pid = os.getpid()
    log.debug("%s pid %s", __name__, parent_pid)

    if pcap_analysis:
        log.info(
            "not starting beacon or sniffer because user requested pcap file analysis"
        )
        helpers.verify_reporting_directories(config)
        try:
            frames = rdpcap(pcap_analysis)
        except FileNotFoundError:
            log.exception("could not find file %s", pcap_analysis)
            print("exiting...")
            sys.exit(-1)

        for frame in frames:
            # extract frames that are Association or Reassociation Request frames
            if frame.haslayer(scapy.layers.dot11.Dot11AssoReq) or frame.haslayer(
                scapy.layers.dot11.Dot11ReassoReq
            ):
                # put frame into the multiprocessing queue for the profiler to analyze
                queue.put(frame)
    else:
        if helpers.validate(config):
            log.debug("config %s", config)
        else:
            log.error("configuration validation failed... exiting...")
            sys.exit(-1)

        listen_only = config.get("GENERAL").get("listen_only")

        from .fakeap import Sniffer, TxBeacons

        boot_time = datetime.now().timestamp()

        lock = mp.Lock()
        sequence_number = mp.Value("i", 0)

        iface_name = config.get("GENERAL").get("interface")
        __IFACE.name = iface_name

        try:
            if args.no_interface_prep:
                log.warning(
                    "we got `--noprep` argument meaning profiler will not handle staging the interface for Tx"
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
                log.debug("finish interface setup with no staging for Tx ...")
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

                if __IFACE.requires_vif:
                    # we require using a mon interface, update config so our subprocesses find it
                    config["GENERAL"]["interface"] = __IFACE.mon
                __IFACE.stage_interface()
                log.debug("finish interface setup and staging ...")
        except InterfaceError:
            log.exception("problem interface staging ... exiting ...", exc_info=True)
            sys.exit(-1)

        helpers.generate_run_message(config)

        if listen_only:
            log.warning(
                "beacon process not started because user requested listen only mode"
            )
        else:
            log.debug("beacon process")
            # update ssid record for sharing with other apps like FPMS for QR code generation
            helpers.update_ssid_record(config.get("GENERAL").get("ssid"))
            txbeacons = mp.Process(
                name="txbeacons",
                target=TxBeacons,
                args=(config, boot_time, lock, sequence_number),
            )
            running_processes.append(txbeacons)
            txbeacons.start()
            __PIDS.append(("txbeacons", txbeacons.pid))  # type: ignore

        log.debug("sniffer process")
        sniffer = mp.Process(
            name="sniffer",
            target=Sniffer,
            args=(config, boot_time, lock, sequence_number, queue, args),
        )
        running_processes.append(sniffer)
        sniffer.start()
        __PIDS.append(("sniffer", sniffer.pid))  # type: ignore

    from .profiler import Profiler

    log.debug("profiler process")

    log_queue = Queue(-1)
    logger = logging.getLogger()
    listener = QueueListener(log_queue, *logger.handlers)
    listener.start()

    profiler = mp.Process(
        name="profiler", target=Profiler, args=(config, queue, log_queue)
    )
    running_processes.append(profiler)
    profiler.start()
    __PIDS.append(("profiler", profiler.pid))  # type: ignore

    shutdown = False

    # keep main process alive until all subprocesses are finished or closed
    while running_processes:
        sleep(0.1)
        for process in running_processes:
            # if exitcode is None, it has not stopped yet.
            if process.exitcode is not None:
                if __IFACE is not None:
                    if __IFACE.requires_vif and not __IFACE.removed:
                        removeVif()
                        # nesting this here is ugly but works
                        if os.path.isfile(SSID_TMP_FILE):
                            os.remove(SSID_TMP_FILE)
                log.debug("shutdown %s process (%s)", process.name, process.exitcode)
                running_processes.remove(process)
                finished_processes.append(process)
                shutdown = True

            if shutdown:
                process.kill()
                process.join()
