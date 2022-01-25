# -*- coding: utf-8 -*-
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2020-2021 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com


"""
profiler.manager
~~~~~~~~~~~~~~~~

handle profiler
"""

# standard library imports
import argparse
import inspect
import logging
import multiprocessing as mp
import os
import platform
import signal
import sys
from datetime import datetime
from multiprocessing import Queue

# third party imports
import scapy  # type: ignore
from scapy.all import rdpcap  # type: ignore

# app imports
from . import helpers
from .__version__ import __version__
from .constants import _20MHZ_FREQUENCY_CHANNEL_MAP
from .interface import Interface, InterfaceError

__PIDS = []
__PIDS.append(("main", os.getpid()))
__IFACE = Interface()


def removeVif():
    """Remove the vif we created if exists"""
    if __IFACE.requires_vif and not __IFACE.removed:
        log = logging.getLogger(inspect.stack()[0][3])
        log.debug("Removing monitor vif ...")
        __IFACE.reset_interface()
        __IFACE.removed = True


def receiveSignal(signum, _frame):
    """Handle noisy keyboardinterrupt"""
    if signum == 2:
        for name, pid in __PIDS:
            # We only want to print exit messages once as multiple processes close
            if name == "main" and os.getpid() == pid:
                print("Detected SIGINT or Control-C ...")
                if __IFACE.requires_vif:
                    removeVif()
        sys.exit(2)


def are_we_root() -> bool:
    """Do we have root permissions?"""
    if os.geteuid() == 0:
        return True
    else:
        return False


def start(args: argparse.Namespace):
    """Begin work"""
    log = logging.getLogger(inspect.stack()[0][3])

    if args.pytest:
        sys.exit("pytest")

    if not are_we_root():
        log.error("profiler must be run with root permissions... exiting...")
        sys.exit(-1)

    helpers.setup_logger(args)

    log.debug("%s version %s", __name__.split(".")[0], __version__)
    log.debug("python platform version is %s", platform.python_version())
    scapy_version = ""
    try:
        scapy_version = scapy.__version__
        log.debug("scapy version is %s", scapy_version)
    except AttributeError:
        log.exception("could not get version information from scapy.__version__")
        log.debug("args: %s", args)

    if args.oui_update:
        # run manuf oui update and exit
        sys.exit(0) if helpers.update_manuf() else sys.exit(-1)

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
        __IFACE.print_interface_information()
        sys.exit(0)

    signal.signal(signal.SIGINT, receiveSignal)

    processes = []
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
            processes.append(txbeacons)
            txbeacons.start()
            __PIDS.append(("txbeacons", txbeacons.pid))  # type: ignore

        log.debug("sniffer process")
        sniffer = mp.Process(
            name="sniffer",
            target=Sniffer,
            args=(config, boot_time, lock, sequence_number, queue, args),
        )
        processes.append(sniffer)
        sniffer.start()
        __PIDS.append(("sniffer", sniffer.pid))  # type: ignore

    from .profiler import Profiler

    log.debug("profiler process")
    profiler = mp.Process(name="profiler", target=Profiler, args=(config, queue))
    processes.append(profiler)
    profiler.start()
    __PIDS.append(("profiler", profiler.pid))  # type: ignore

    shutdown = False

    # keep main process alive until all subprocesses are finished or closed
    while processes:
        for process in processes:
            if shutdown:
                process.kill()
            if process.exitcode is not None:
                if __IFACE.requires_vif and not __IFACE.removed:
                    removeVif()
                log.debug(process)
                processes.remove(process)
                finished_processes.append(process)
                shutdown = True
