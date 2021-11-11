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
import sys
from datetime import datetime
from multiprocessing import Queue
from signal import SIGINT, signal

# third party imports
import scapy  # type: ignore
from scapy.all import rdpcap  # type: ignore

# app imports
from . import helpers
from .__version__ import __version__
from .interface import Interface, InterfaceError

__pids = []
__pids.append(("main", os.getpid()))
__iface = Interface()


def signal_handler(signum, frame):
    """Handle noisy keyboardinterrupt"""
    if signum == 2:
        for name, pid in __pids:
            # We only want to print exit messages once as multiple processes close
            if name == "main" and os.getpid() == pid:
                if __iface.requires_monitor_interface:
                    print(
                        "Detected SIGINT or Control-C ... Removing monitor interface ..."
                    )
                    __iface.reset_interface()
                    print("Exiting ...")
                else:
                    print("Detected SIGINT or Control-C ... Exiting ...")
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
        __iface.print_interface_information()
        sys.exit(0)

    signal(SIGINT, signal_handler)

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
        __iface.name = iface_name

        try:
            if args.no_interface_prep:
                log.warning(
                    "user provided `--noprep` argument meaning profiler will not handle staging the interface"
                )
                # get channel from `iw`
                __iface.no_interface_prep = True
                __iface.setup()
                if __iface.channel:
                    config["GENERAL"]["channel"] = __iface.channel
                log.debug("finish interface setup with no staging ...")
            else:
                # get channel from config (CLI option or config.ini)
                channel = int(config.get("GENERAL").get("channel"))
                __iface.channel = channel
                __iface.setup()
                if __iface.requires_monitor_interface:
                    # we require using a mon interface, update config so our subprocesses know to use it
                    config["GENERAL"]["interface"] = __iface.mon
                __iface.stage_interface()
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
            txbeacons = mp.Process(
                name="txbeacons",
                target=TxBeacons,
                args=(config, boot_time, lock, sequence_number),
            )
            processes.append(txbeacons)
            txbeacons.start()
            __pids.append(("txbeacons", txbeacons.pid))  # type: ignore

        log.debug("sniffer process")
        sniffer = mp.Process(
            name="sniffer",
            target=Sniffer,
            args=(config, boot_time, lock, sequence_number, queue, args),
        )
        processes.append(sniffer)
        sniffer.start()
        __pids.append(("sniffer", sniffer.pid))  # type: ignore

    from .profiler import Profiler

    log.debug("profiler process")
    profiler = mp.Process(name="profiler", target=Profiler, args=(config, queue))
    processes.append(profiler)
    profiler.start()
    __pids.append(("profiler", profiler.pid))  # type: ignore

    shutdown = False

    # keep main process alive until all subprocesses are finished or closed
    while processes:
        for process in processes:
            if shutdown:
                process.kill()
            if process.exitcode is not None:
                log.debug(process)
                processes.remove(process)
                finished_processes.append(process)
                shutdown = True
