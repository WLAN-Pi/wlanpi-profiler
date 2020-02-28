#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
profiler2
~~~~~~~~~

py3 version of the WLAN Pi profiler
"""

import os
import platform
import sys

# hard set no support for non linux platforms
if "linux" not in sys.platform:
    sys.exit("{0} only works on Linux... exiting...".format(os.path.basename(__file__)))

# hard set no support for python < v3.6
if sys.version_info < (3, 6):
    sys.exit(
        "exiting... {0} requires Python v3.6+...\nyou're running with {1}".format(
            os.path.basename(__file__), platform.python_version()
        )
    )

# standard library imports
from datetime import datetime
import inspect
import logging
import multiprocessing as mp
import signal
from time import time, sleep

# app imports
from . import helpers

# third party imports
from scapy.all import rdpcap


def main() -> None:
    signal.signal(signal.SIGINT, signal_handler)
    parser = helpers.setup_parser()
    args = parser.parse_args()
    helpers.setup_logger(args)

    log = logging.getLogger(inspect.stack()[0][3])
    log.info(f"args {args}")
    log.info(f"python version: {sys.version}")

    config = helpers.setup_config(args)

    interface = config.get("GENERAL", "interface")
    ssid = config.get("GENERAL", "ssid")
    channel = int(config.get("GENERAL", "channel"))

    clients_dir = config.get("REPORTING", "clients")
    reports_dir = config.get("REPORTING", "reports")
    menu_report_file = config.get("MENU", "file")

    queue = mp.Queue()

    if args.file_analysis_only:
        log.info("not starting beacon or sniffer - user wants to do file analysis only")
        try:
            frame = rdpcap(args.file_analysis_only)
        except FileNotFoundError as error:
            log.error(f"could not find file {args.file_analysis_only}")
            log.exception(f"{error}")
            sys.exit(-1)

        # extract the first frame object from pcap
        assoc_req_frame = frame[0]

        # put frame into the multiprocessing queue for the profiler to read later
        queue.put(assoc_req_frame)
    else:
        from .fakeap import TxBeacons, Sniffer

        boot_time = datetime.now().timestamp()

        # mp.set_start_method("spawn")

        lock = mp.Lock()
        sequence_number = mp.Value("i", 0)

        log.info("start interface prep...")
        if not helpers.prep_interface(interface, "monitor", channel):
            log.error("failed to prep interface")
            sys.exit(-1)
        log.info("done prep interface...")

        if args.listen_only:
            log.info("beacon process not started due to listen only mode")
        else:
            log.info("starting beacon process")
            p = mp.Process(
                name="txbeacons",
                target=TxBeacons,
                args=(args, boot_time, lock, sequence_number, ssid, interface, channel),
            )
            p.start()

        log.info("starting sniffer process")
        p2 = mp.Process(
            name="sniffer",
            target=Sniffer,
            args=(
                args,
                boot_time,
                lock,
                sequence_number,
                ssid,
                interface,
                channel,
                queue,
            ),
        )
        p2.start()

    from .profiler import Profiler

    log.info("starting profiler process")
    p3 = mp.Process(
        name="profiler",
        target=Profiler,
        args=(args, queue, clients_dir, reports_dir, channel, ssid, menu_report_file),
    )
    p3.start()


def signal_handler(sig, frame):
    print("SIGINT or Control-C detected... exiting...")
    sys.exit(0)


if __name__ == "__main__":
    main()
