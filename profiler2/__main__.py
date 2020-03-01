#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
profiler2
~~~~~~~~~

attempt at porting and optimizing profiler code from py2 to py3
"""

# standard library imports
import inspect
import logging
import os
import platform
import sys
from time import time, sleep

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

# app imports
from . import helpers


def main() -> None:
    parser = helpers.setup_parser()
    args = parser.parse_args()
    helpers.setup_logger(args)

    log = logging.getLogger(inspect.stack()[0][3])
    log.info("args {0}".format(args))
    log.info("{0}".format(sys.version))

    config = helpers.setup_config(args)
    log.info("config: {0}".format(config))

    interface = config.get("GENERAL", "interface")
    ssid = config.get("GENERAL", "ssid")
    channel = int(config.get("GENERAL", "channel"))

    from datetime import datetime

    boot_time = datetime.now().timestamp()

    import multiprocessing as mp

    # mp.set_start_method("spawn")

    lock = mp.Lock()
    sequence_number = mp.Value("i", 0)
    from .fakeap import TxBeacons, Sniffer

    log.info("start interface prep...")
    if not helpers.prep_interface(interface, "monitor", channel):
        log.error("failed to prep interface")
        sys.exit(-1)
    log.info("done prep interface...")

    log.info("starting beacon process")
    p = mp.Process(
        name="txbeacons",
        target=TxBeacons,
        args=(args, boot_time, lock, sequence_number, ssid, interface, channel),
    )
    p.start()

    queue = mp.Queue()

    log.info("starting sniffer process")
    p2 = mp.Process(
        name="sniffer",
        target=Sniffer,
        args=(args, boot_time, lock, sequence_number, ssid, interface, channel, queue),
    )
    p2.start()

    from .profiler import Profiler

    log.info("starting profiler process")
    p3 = mp.Process(name="profiler", target=Profiler, args=(args, queue))
    p3.start()


if __name__ == "__main__":
    main()
