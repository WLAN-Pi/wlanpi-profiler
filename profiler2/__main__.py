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

    log = helpers.setup_logger(args)
    log.info("args {0}".format(args))
    log.info("{0}".format(sys.version))

    config = helpers.setup_config(args)
    log.info("config: {0}".format(config))

    interface = config["fakeap"]["interface"]
    ssid = config["fakeap"]["ssid"]
    channel = config["fakeap"]["channel"]

    boot_time = time()
    import multiprocessing as mp

    mp.set_start_method("spawn")

    lock = mp.Lock()
    sequence_number = mp.Value("i", 0)
    from .profiler import TxBeacons, Sniffer, AnalyzeFrame

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
        args=(args, boot_time, lock, sequence_number, ssid, interface, channel),
    )
    p2.start()

    while True:
        sleep(1)


if __name__ == "__main__":
    main()
