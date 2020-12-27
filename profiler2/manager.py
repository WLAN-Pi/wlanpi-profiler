# -*- coding: utf-8 -*-
#
# profiler2: a Wi-Fi client capability analyzer
# Copyright 2020 Josh Schmelzle
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""
profiler2.manager
~~~~~~~~~~~~~~~~~

handle profiler
"""

# standard library imports
import inspect
import logging
import multiprocessing as mp
import os
import platform
import signal
import sys
from datetime import datetime

# third party imports
import scapy
from scapy.all import rdpcap

# app imports
from . import helpers
from .__version__ import __version__


def signal_handler(sig, frame):
    """ Suppress stack traces when intentionally closed """
    print("SIGINT or Control-C detected... exiting...")
    sys.exit(0)


def are_we_root() -> bool:
    """ Do we have root permissions? """
    if os.geteuid() == 0:
        return True
    else:
        return False


def start(args: dict):
    """ Begin work """
    log = logging.getLogger(inspect.stack()[0][3])

    if args.pytest:
        sys.exit("pytest")

    if not are_we_root():
        log.error("must run with root permissions... exiting...")
        sys.exit(-1)

    signal.signal(signal.SIGINT, signal_handler)
    helpers.setup_logger(args)

    log.debug("%s version %s", __name__.split(".")[0], __version__)
    log.debug("python platform version is %s", platform.python_version())
    log.debug("scapy version is %s", scapy.__version__)
    log.debug("args: %s", args)

    if args.oui_update:
        sys.exit(0) if helpers.update_manuf() else sys.exit(-1)

    config = helpers.setup_config(args)

    if helpers.validate(config):
        log.debug("config %s", config)
    else:
        log.error("configuration validation failed... exiting...")
        sys.exit(-1)

    if args.clean and args.files:
        clients_dir = os.path.join(config["GENERAL"].get("files_path"), "clients")
        helpers.files_cleanup(clients_dir, args.yes)
        sys.exit(0)

    if args.clean:
        reports_dir = os.path.join(config["GENERAL"].get("files_path"), "reports")
        helpers.files_cleanup(reports_dir, args.yes)
        sys.exit(0)

    interface = config.get("GENERAL").get("interface")
    channel = int(config.get("GENERAL").get("channel"))
    pcap_analysis = config.get("GENERAL").get("pcap_analysis")
    listen_only = config.get("GENERAL").get("listen_only")
    queue = mp.Queue()

    log.debug("%s pid %s", __name__, os.getpid())

    if pcap_analysis:
        log.info("not starting beacon or sniffer - user wants to do file analysis only")
        try:
            frame = rdpcap(pcap_analysis)
        except FileNotFoundError:
            log.exception("could not find file %s", pcap_analysis)
            print("exiting...")
            sys.exit(-1)

        # extract the first frame object from pcap
        assoc_req_frame = frame[0]

        # put frame into the multiprocessing queue for the profiler to analyze
        queue.put(assoc_req_frame)
    else:
        helpers.generate_run_message(config)

        from .fakeap import Sniffer, TxBeacons

        boot_time = datetime.now().timestamp()

        lock = mp.Lock()
        sequence_number = mp.Value("i", 0)

        if args.no_interface_prep:
            log.warning("skipping interface prep...")
        else:
            log.info("start interface prep...")
            if not helpers.prep_interface(interface, "monitor", channel):
                log.error("failed to prep interface")
                print("exiting...")
                sys.exit(-1)
            log.info("done prep interface...")

        if listen_only:
            log.info("beacon process not started due to listen only mode")
        else:
            log.info("starting beacon process")
            mp.Process(
                name="txbeacons",
                target=TxBeacons,
                args=(config, boot_time, lock, sequence_number),
            ).start()

        log.info("starting sniffer process")
        mp.Process(
            name="sniffer",
            target=Sniffer,
            args=(config, boot_time, lock, sequence_number, queue),
        ).start()

    from .profiler import Profiler

    log.info("starting profiler process")
    mp.Process(name="profiler", target=Profiler, args=(config, queue)).start()
