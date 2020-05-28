# -*- coding: utf-8 -*-
#
# profiler2: a Wi-Fi client capability analyzer
# Copyright (C) 2020 Josh Schmelzle, WLAN Pi Community.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
profiler2.manager
~~~~~~~~~~~~~~~~~

handle profiler
"""

# standard library imports
import inspect, logging, multiprocessing as mp, os, platform, signal, sys
from datetime import datetime

# third party imports
from scapy.all import rdpcap

# app imports
from . import constants, helpers
from .__version__ import __version__


def signal_handler(sig, frame):
    """ Suppress stack traces when intentionally closed """
    print("SIGINT or Control-C detected... exiting...")
    sys.exit(0)


def start(args):
    """ Begin work """
    log = logging.getLogger(inspect.stack()[0][3])

    signal.signal(signal.SIGINT, signal_handler)
    helpers.setup_logger(args)

    log.info("%s version %s", __name__.split(".")[0], __version__)
    log.info("python platform version is %s", platform.python_version())
    log.debug("args: %s", args)

    if args.oui_update:
        sys.exit(0) if helpers.update_manuf() else sys.exit(-1)

    config = helpers.setup_config(args)

    if args.clean:
        reports_dir = os.path.join(
            config["GENERAL"].get("files_root"),
            constants.ROOT_DIR,
            constants.REPORTS_DIR,
        )
        helpers.report_cleanup(reports_dir)
        sys.exit(0)

    interface = config.get("GENERAL").get("interface")
    ssid = config.get("GENERAL").get("ssid")
    channel = int(config.get("GENERAL").get("channel"))

    queue = mp.Queue()

    log.debug("pid %s", os.getpid())

    if args.pcap_analysis_only:
        log.info("not starting beacon or sniffer - user wants to do file analysis only")
        try:
            frame = rdpcap(args.pcap_analysis_only)
        except FileNotFoundError:
            log.exception("could not find file %s", args.pcap_analysis_only)
            print("exiting...")
            sys.exit(-1)

        # extract the first frame object from pcap
        assoc_req_frame = frame[0]

        # put frame into the multiprocessing queue for the profiler to read later
        queue.put(assoc_req_frame)
    else:
        if not helpers.is_fakeap_interface_valid(config):
            sys.exit(-1)

        helpers.generate_run_message(config)

        from .fakeap import TxBeacons, Sniffer

        boot_time = datetime.now().timestamp()

        lock = mp.Lock()
        sequence_number = mp.Value("i", 0)

        log.info("start interface prep...")
        if not helpers.prep_interface(interface, "monitor", channel):
            log.error("failed to prep interface")
            print("exiting...")
            sys.exit(-1)
        log.info("done prep interface...")

        if args.listen_only:
            log.info("beacon process not started due to listen only mode")
        else:
            log.info("starting beacon process")
            mp.Process(
                name="txbeacons",
                target=TxBeacons,
                args=(args, boot_time, lock, sequence_number, ssid, interface, channel),
            ).start()

        log.info("starting sniffer process")
        mp.Process(
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
        ).start()

    from .profiler import Profiler

    log.info("starting profiler process")
    mp.Process(name="profiler", target=Profiler, args=(args, queue, config)).start()
