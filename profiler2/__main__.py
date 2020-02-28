#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
profiler2
~~~~~~~~~

a WLAN client profiler
"""

# standard library imports
import os
import platform
import sys

script_file_name = os.path.basename(__file__)

# hard set no support for non linux platforms
if "linux" not in sys.platform:
    sys.exit("{0} only works on Linux... exiting...".format(script_file_name))

# hard set no support for python < v3.6
if sys.version_info < (3, 6):
    sys.exit(
        "exiting... {0} requires Python v3.6+...\nyou're running with {1}".format(
            script_file_name, platform.python_version()
        )
    )

# app imports
from . import helpers


def main() -> None:
    parser = helpers.setup_parser()
    args = parser.parse_args()

    from .fakeap import FakeAP

    log = helpers.setup_logger(args)
    log.info("args {0}".format(args))
    log.info("{0}".format(sys.version))

    config = helpers.setup_config(args)
    log.info("config: {0}".format(config))

    FakeAP(config, args).beam_up()


if __name__ == "__main__":
    main()
