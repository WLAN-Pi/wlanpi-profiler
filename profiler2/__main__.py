#!/usr/bin/python3
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
profiler2
~~~~~~~~~

Wi-Fi client capabilities analyzer for the WLAN Pi
"""

import os
import platform
import sys

from . import helpers, manager

# hard set no support for non linux platforms
if "linux" not in sys.platform:
    sys.exit("{0} only works on Linux... exiting...".format(os.path.basename(__file__)))

# hard set no support for python < v3.6
if sys.version_info < (3, 6):
    sys.exit(
        "{0} requires Python version 3.6 or higher...\nyou are trying to run with Python version {1}...\nexiting...".format(
            os.path.basename(__file__), platform.python_version()
        )
    )


def main() -> None:
    """ Set up args and start the profiler manager """
    if os.geteuid() == 0:
        parser = helpers.setup_parser()
        args = parser.parse_args()
        manager.start(args)
    else:
        print("must run as root... exiting...")


if __name__ == "__main__":
    main()
