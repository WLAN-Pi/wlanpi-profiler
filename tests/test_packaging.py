"""Packaging invariants that have regressed before."""

import configparser
from pathlib import Path

DEBIAN = Path(__file__).resolve().parent.parent / "debian"


def test_profiler_unit_can_never_start_at_boot():
    # The profiler starts an AP on a radio it picks itself (#279). A static
    # unit (no [Install]) can't be enabled, and postinst must remove the
    # enable symlink that releases before 2.1.2 created by default.
    unit = configparser.ConfigParser()
    unit.read(DEBIAN / "wlanpi-profiler.service")
    assert "Service" in unit
    assert "Install" not in unit

    postinst = (DEBIAN / "postinst").read_text()
    assert (
        "rm -f /etc/systemd/system/multi-user.target.wants/wlanpi-profiler.service"
        in postinst
    )
    assert "#DEBHELPER#" in postinst
