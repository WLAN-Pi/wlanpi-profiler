"""Packaging invariants that have regressed before."""

import configparser
from pathlib import Path

DEBIAN = Path(__file__).resolve().parent.parent / "debian"


def test_profiler_unit_can_never_start_at_boot():
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
