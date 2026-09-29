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


def test_python_pin_matches_across_packaging():
    # debian/bookworm is pinned to one interpreter in three places: the venv
    # is built with SNAKE, the package Pre-Depends on it, and requires-python
    # admits only it. A cherry-pick from main (3.13) can drift any one of them.
    import re
    import tomllib

    from packaging.specifiers import SpecifierSet

    snake = re.search(
        r"^SNAKE=/usr/bin/python(3\.\d+)$",
        (DEBIAN / "rules").read_text(),
        re.MULTILINE,
    )
    assert snake, "SNAKE=/usr/bin/python3.X not found in debian/rules"
    version = snake.group(1)

    control = (DEBIAN / "control").read_text()
    pre_depends = re.search(r"^Pre-Depends:(.*)$", control, re.MULTILINE)
    assert pre_depends
    assert re.search(rf"\bpython{re.escape(version)}\b", pre_depends.group(1))
    assert f"X-Python3-Version: >= {version}" in control

    pyproject = tomllib.loads((DEBIAN.parent / "pyproject.toml").read_text())
    spec = SpecifierSet(pyproject["project"]["requires-python"])
    major, minor = (int(p) for p in version.split("."))
    assert f"{major}.{minor}" in spec
    assert f"{major}.{minor - 1}" not in spec
    assert f"{major}.{minor + 1}" not in spec
    assert pyproject["tool"]["ruff"]["target-version"] == f"py{major}{minor}"
    assert pyproject["tool"]["mypy"]["python_version"] == version
