"""build-package-native.sh engine/architecture dispatch, with fake engines.

No container is started: podman/docker/uname are shims on a minimal PATH that
record their arguments.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "build-package-native.sh"

ENGINE_SHIM = """#!/bin/sh
echo "$(basename "$0") $*" | head -n 1 >> "$LOG"  # drop the bash -c body
eval "last=\\${$#}"
if [ "$1" = run ] && [ "$last" = true ]; then exit "${FAKE_PROBE_RC:-0}"; fi
"""


def run(tmp_path, engines=("podman",), uname="x86_64", **env):
    repo, bin_ = tmp_path / "repo", tmp_path / "bin"
    repo.mkdir()
    bin_.mkdir()
    shutil.copy(SCRIPT, repo)
    (repo / "wlanpi-profiler_0_arm64.deb").touch()  # stale build output
    shims = dict.fromkeys(engines, ENGINE_SHIM)
    shims["uname"] = f"#!/bin/sh\necho {uname}\n"
    for name, body in shims.items():
        (bin_ / name).write_text(body)
        (bin_ / name).chmod(0o755)
    for tool in ("dirname", "rm", "ls", "basename", "head"):
        (bin_ / tool).symlink_to(shutil.which(tool))
    log = tmp_path / "log"
    log.touch()
    proc = subprocess.run(
        [shutil.which("bash"), str(repo / SCRIPT.name)],
        env={"PATH": str(bin_), "LOG": str(log), **env},
        capture_output=True,
        text=True,
    )
    return proc, log.read_text().splitlines(), repo


@pytest.mark.parametrize("uname,arch", [("x86_64", "amd64"), ("aarch64", "arm64")])
def test_defaults_to_host_arch_without_probe(tmp_path, uname, arch):
    proc, calls, _ = run(tmp_path, uname=uname)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [c.split()[:2] for c in calls] == [["podman", "build"], ["podman", "run"]]
    assert f"--platform linux/{arch} " in calls[0]
    assert f"-t localhost/wlanpi-profiler-builder:trixie-{arch} ." in calls[0]
    assert calls[1].startswith(f"podman run --rm --platform linux/{arch} ")
    assert f"localhost/wlanpi-profiler-builder:trixie-{arch}" in calls[1].split()


def test_foreign_arch_probes_emulation_before_building(tmp_path):
    proc, calls, _ = run(tmp_path, ARCH="arm64")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert calls[:2] == [
        "podman pull --platform linux/arm64 docker.io/library/debian:trixie",
        "podman run --rm --platform linux/arm64 docker.io/library/debian:trixie true",
    ]
    assert [c.split()[1] for c in calls[2:]] == ["build", "run"]


def test_failed_probe_stops_before_cleanup_and_build(tmp_path):
    proc, calls, repo = run(tmp_path, ARCH="arm64", FAKE_PROBE_RC="1")
    assert proc.returncode == 1
    assert "needs QEMU user emulation" in proc.stdout
    assert [c.split()[1] for c in calls] == ["pull", "run"]
    assert (repo / "wlanpi-profiler_0_arm64.deb").exists()


def test_falls_back_to_docker_without_podman(tmp_path):
    proc, calls, _ = run(tmp_path, engines=("docker",))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [c.split()[0] for c in calls] == ["docker", "docker"]


@pytest.mark.parametrize("env", [{"ARCH": "armhf"}, {"ENGINE": "nope"}])
def test_bad_arch_or_engine_fails_before_cleanup(tmp_path, env):
    proc, calls, repo = run(tmp_path, **env)
    assert proc.returncode == 1
    assert calls == []
    assert (repo / "wlanpi-profiler_0_arm64.deb").exists()
