# Initial development setup

## Repository

See [CONTRIBUTING.md](CONTRIBUTING.md#branching-model) for the branching model:
`main` is the only long-lived branch; create short-lived feature branches from
`main` and open pull requests against `main`.

## Prerequisites

`main` targets Debian trixie and needs **Python 3.13**, which is what current
WLAN Pi OS images run. On an older bullseye-based image (WLAN Pi OS v3.x) the
steps below fail (for example, `pip install -r requirements.txt` needs Python
3.10 or newer). Upgrade the WLAN Pi to a current image, or work from the
`debian/bullseye` branch (`git checkout debian/bullseye`).

## Setup

1. Clone repo to development host

2. Create and activate virtualenv

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Update and install tools 

```bash
pip install -U pip pip-tools setuptools wheel
```

4. Install depends

```bash
pip install -r requirements.txt
```

## Building Debian packages

The package contains compiled code (hostapd), so it is built per architecture.
WLAN Pi devices are **arm64**. Pick the row that matches your machine:

| You have | Use | Notes |
|----------|-----|-------|
| An arm64 host (WLAN Pi, Apple Silicon Mac, other arm64 Linux) | `./build-package-native.sh` | Fastest |
| An x86_64 host (Linux, Intel Mac, Windows) | `ARCH=arm64 ./build-package-native.sh` | Runs under QEMU emulation, much slower |
| A Debian or Ubuntu host with sudo | `./build-package-cross.sh` | sbuild chroot, closest to CI |
| Write access to this repository | The **Build and Archive Debian Package** workflow | Run it from the Actions tab (it also runs on pull requests that change `debian/`); download the `.deb` from the run's artifacts |

### Container builds: `build-package-native.sh`

Builds the package inside a Debian container (see `Dockerfile.build`).

**Requirements:**

- Podman or Docker. Podman is used if both are installed; set `ENGINE=docker`
  to override. On a WLAN Pi or other Debian host: `sudo apt install podman`
- For `ARCH=arm64` on an x86_64 Linux host: QEMU user emulation registered with
  binfmt_misc (`sudo apt install qemu-user-static` on Debian/Ubuntu). Docker
  Desktop and podman machine on macOS and Windows already include it.

**Usage:**

```bash
./build-package-native.sh              # trixie, host architecture
ARCH=arm64 ./build-package-native.sh   # trixie, arm64 (for a WLAN Pi)
ARCH=amd64 ./build-package-native.sh   # trixie, amd64
```

**Output:** `wlanpi-profiler_<version>_<arch>.deb` in the repository root.

`build-and-deploy.sh` wraps this script, always builds arm64, and installs the
result on a WLAN Pi:

```bash
WLANPI_IP=198.18.42.1 ./build-and-deploy.sh
```

### sbuild builds: `build-package-cross.sh`

Builds the package in an sbuild/schroot chroot, like CI. The arm64 chroot runs
under `qemu-user-static` emulation on non-arm64 hosts.

**Requirements:**

- Debian or Ubuntu host with sudo
- sbuild, schroot, debootstrap, qemu-user-static (installed by the script)
- The first run creates the chroot under `/srv/chroot` (takes several minutes)

**Usage:**

```bash
# Build for trixie/arm64 (default)
./build-package-cross.sh

# Build for a different architecture
INPUTS_ARCH=amd64 ./build-package-cross.sh
```

**Output:** `wlanpi-profiler_<version>_<arch>.deb` in the repository root.

---

## Testing

Run the test suite with pytest:

```bash
# Activate virtualenv first
source venv/bin/activate

# Run test runner
tox

# Run specific test file
pytest tests/test_profiler.py
```

---

## Code quality

```bash
# Format and lint code with ruff
ruff check profiler/ tests/          # Check for issues
ruff check --fix profiler/ tests/    # Auto-fix issues
ruff format profiler/ tests/         # Format code

# Or run both check and format together
ruff check --fix profiler/ tests/ && ruff format profiler/ tests/
```

---

## Monitoring & status files

Profiler exposes operational status and monitoring metrics via JSON files in `/var/run/` for integration with external tools (Web UI, FPMS, custom scripts).

**Documentation:**

- [INFO_FILE_SCHEMA.md](INFO_FILE_SCHEMA.md) - Complete reference for the info file structure
- [README.md](README.md#status--info-files-external-monitoring) - Quick overview and usage

**Files:**

- `/var/run/wlanpi-profiler.status` - Profiler state (starting, running, stopped, failed)
- `/var/run/wlanpi-profiler.info` - Operational details and monitoring metrics

**Implementation:**

- [profiler/status.py](profiler/status.py) - Status file generation and management

