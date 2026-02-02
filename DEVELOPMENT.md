# Initial development setup

## Repository

1. Clone repo to development host

2. Create and activate virtualenv

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Update and install tools 

```bash
pip install -u pip pip-tools setuptools wheel
```

4. Install depends

```bash
pip install -r requirements.txt
```

## Building Debian packages

Two build scripts are available depending on your needs:

### Local native builds (recommended for development)

**`build-package-native.sh`** - Uses Podman/Docker containers for native architecture builds.

**Requirements:**

- Podman or Docker installed
- No additional setup needed

**Usage:**

```bash
./build-package-native.sh
```

**Output:** `wlanpi-profiler_<version>_<arch>.deb` in current directory

**When to use:**

- Local development and testing
- Quick builds on your development machine
- Works on any OS with Podman/Docker (macOS, Linux, etc.)
- Builds for the host architecture (arm64 on Apple Silicon, amd64 on x86_64)

### Cross-architecture builds (for multiple targets)

**`build-package-cross.sh`** - Uses sbuild/schroot for cross-compilation.

**Requirements:**

- Debian or Ubuntu host
- sbuild, schroot, debootstrap, qemu-user-static (automatically installed by script)
- First run creates schroot environment (takes several minutes)

**Usage:**

```bash
# Build for bookworm/arm64 (default)
./build-package-cross.sh

# Build for different architecture
INPUTS_ARCH=armhf ./build-package-cross.sh

# Build for different distro
INPUTS_DISTRO=bullseye ./build-package-cross.sh

# Combine both
INPUTS_DISTRO=bullseye INPUTS_ARCH=armhf ./build-package-cross.sh
```

**Supported architectures:** arm64

**Supported distros:** bookworm (default), bullseye

**When to use:**

- Building for multiple architectures
- Creating official release packages
- CI/CD environments (GitHub Actions uses similar sbuild approach)

---

### Which script should I use?

| Scenario | Script | Why |
|----------|--------|-----|
| Local development on macOS | `build-package-native.sh` | Simple, no setup required |
| Local development on Linux | `build-package-native.sh` | Fastest for native builds |
| Testing on different architecture | `build-package-cross.sh` | True cross-compilation |
| Building for armhf (32-bit) | `build-package-cross.sh` | Requires cross-compilation |
| CI/CD pipeline | GitHub Actions | Uses shared sbuild workflows |

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

