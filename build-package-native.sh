#!/bin/bash
#
# Build wlanpi-profiler Debian package in a podman or docker container
#
# Usage: [ARCH=arm64|amd64] [ENGINE=podman|docker] ./build-package-native.sh [SUITE]
#   SUITE   Debian release to build for (default: trixie)
#   ARCH    Debian architecture to build for (default: host architecture).
#           Use ARCH=arm64 on an x86_64 host to build for the WLAN Pi; this
#           runs the build under QEMU emulation and is much slower.
#   ENGINE  Container engine (default: podman if installed, else docker)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Debian release to build for
SUITE="${1:-trixie}"

case "$(uname -m)" in
    aarch64|arm64) HOST_ARCH=arm64 ;;
    x86_64|amd64)  HOST_ARCH=amd64 ;;
    *)             HOST_ARCH=$(uname -m) ;;
esac
ARCH="${ARCH:-$HOST_ARCH}"
case "$ARCH" in
    arm64|amd64) ;;
    *)
        echo "ERROR: unsupported ARCH '$ARCH' (use arm64 or amd64)"
        exit 1
        ;;
esac

if [ -z "${ENGINE:-}" ]; then
    if command -v podman &> /dev/null; then
        ENGINE=podman
    else
        ENGINE=docker
    fi
fi
if ! command -v "$ENGINE" &> /dev/null; then
    echo "ERROR: $ENGINE not found!"
    echo "Please install podman (or docker) to use this build script."
    exit 1
fi

# A foreign-architecture build needs QEMU user emulation. Docker Desktop and
# podman machine (macOS, Windows) include it; Linux hosts need it registered
# with binfmt_misc, e.g. `sudo apt install qemu-user-static` on Debian/Ubuntu.
# Probe the engine itself rather than the local binfmt_misc table: with a VM or
# remote engine the host table says nothing about what the engine can run.
BASE_IMAGE="docker.io/library/debian:$SUITE"
if [ "$ARCH" != "$HOST_ARCH" ]; then
    # Pull first so a registry or network error is reported as itself.
    "$ENGINE" pull --platform "linux/$ARCH" "$BASE_IMAGE"
    if ! "$ENGINE" run --rm --platform "linux/$ARCH" "$BASE_IMAGE" true; then
        echo "ERROR: $ENGINE cannot run linux/$ARCH containers on this $HOST_ARCH host."
        echo "Building $ARCH here needs QEMU user emulation."
        echo "On Debian/Ubuntu: sudo apt install qemu-user-static"
        exit 1
    fi
fi

# Fully qualified: with --platform and a terminal attached, podman asks which
# registry a short name means instead of using the local image.
IMAGE="localhost/wlanpi-profiler-builder:${SUITE}-${ARCH}"

# Clean up old build manifest, stale build trees, and previously built
# packages. Without this, setuptools reuses build/lib and repackages files that
# were deleted or renamed in the source tree, and stale .deb files in the repo
# root get picked up by the manifest and deployed.
rm -f .build-manifest.txt
rm -rf build .pybuild
rm -f wlanpi-profiler*.deb

echo "========================================="
echo "Building wlanpi-profiler Debian Package"
echo "  suite:  $SUITE"
echo "  arch:   $ARCH"
echo "  engine: $ENGINE"
echo "========================================="

echo "Step 1: Building container image..."
"$ENGINE" build --platform "linux/$ARCH" -f Dockerfile.build \
    --build-arg SUITE="$SUITE" -t "$IMAGE" .

echo ""
echo "Step 2: Building Debian package in container..."
echo "(This may take several minutes...)"
echo ""

# Run the build in container
"$ENGINE" run --rm --platform "linux/$ARCH" \
    -v "$(pwd)":/work:Z \
    -w /work \
    "$IMAGE" \
    bash -c '
set -e
# With rootful docker, files created here are owned by root on the host and
# break the cleanup on the next run. Give root-owned files to the owner of the
# source tree, as seen in the container. Under rootless podman/docker that owner
# is root (0) and this does nothing. The trap also runs when the build fails.
trap "o=\$(stat -c %u:%g /work); [ \"\${o%%:*}\" = 0 ] || chown -R --from=0 \"\$o\" /work" EXIT

echo "Installing package build dependencies..."
apt-get update
mk-build-deps --install --remove --tool "apt-get -y --no-install-recommends" debian/control || true

echo ""
echo "Building package..."
dpkg-buildpackage -us -uc -b

echo ""
echo "Copying packages from container to host..."
cp -v /*.deb /work/ 2>/dev/null || echo "No .deb files found in container root"

echo ""
echo "Creating build manifest..."
# List only the packages built in this run. The container root holds just the
# output of this build; globbing /work would also match stale .deb files from
# earlier builds and deploy the wrong version.
ls -1 /*.deb 2>/dev/null | grep -v dbgsym | xargs -r -n1 basename > /work/.build-manifest.txt || true

echo ""
echo "Build complete!"
'

echo ""
echo "========================================="
echo "Package Build Complete!"
echo "========================================="
echo ""
echo "Generated packages:"
ls -lh wlanpi-profiler*.deb 2>/dev/null || echo "No wlanpi-profiler .deb files found"
echo ""
echo "To install the package:"
echo "  sudo dpkg -i wlanpi-profiler_*.deb"
echo "  sudo apt-get install -f  # if there are dependency issues"
echo ""
