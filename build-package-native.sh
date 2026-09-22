#!/bin/bash
#
# Build wlanpi-profiler Debian package in podman container
#
# Usage: ./build-package-native.sh [SUITE]
#   SUITE   Debian release to build for (default: trixie)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Debian release to build for
SUITE="${1:-trixie}"

IMAGE="wlanpi-profiler-builder:${SUITE}"

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
echo "========================================="

# Check for podman
if ! command -v podman &> /dev/null; then
    echo "ERROR: podman not found!"
    echo "Please install podman to use this build script."
    exit 1
fi

echo "Step 1: Building container image..."
podman build -f Dockerfile.build --build-arg SUITE="$SUITE" -t "$IMAGE" .

echo ""
echo "Step 2: Building Debian package in container..."
echo "(This may take several minutes...)"
echo ""

# Run the build in container
podman run --rm \
    -v "$(pwd)":/work:Z \
    -w /work \
    "$IMAGE" \
    bash -c '
set -e

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
