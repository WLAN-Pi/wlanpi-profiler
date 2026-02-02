#!/bin/bash
#
# Build wlanpi-profiler Debian package in podman container
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Clean up old build manifest
rm -f .build-manifest.txt

echo "========================================="
echo "Building wlanpi-profiler Debian Package"
echo "========================================="

# Check for podman
if ! command -v podman &> /dev/null; then
    echo "ERROR: podman not found!"
    echo "Please install podman to use this build script."
    exit 1
fi

echo "Step 1: Building Docker image..."
podman build -f Dockerfile.build -t wlanpi-profiler-builder .

echo ""
echo "Step 2: Building Debian package in container..."
echo "(This may take several minutes...)"
echo ""

# Run the build in container
podman run --rm \
    -v "$(pwd)":/work:Z \
    -w /work \
    wlanpi-profiler-builder \
    bash -c '
set -e

echo "Installing package build dependencies..."
mk-build-deps --install --remove --tool "apt-get -y --no-install-recommends" debian/control || true

echo ""
echo "Building package..."
dpkg-buildpackage -us -uc -b

echo ""
echo "Copying packages from container to host..."
cp -v /*.deb /work/ 2>/dev/null || echo "No .deb files found in container root"

echo ""
echo "Creating build manifest..."
cd /work && ls -1 wlanpi-profiler_*.deb 2>/dev/null | grep -v dbgsym > .build-manifest.txt || true

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
