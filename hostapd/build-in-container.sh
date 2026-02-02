#!/bin/bash
#
# Build hostapd in a Debian container (for systems without libnl dependencies)
#
# This script builds hostapd inside a podman/docker container with all
# required dependencies, avoiding the need to install build dependencies
# on the host system.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================="
echo "Building Hostapd in Container"
echo "========================================="

if command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
elif command -v docker &> /dev/null; then
    CONTAINER_CMD="docker"
else
    echo "ERROR: Neither podman nor docker found!"
    echo "Please install podman or docker to use this build script."
    exit 1
fi

echo "Using container runtime: $CONTAINER_CMD"

$CONTAINER_CMD run --rm \
    -v "$(pwd)":/work \
    -w /work \
    debian:bookworm \
    bash -c '
set -e

echo "Installing build dependencies..."
apt-get update -qq
apt-get install -y -qq \
    build-essential \
    libnl-3-dev \
    libnl-genl-3-dev \
    libssl-dev \
    pkg-config \
    > /dev/null 2>&1

TARBALL="hostapd-2.11.tar.gz"
PATCH="hostapd_profiler.patch"
EXPECTED_SHA256="2b3facb632fd4f65e32f4bf82a76b4b72c501f995a4f62e330219fe7aed1747a"

echo "Verifying source tarball checksum..."
echo "$EXPECTED_SHA256  $TARBALL" | sha256sum -c - || {
    echo "ERROR: SHA256 checksum mismatch!"
    exit 1
}
echo "✓ Checksum verified"

# Clean previous build if exists
if [ -d "hostapd-2.11" ]; then
    echo "Cleaning previous build..."
    rm -rf hostapd-2.11
fi

echo "Extracting source tarball..."
tar -xzf "$TARBALL"
echo "✓ Source extracted"

echo "Applying profiler patch..."
cd hostapd-2.11
patch -p1 < "../$PATCH" || {
    echo "ERROR: Failed to apply patch!"
    exit 1
}
echo "✓ Patch applied successfully"

# Apply additional MCS overrides
bash "../apply-mcs-fixes.sh" || {
    echo "ERROR: Failed to apply MCS overrides!"
    exit 1
}

cd hostapd

echo "Configuring build..."
cp defconfig .config

# Enable 802.11n and 802.11ac (disabled by default in defconfig)
sed -i "s/#CONFIG_IEEE80211N=y/CONFIG_IEEE80211N=y/" .config
sed -i "s/#CONFIG_IEEE80211AC=y/CONFIG_IEEE80211AC=y/" .config

# Add required features
cat >> .config <<EOF

# Required features for profiler
CONFIG_LIBNL32=y
CONFIG_SAE=y
CONFIG_OWE=y
CONFIG_IEEE80211AX=y
CONFIG_IEEE80211BE=y
CONFIG_IEEE80211R=y
CONFIG_MBO=y
CONFIG_WPA3_SAE=y
CONFIG_IEEE80211W=y
CONFIG_WNM=y
EOF

echo "✓ Build configured"

echo "Building hostapd (this may take a few minutes)..."
NPROC=$(nproc 2>/dev/null || echo 1)
make -j"$NPROC" || {
    echo "ERROR: Build failed!"
    exit 1
}

echo ""
echo "========================================="
echo "Build Complete!"
echo "========================================="
ls -lh hostapd
echo ""
echo "Binary size: $(du -h hostapd | awk '\''{print $1}'\'')"
echo "========================================="
'

echo ""
echo "Binary location: $SCRIPT_DIR/hostapd-2.11/hostapd/hostapd"
echo ""
echo "To strip debug symbols and reduce size:"
echo "  strip hostapd-2.11/hostapd/hostapd"
echo ""
