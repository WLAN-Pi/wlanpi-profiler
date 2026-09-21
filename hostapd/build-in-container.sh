#!/bin/bash
#
# Build hostapd in a Debian container (for systems without libnl dependencies)
#
# Thin wrapper around build.sh for hosts that lack the build dependencies.
# The hostapd version comes from ./VERSION.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    -v "$SCRIPT_DIR":/work \
    -w /work \
    debian:trixie \
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

bash build.sh
'

echo ""
echo "Binary location: $SCRIPT_DIR/build/hostapd"
echo ""
