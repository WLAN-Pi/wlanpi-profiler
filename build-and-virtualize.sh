#!/bin/bash
#
# Build Debian package and test in Podman container
#
set -e

PACKAGE_NAME="wlanpi-profiler"
CONTAINER_NAME="wlanpi-profiler-test"
IMAGE_NAME="debian:bookworm"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Build and Virtualize $PACKAGE_NAME"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

if ! command -v podman &> /dev/null; then
    echo "ERROR: podman not found!"
    echo "Please install podman to use this script."
    exit 1
fi

echo ""
echo "Building package..."
if ! bash build-package-native.sh; then
    echo ""
    echo "ERROR: Build failed!"
    exit 1
fi

echo ""
echo "Reading build manifest..."
if [ ! -f .build-manifest.txt ]; then
    echo "ERROR: Build manifest not found!"
    exit 1
fi

DEB_FILES=$(cat .build-manifest.txt)

if [ -z "$DEB_FILES" ]; then
    echo "ERROR: No packages listed in build manifest!"
    exit 1
fi

echo "Packages to install:"
for f in $DEB_FILES; do echo "  $(basename $f)"; done

echo ""
echo "Checking for existing container..."
if podman container exists "$CONTAINER_NAME"; then
    echo "Container '$CONTAINER_NAME' already exists."
    read -p "Remove and recreate? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing container..."
        podman rm -f "$CONTAINER_NAME" > /dev/null
        CREATE_NEW=1
    else
        echo "Reusing existing container..."
        CREATE_NEW=0
    fi
else
    CREATE_NEW=1
fi

if [ $CREATE_NEW -eq 1 ]; then
    echo ""
    echo "Creating new container..."
    podman run -dt --name "$CONTAINER_NAME" "$IMAGE_NAME" /bin/bash
    echo "Container created."
fi

echo ""
echo "Starting container if stopped..."
podman start "$CONTAINER_NAME" > /dev/null 2>&1 || true

echo ""
echo "Copying packages to container..."
for DEB_FILE in $DEB_FILES; do
    podman cp "$DEB_FILE" "$CONTAINER_NAME:/tmp/"
    echo "  Copied $(basename $DEB_FILE)"
done

echo ""
echo "Updating package lists in container..."
podman exec "$CONTAINER_NAME" bash -c "apt-get update > /dev/null 2>&1"

echo ""
echo "Installing tools in container..."
podman exec "$CONTAINER_NAME" bash -c "apt-get install -y sudo vim tcpdump usbutils pciutils ethtool iw iproute2 kmod > /dev/null 2>&1"

echo ""
echo "Installing packages in container..."
for DEB_FILE in $DEB_FILES; do
    REMOTE_DEB="/tmp/$(basename "$DEB_FILE")"
    echo "  Installing $(basename $DEB_FILE)..."
    podman exec "$CONTAINER_NAME" bash -c "apt-get install -y $REMOTE_DEB"
done

echo ""
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Success! Dropping into container shell."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ""
echo "Container: $CONTAINER_NAME"
echo "To restart later: podman start -ai $CONTAINER_NAME"
echo "To remove: podman rm -f $CONTAINER_NAME"
echo ""

podman exec -it "$CONTAINER_NAME" /bin/bash

echo ""
echo "Stopping container..."
podman stop "$CONTAINER_NAME" > /dev/null

echo "Container stopped but preserved."
echo "Restart with: podman start -ai $CONTAINER_NAME"
echo "Remove with: podman rm $CONTAINER_NAME"
