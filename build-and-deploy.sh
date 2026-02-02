#!/bin/bash
#
# Build Debian package and deploy to WLAN Pi device
#
set -e

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Configuration - Edit these values as needed
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PACKAGE_NAME="wlanpi-profiler"
WLANPI_IP="198.18.42.1"
WLANPI_USER="wlanpi"
DEPLOY_PATH="/tmp"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Script logic - No need to edit below
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Build and Deploy $PACKAGE_NAME"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

# Step 1: Check if target is reachable
echo "Step 1: Checking connection to $WLANPI_IP..."
if ! ping -c 1 -W 2 "$WLANPI_IP" > /dev/null 2>&1; then
    echo "ERROR: Cannot reach $WLANPI_IP"
    echo "Please check network connection and IP address."
    exit 1
fi
echo "Target is reachable."

# Step 2: Build the package
echo ""
echo "Step 2: Building package..."
echo "Step 1: Building package..."
if ! bash build-package-native.sh; then
    echo ""
    echo "ERROR: Build failed!"
    echo "Deployment aborted."
    exit 1
fi

# Step 3: Read build manifest
echo ""
echo "Step 3: Reading build manifest..."
if [ ! -f .build-manifest.txt ]; then
    echo "ERROR: Build manifest not found!"
    exit 1
fi

DEB_FILES=$(cat .build-manifest.txt)

if [ -z "$DEB_FILES" ]; then
    echo "ERROR: No packages listed in build manifest!"
    exit 1
fi

echo "Packages to deploy:"
for f in $DEB_FILES; do echo "  $(basename $f)"; done

# Step 4: Copy to WLAN Pi
echo ""
echo "Step 4: Copying to WLAN Pi at $WLANPI_IP..."
for DEB_FILE in $DEB_FILES; do
    if ! scp "$DEB_FILE" "$WLANPI_USER@$WLANPI_IP:$DEPLOY_PATH/"; then
        echo "ERROR: Failed to copy $(basename $DEB_FILE)"
        exit 1
    fi
done

# Step 5: Install on WLAN Pi
echo ""
echo "Step 5: Installing on WLAN Pi..."
for DEB_FILE in $DEB_FILES; do
    REMOTE_DEB="$DEPLOY_PATH/$(basename "$DEB_FILE")"
    if ! ssh "$WLANPI_USER@$WLANPI_IP" "sudo dpkg -i $REMOTE_DEB"; then
        echo ""
        echo "WARNING: Installation may have issues."
        echo "You may need to run: ssh $WLANPI_USER@$WLANPI_IP 'sudo apt-get install -f'"
        exit 1
    fi
done

echo ""
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Success! Package deployed and installed."
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
