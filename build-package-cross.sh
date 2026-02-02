#!/bin/bash
#
# Build wlanpi-profiler Debian package using sbuild (cross-compilation)
#
# This script uses sbuild/schroot for cross-architecture builds.
# Default target: Debian Bookworm (stable) on arm64 architecture
#
# Usage:
#   ./build-package-cross.sh                    # Build for bookworm/arm64 (default)
#   INPUTS_DISTRO=bullseye ./build-package-cross.sh  # Override distro
#   INPUTS_ARCH=armhf ./build-package-cross.sh       # Override architecture
#
# Supported architectures: arm64, armhf, amd64
# Supported distros: bookworm, bullseye, buster
#
# Note: This requires sbuild setup. For simpler native builds, use build-package-native.sh instead.
#

set -e

distro="${INPUTS_DISTRO:-bookworm}"
arch="${INPUTS_ARCH:-arm64}"

export DEBIAN_FRONTEND=noninteractive

echo "========================================="
echo "Building wlanpi-profiler Debian Package"
echo "Cross-compilation via sbuild"
echo "========================================="
echo "Target: ${distro}/${arch}"
echo ""

echo "Step 1: Installing build dependencies..."
sudo apt-get update -yqq
sudo apt-get install -yqq --no-install-recommends \
            devscripts \
            build-essential \
            sbuild \
            schroot \
            debootstrap \
            qemu-user-static

set +e
schroot_name="${distro}-${arch}-sbuild"
schroot_exists=$(sudo schroot -l | grep -o "chroot:${schroot_name}")
set -e

if [ "${schroot_exists}" != "chroot:${schroot_name}" ]; then
    echo ""
    echo "Step 2: Creating schroot environment (${schroot_name})..."
    echo "This may take several minutes on first run..."
    sudo sbuild-createchroot --arch=${arch} ${distro} \
        /srv/chroot/${schroot_name} http://deb.debian.org/debian
else
    echo ""
    echo "Step 2: Using existing schroot environment (${schroot_name})"
fi

echo ""
echo "Step 3: Generating source package (.dsc file)..."
res=$(dpkg-source -b ./)

echo ""
echo "Step 4: Extracting .dsc filename..."
dsc_file=$(echo "$res" | grep .dsc | grep -o '[^ ]*$')
echo "DSC file: ${dsc_file}"

echo ""
echo "Step 5: Building package in schroot..."
echo "This may take several minutes..."
sudo sbuild --arch=${arch} -c ${schroot_name} \
    -d ${distro} ../${dsc_file}

echo ""
echo "========================================="
echo "Package Build Complete!"
echo "========================================="
echo ""
echo "Generated packages:"
DEB_PACKAGE=$(find ./ -name "*.deb" | grep -v "dbgsym")
if [ -n "$DEB_PACKAGE" ]; then
    ls -lh $DEB_PACKAGE
    echo ""
    echo "To install the package:"
    echo "  sudo dpkg -i ${DEB_PACKAGE}"
    echo "  sudo apt-get install -f  # if there are dependency issues"
else
    echo "WARNING: No .deb files found!"
fi
echo ""

# Set output for GitHub Actions (if used in CI/CD)
echo "::set-output name=deb-package::${DEB_PACKAGE}"
