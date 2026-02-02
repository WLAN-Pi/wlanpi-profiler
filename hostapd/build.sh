#!/bin/bash
#
# Deterministic build script for patched hostapd
#
# This script is called by debian/rules during package build.
# It produces a binary at hostapd-2.11/hostapd/hostapd
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARBALL="hostapd-2.11.tar.gz"
PATCH="hostapd_profiler.patch"
EXPECTED_SHA256="2b3facb632fd4f65e32f4bf82a76b4b72c501f995a4f62e330219fe7aed1747a"

echo "========================================="
echo "Building Patched Hostapd for wlanpi-profiler"
echo "========================================="

# Verify checksum
echo "Verifying source tarball checksum..."
echo "$EXPECTED_SHA256  $TARBALL" | sha256sum -c - || {
    echo "ERROR: SHA256 checksum mismatch!"
    echo "Expected: $EXPECTED_SHA256"
    echo "Got:      $(sha256sum $TARBALL | awk '{print $1}')"
    exit 1
}
echo "✓ Checksum verified"

# Clean previous build if exists
if [ -d "hostapd-2.11" ]; then
    echo "Cleaning previous build..."
    rm -rf hostapd-2.11
fi

# Extract
echo "Extracting source tarball..."
tar -xzf "$TARBALL"
echo "✓ Source extracted"

# Apply patches
echo "Applying profiler patches..."
cd hostapd-2.11

# Apply all patches in order
echo "Applying profiler patches..."

# 1. Version string (cosmetic)
if [ -f "../patches/profiler_version_string.patch" ]; then
    echo "  - Applying profiler_version_string.patch..."
    patch -p1 < "../patches/profiler_version_string.patch" || {
        echo "    ERROR: Failed to apply version string patch!"
        exit 1
    }
    echo "    ✓ Applied"
fi

# 2. hw_features profiler patch (capability validation + NO-IR bypass)
if [ -f "../patches/hw_features_profiler.patch" ]; then
    echo "  - Applying hw_features_profiler.patch..."
    patch -p1 < "../patches/hw_features_profiler.patch" || {
        echo "    ERROR: Failed to apply hw_features profiler patch!"
        exit 1
    }
    echo "    ✓ Applied"
fi

# 2e. VHT 4 SS advertising
if [ -f "../patches/vht_advertise_4ss.patch" ]; then
    echo "  - Applying vht_advertise_4ss.patch..."
    patch -p1 < "../patches/vht_advertise_4ss.patch" || {
        echo "    ERROR: Failed to apply VHT 4 SS advertising patch!"
        exit 1
    }
    echo "    ✓ Applied"
fi

# 2f. VHT Operation override (advertise 160 MHz while operating at 20 MHz)
if [ -f "../patches/vht_operation_override.patch" ]; then
    echo "  - Applying vht_operation_override.patch..."
    patch -p1 < "../patches/vht_operation_override.patch" || {
        echo "    ERROR: Failed to apply VHT Operation override patch!"
        exit 1
    }
    echo "    ✓ Applied"
fi

# 3. Apply MLD/EML config patches
if [ -f "../patches/add_mld_config_struct.patch" ]; then
    echo "  - Applying add_mld_config_struct.patch..."
    patch -p1 < "../patches/add_mld_config_struct.patch" || {
        echo "    ERROR: Failed to apply MLD config struct patch!"
        exit 1
    }
    echo "    ✓ Applied"
fi

if [ -f "../patches/add_mld_config_parsing.patch" ]; then
    echo "  - Applying add_mld_config_parsing.patch..."
    patch -p1 < "../patches/add_mld_config_parsing.patch" || {
        echo "    ERROR: Failed to apply MLD config parsing patch!"
        exit 1
    }
    echo "    ✓ Applied"
fi

if [ -f "../patches/add_mld_caps_override.patch" ]; then
    echo "  - Applying add_mld_caps_override.patch..."
    patch -p1 < "../patches/add_mld_caps_override.patch" || {
        echo "    ERROR: Failed to apply MLD caps override patch!"
        exit 1
    }
    echo "    ✓ Applied"
fi
# 4. Apply all capability override patches (hostapd_*.patch)
for patch_file in ../patches/hostapd_*.patch; do
    if [ -f "$patch_file" ]; then
        patch_name=$(basename "$patch_file")
        echo "  - Applying $patch_name..."
        patch -p1 < "$patch_file" || {
            echo "    ERROR: Failed to apply $patch_name!"
            exit 1
        }
        echo "    ✓ Applied"
    fi
done

# 4b. Apply EHT operation patches (eht_*.patch)
for patch_file in ../patches/eht_*.patch; do
    if [ -f "$patch_file" ]; then
        patch_name=$(basename "$patch_file")
        echo "  - Applying $patch_name..."
        patch -p1 < "$patch_file" || {
            echo "    ERROR: Failed to apply $patch_name!"
            exit 1
        }
        echo "    ✓ Applied"
    fi
done

# 4c. Apply MLD patches (mld_*.patch)
for patch_file in ../patches/mld_*.patch; do
    if [ -f "$patch_file" ]; then
        patch_name=$(basename "$patch_file")
        echo "  - Applying $patch_name..."
        patch -p1 < "$patch_file" || {
            echo "    ERROR: Failed to apply $patch_name!"
            exit 1
        }
        echo "    ✓ Applied"
    fi
done

echo "✓ All patches applied successfully"

# 4d. Apply DS Parameter Set patch for 5 GHz
if [ -f "../patches/ds_params_5ghz.patch" ]; then
    echo "  - Applying ds_params_5ghz.patch (DS Parameter Set for 5 GHz)..."
    patch -p1 < "../patches/ds_params_5ghz.patch" || {
        echo "    ERROR: Failed to apply DS Parameter Set patch!"
        exit 1
    }
    echo "    ✓ Applied"
fi

# 5. Apply Extended Capabilities patch
if [ -f "../patches/ext_cap_profiler.patch" ]; then
    echo "  - Applying ext_cap_profiler.patch (Extended Capabilities)..."
    patch -p1 < "../patches/ext_cap_profiler.patch" || {
        echo "    ERROR: Failed to apply Extended Capabilities patch!"
        exit 1
    }
    echo "    ✓ Applied"
fi

# Now move to hostapd directory for build
cd hostapd

# Configure
echo "Configuring build..."
cp defconfig .config

# Enable 802.11n and 802.11ac (disabled by default in defconfig)
sed -i 's/#CONFIG_IEEE80211N=y/CONFIG_IEEE80211N=y/' .config
sed -i 's/#CONFIG_IEEE80211AC=y/CONFIG_IEEE80211AC=y/' .config

# Add required features
cat >> .config <<EOF

# Required features for profiler
CONFIG_LIBNL32=y
CONFIG_SAE=y
CONFIG_OWE=y
CONFIG_IEEE80211AX=y
CONFIG_IEEE80211BE=y
CONFIG_MBO=y
CONFIG_WPA3_SAE=y
CONFIG_IEEE80211W=y
CONFIG_WNM=y

# Additional features for config template compatibility
CONFIG_IEEE80211R=y
CONFIG_INTERWORKING=y
CONFIG_HS20=y
EOF

echo "✓ Build configured"

# Build
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
echo "Binary location: $(pwd)/hostapd"
ls -lh hostapd
echo ""
echo "Binary size: $(du -h hostapd | awk '{print $1}')"
echo "Strip to reduce size: strip hostapd"
echo "========================================="
