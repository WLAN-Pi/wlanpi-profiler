#!/bin/bash
#
# OTA Test Runner Script
#
# This script runs the OTA beacon verification tests.
# Must be run with sudo due to scapy raw socket requirements.
#
# Usage:
#   sudo ./tests/run_ota_tests.sh [test_name]
#
# Examples:
#   sudo ./tests/run_ota_tests.sh                    # Run all OTA tests
#   sudo ./tests/run_ota_tests.sh test_wpa2_beacons  # Run specific test
#

set -e

# Configuration
OTA_INTERFACE=${PROFILER_OTA_INTERFACE:-wlu1u3}
REMOTE_HOST=${PROFILER_REMOTE_HOST:-wlanpi@198.18.42.1}
REMOTE_CHANNEL=${PROFILER_REMOTE_CHANNEL:-36}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== WLAN Pi Profiler OTA Test Runner ===${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR: This script must be run with sudo${NC}"
    echo "Reason: Scapy requires raw socket access for beacon capture"
    echo ""
    echo "Usage: sudo ./tests/run_ota_tests.sh"
    exit 1
fi

# Verify monitor interface exists
echo -e "${YELLOW}Checking monitor interface: $OTA_INTERFACE${NC}"
if ! ip link show "$OTA_INTERFACE" &>/dev/null; then
    echo -e "${RED}ERROR: Interface $OTA_INTERFACE not found${NC}"
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+" | awk '{print "  - " $2}' | sed 's/:$//'
    exit 1
fi

# Configure monitor mode
echo -e "${YELLOW}Configuring $OTA_INTERFACE for monitor mode${NC}"
ip link set "$OTA_INTERFACE" down
iw dev "$OTA_INTERFACE" set type monitor
ip link set "$OTA_INTERFACE" up

# Verify monitor mode
if ! iw dev "$OTA_INTERFACE" info | grep -q "type monitor"; then
    echo -e "${RED}ERROR: Failed to set $OTA_INTERFACE to monitor mode${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Monitor interface configured${NC}"

# Test SSH connectivity
echo -e "${YELLOW}Testing SSH connection to $REMOTE_HOST${NC}"
if ! ssh -o ConnectTimeout=5 "$REMOTE_HOST" "echo 'SSH OK'" &>/dev/null; then
    echo -e "${RED}ERROR: Cannot connect to $REMOTE_HOST via SSH${NC}"
    echo "Please ensure:"
    echo "  1. Remote host is reachable"
    echo "  2. SSH key is configured (ssh-copy-id $REMOTE_HOST)"
    exit 1
fi

echo -e "${GREEN}✓ SSH connectivity verified${NC}"

# Verify profiler is installed on remote
echo -e "${YELLOW}Verifying profiler on remote${NC}"
REMOTE_VERSION=$(ssh "$REMOTE_HOST" "profiler --version 2>&1" || echo "FAILED")
if [ "$REMOTE_VERSION" = "FAILED" ]; then
    echo -e "${RED}ERROR: Profiler not found on remote host${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Remote profiler version: $REMOTE_VERSION${NC}"
echo ""

# Determine which tests to run
TEST_SPEC="tests/test_ota_beacons.py"
if [ -n "$1" ]; then
    if [[ "$1" == *"::"* ]]; then
        # Full test path provided
        TEST_SPEC="$1"
    else
        # Just test name provided, search for it
        TEST_SPEC="tests/test_ota_beacons.py::*::$1"
    fi
    echo -e "${YELLOW}Running specific test: $TEST_SPEC${NC}"
else
    echo -e "${YELLOW}Running all OTA tests${NC}"
fi

echo ""
echo -e "${GREEN}=== Starting OTA Tests ===${NC}"
echo "  Interface: $OTA_INTERFACE"
echo "  Remote: $REMOTE_HOST"
echo "  Channel: $REMOTE_CHANNEL"
echo ""

# Run pytest with proper environment
cd "$(dirname "$0")/.."

PROFILER_OTA_TESTS=1 \
PROFILER_OTA_INTERFACE="$OTA_INTERFACE" \
PROFILER_REMOTE_HOST="$REMOTE_HOST" \
PROFILER_REMOTE_CHANNEL="$REMOTE_CHANNEL" \
python -m pytest "$TEST_SPEC" -v --tb=short

TEST_RESULT=$?

echo ""
if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}=== All Tests Passed! ===${NC}"
else
    echo -e "${RED}=== Some Tests Failed ===${NC}"
    echo "Check output above for details"
fi

exit $TEST_RESULT
