#!/bin/bash
# Validate that localhost monitor interface is working
# by capturing beacons from ambient 2.4 GHz networks

set -e

INTERFACE="${1:-wlu1u3}"

echo "=== Localhost Monitor Validation Test ==="
echo ""
echo "This test validates your monitor interface by scanning 2.4 GHz channel 1"
echo "for ambient Wi-Fi beacons. If you see beacons, monitor mode is working."
echo ""

# Setup monitor mode on 2.4 GHz channel 1
echo "[1/3] Setting up monitor mode on 2.4 GHz channel 1..."

# Remove P2P interface if it exists
P2P_DEV="p2p-dev-$INTERFACE"
if ip link show "$P2P_DEV" 2>/dev/null; then
    echo "  - Removing P2P interface $P2P_DEV..."
    sudo iw dev "$P2P_DEV" del 2>/dev/null || true
fi

sudo nmcli device set "$INTERFACE" managed no 2>/dev/null || true
sudo rfkill unblock all
sudo ip link set "$INTERFACE" down
sudo iw dev "$INTERFACE" set type monitor
sudo iw dev "$INTERFACE" set channel 1
sudo ip link set "$INTERFACE" up

echo "✓ Interface configured"
echo ""

# Show interface status
echo "[2/3] Interface status:"
sudo iw dev "$INTERFACE" info
echo ""

# Capture beacons for 10 seconds
echo "[3/3] Capturing beacons on 2.4 GHz channel 1 (10 seconds)..."
echo "Looking for ANY beacon frames from ambient Wi-Fi networks..."
echo ""

BEACON_COUNT=$(sudo timeout 10 tcpdump -i "$INTERFACE" -c 50 'wlan type mgt subtype beacon' 2>&1 | tee /dev/stderr | grep -c "Beacon" || echo "0")

echo ""
echo "=== Results ==="
if [ "$BEACON_COUNT" -gt 0 ]; then
    echo "✓ SUCCESS: Captured $BEACON_COUNT beacon frames"
    echo "✓ Monitor mode is WORKING on localhost"
    echo ""
    echo "This means if you see 0 beacons from WLAN Pi on 5 GHz,"
    echo "the problem is with WLAN Pi transmission, NOT with your capture setup."
else
    echo "✗ FAILURE: No beacons captured"
    echo "✗ Monitor mode may not be working correctly"
    echo ""
    echo "Troubleshooting steps:"
    echo "  1. Check if there are any 2.4 GHz networks nearby"
    echo "  2. Try a different channel: sudo iw dev $INTERFACE set channel 6"
    echo "  3. Check interface with: sudo iw dev $INTERFACE info"
fi
echo ""
