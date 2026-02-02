#!/bin/bash
# Robust script to setup localhost Wi-Fi interface for monitor mode
# Handles all common issues: rfkill, NetworkManager, P2P interfaces, etc.

set -e

INTERFACE="${1:-wlu1u3}"
CHANNEL="${2:-36}"  # Default to 5 GHz channel 36

echo "=== Setting up $INTERFACE for monitor mode ==="
echo ""

echo "[1/6] Unblocking RF-kill..."
sudo rfkill unblock all
echo "✓ RF unblocked"
echo ""

echo "[2/6] Removing from NetworkManager..."
sudo nmcli device set "$INTERFACE" managed no 2>/dev/null || true
echo "✓ Removed from NetworkManager"
echo ""

echo "[3/6] Removing P2P interface if exists..."
P2P_DEV="p2p-dev-$INTERFACE"
if ip link show "$P2P_DEV" &>/dev/null; then
    echo "  Found $P2P_DEV, removing..."
    sudo iw dev "$P2P_DEV" del 2>/dev/null || true
    sleep 1
fi
echo "✓ P2P interface handled"
echo ""

echo "[4/6] Checking if we're already in monitor mode..."
CURRENT_TYPE=$(sudo iw dev "$INTERFACE" info | grep "type" | awk '{print $2}')
echo "  Current type: $CURRENT_TYPE"

if [ "$CURRENT_TYPE" != "monitor" ]; then
    echo "  Setting to monitor mode..."
    sudo ip link set "$INTERFACE" down
    sudo iw dev "$INTERFACE" set type monitor
    sudo ip link set "$INTERFACE" up
    echo "✓ Set to monitor mode"
else
    echo "✓ Already in monitor mode"
fi
echo ""

echo "[5/6] Setting channel $CHANNEL..."
sudo ip link set "$INTERFACE" down
sleep 1
sudo iw dev "$INTERFACE" set channel "$CHANNEL" || {
    echo "⚠ Failed to set channel, trying with interface up..."
    sudo ip link set "$INTERFACE" up
    sleep 1
    sudo iw dev "$INTERFACE" set channel "$CHANNEL" || {
        echo "⚠ Still failed, continuing anyway..."
    }
}
sudo ip link set "$INTERFACE" up
echo "✓ Channel configuration attempted"
echo ""

echo "[6/6] Final interface state:"
sudo iw dev "$INTERFACE" info
echo ""

echo "=== Quick beacon capture test (3 seconds) ==="
echo "Capturing to verify interface is working..."
FRAME_COUNT=$(sudo timeout 3 tcpdump -i "$INTERFACE" -c 10 2>&1 | grep -c "packets captured" || echo "0")
if [ "$FRAME_COUNT" -gt 0 ]; then
    echo "✓ Interface is capturing frames"
else
    echo "⚠ No frames captured in 3 seconds (may be normal if channel is quiet)"
fi
echo ""

echo "=== Setup complete ==="
echo "Interface: $INTERFACE"
echo "Mode: monitor"
echo "Channel: $CHANNEL"
echo ""
echo "To capture beacons:"
echo "  sudo tcpdump -i $INTERFACE -vvv 'wlan type mgt subtype beacon'"
echo ""
