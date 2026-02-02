#!/bin/bash
#
# End-to-End OTA Beacon Testing Script
# Tests beacon transmission from WLAN Pi and captures on localhost
#
# Usage: ./test_ota_e2e.sh <bandwidth> [channel]
#   bandwidth: 20, 40, 80, 160
#   channel: default 36
#
# Example: ./test_ota_e2e.sh 160 36
#

set -e

# Configuration
WLANPI_IP="198.18.42.1"
WLANPI_USER="wlanpi"
WLANPI_IFACE="wlan0"
LOCALHOST_IFACE="wlu1u3"
CAPTURE_COUNT=20
TIMEOUT=30

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
BANDWIDTH="${1:-80}"
CHANNEL="${2:-36}"

if [[ ! "$BANDWIDTH" =~ ^(20|40|80|160)$ ]]; then
    echo -e "${RED}ERROR: Bandwidth must be 20, 40, 80, or 160${NC}"
    exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}OTA Beacon E2E Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Bandwidth: ${BANDWIDTH} MHz"
echo "Channel: ${CHANNEL}"
echo "WLAN Pi: ${WLANPI_IP}"
echo "Monitor Interface: ${LOCALHOST_IFACE}"
echo ""

# Step 1: Setup localhost monitor
echo -e "${YELLOW}[1/5] Setting up localhost monitor mode...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "${SCRIPT_DIR}/setup_monitor_localhost.sh" "${LOCALHOST_IFACE}" "${CHANNEL}"

if [ $? -ne 0 ]; then
    echo -e "${RED}FAILED: Could not setup monitor mode${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Monitor mode ready${NC}"
echo ""

# Step 2: Generate hostapd config on WLAN Pi
echo -e "${YELLOW}[2/5] Generating hostapd config on WLAN Pi...${NC}"

# Calculate center frequency based on bandwidth and channel
case $BANDWIDTH in
    20)
        VHT_CHWIDTH=0
        HE_CHWIDTH=0
        CENTER_FREQ=$CHANNEL
        ;;
    40)
        VHT_CHWIDTH=0
        HE_CHWIDTH=0
        CENTER_FREQ=$((CHANNEL + 2))
        ;;
    80)
        VHT_CHWIDTH=1
        HE_CHWIDTH=1
        # 80 MHz uses 4 channels, center is +6 from base
        CENTER_FREQ=$((CHANNEL + 6))
        ;;
    160)
        VHT_CHWIDTH=2
        HE_CHWIDTH=2
        # 160 MHz uses 8 channels, center is +14 from base
        CENTER_FREQ=$((CHANNEL + 14))
        ;;
esac

CONFIG_FILE="/tmp/hostapd_test_${BANDWIDTH}mhz.conf"

ssh "${WLANPI_USER}@${WLANPI_IP}" "cat > ${CONFIG_FILE}" <<EOF
interface=${WLANPI_IFACE}
driver=nl80211
ssid=TEST-${BANDWIDTH}MHZ
hw_mode=a
channel=${CHANNEL}
country_code=US
ieee80211d=1
ieee80211h=0

# HT (802.11n)
ieee80211n=1
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1]

# VHT (802.11ac)
ieee80211ac=1
vht_oper_chwidth=${VHT_CHWIDTH}
vht_oper_centr_freq_seg0_idx=${CENTER_FREQ}
vht_capab=[MAX-MPDU-11454][SHORT-GI-80][TX-STBC-2BY1][RX-STBC-1]

# HE (802.11ax)
ieee80211ax=1
he_oper_chwidth=${HE_CHWIDTH}
he_oper_centr_freq_seg0_idx=${CENTER_FREQ}

# Security
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=profiler
wpa_pairwise=CCMP

# Control
ctrl_interface=/var/run/wlanpi-profiler/hostapd
EOF

echo -e "${GREEN}✓ Config generated: ${CONFIG_FILE}${NC}"
echo ""

# Step 3: Start hostapd on WLAN Pi
echo -e "${YELLOW}[3/5] Starting hostapd on WLAN Pi...${NC}"

# Kill any existing hostapd
ssh "${WLANPI_USER}@${WLANPI_IP}" "sudo pkill -9 hostapd 2>/dev/null || true"
sleep 2

# Start hostapd in background
ssh "${WLANPI_USER}@${WLANPI_IP}" "sudo /opt/wlanpi-profiler/bin/hostapd ${CONFIG_FILE} > /tmp/hostapd.log 2>&1 &"
HOSTAPD_PID=$!

# Wait for hostapd to start
echo -n "Waiting for hostapd to start."
for i in {1..10}; do
    sleep 1
    echo -n "."
    if ssh "${WLANPI_USER}@${WLANPI_IP}" "pgrep hostapd > /dev/null"; then
        break
    fi
done
echo ""

# Check if hostapd is running
if ! ssh "${WLANPI_USER}@${WLANPI_IP}" "pgrep hostapd > /dev/null"; then
    echo -e "${RED}FAILED: hostapd did not start${NC}"
    echo -e "${YELLOW}Hostapd log:${NC}"
    ssh "${WLANPI_USER}@${WLANPI_IP}" "cat /tmp/hostapd.log"
    exit 1
fi

# Check hostapd log for errors
sleep 3
HOSTAPD_LOG=$(ssh "${WLANPI_USER}@${WLANPI_IP}" "tail -20 /tmp/hostapd.log")
if echo "$HOSTAPD_LOG" | grep -q "Could not set channel\|failed\|ERROR"; then
    echo -e "${RED}FAILED: hostapd encountered errors${NC}"
    echo -e "${YELLOW}Hostapd log:${NC}"
    echo "$HOSTAPD_LOG"
    ssh "${WLANPI_USER}@${WLANPI_IP}" "sudo pkill -9 hostapd 2>/dev/null || true"
    exit 1
fi

# Check if reached ENABLED state
if echo "$HOSTAPD_LOG" | grep -q "AP-ENABLED"; then
    echo -e "${GREEN}✓ Hostapd running (AP-ENABLED)${NC}"
else
    echo -e "${YELLOW}⚠ Hostapd running but may not be in ENABLED state${NC}"
    echo -e "${YELLOW}Last 10 lines of log:${NC}"
    echo "$HOSTAPD_LOG" | tail -10
fi
echo ""

# Step 4: Capture beacons on localhost
echo -e "${YELLOW}[4/5] Capturing beacons on localhost...${NC}"
CAPTURE_FILE="/tmp/beacons_${BANDWIDTH}mhz_ch${CHANNEL}.pcap"

echo "Capturing ${CAPTURE_COUNT} packets (timeout ${TIMEOUT}s)..."
timeout ${TIMEOUT} sudo tcpdump -i "${LOCALHOST_IFACE}" -w "${CAPTURE_FILE}" -c ${CAPTURE_COUNT} 'wlan type mgt subtype beacon' 2>&1 | grep -v "listening on" || true

if [ ! -f "${CAPTURE_FILE}" ]; then
    echo -e "${RED}FAILED: No capture file created${NC}"
    ssh "${WLANPI_USER}@${WLANPI_IP}" "sudo pkill -9 hostapd 2>/dev/null || true"
    exit 1
fi

PACKET_COUNT=$(tshark -r "${CAPTURE_FILE}" 2>/dev/null | wc -l)

if [ "$PACKET_COUNT" -eq 0 ]; then
    echo -e "${RED}FAILED: No beacons captured${NC}"
    ssh "${WLANPI_USER}@${WLANPI_IP}" "sudo pkill -9 hostapd 2>/dev/null || true"
    exit 1
fi

echo -e "${GREEN}✓ Captured ${PACKET_COUNT} beacons${NC}"
echo ""

# Step 5: Analyze beacons
echo -e "${YELLOW}[5/5] Analyzing captured beacons...${NC}"

# Extract first beacon for analysis
BEACON_ANALYSIS=$(tshark -r "${CAPTURE_FILE}" -Y "wlan.fc.type_subtype == 0x08" -c 1 -V 2>/dev/null)

# Check SSID
SSID=$(echo "$BEACON_ANALYSIS" | grep "SSID:" | head -1 | awk '{print $2}')
if [ "$SSID" == "TEST-${BANDWIDTH}MHZ" ]; then
    echo -e "${GREEN}✓ SSID: ${SSID}${NC}"
else
    echo -e "${YELLOW}⚠ SSID: ${SSID} (expected TEST-${BANDWIDTH}MHZ)${NC}"
fi

# Check channel
DETECTED_CHANNEL=$(echo "$BEACON_ANALYSIS" | grep "Current Channel:" | awk '{print $3}')
if [ "$DETECTED_CHANNEL" == "$CHANNEL" ]; then
    echo -e "${GREEN}✓ Channel: ${DETECTED_CHANNEL}${NC}"
else
    echo -e "${YELLOW}⚠ Channel: ${DETECTED_CHANNEL} (expected ${CHANNEL})${NC}"
fi

# Check HT capabilities
if echo "$BEACON_ANALYSIS" | grep -q "HT Capabilities"; then
    echo -e "${GREEN}✓ HT (802.11n) capabilities present${NC}"
else
    echo -e "${RED}✗ HT capabilities missing${NC}"
fi

# Check VHT capabilities (for 80/160 MHz)
if [ "$BANDWIDTH" -ge 80 ]; then
    if echo "$BEACON_ANALYSIS" | grep -q "VHT Capabilities"; then
        echo -e "${GREEN}✓ VHT (802.11ac) capabilities present${NC}"
        
        # Check VHT channel width
        VHT_WIDTH=$(echo "$BEACON_ANALYSIS" | grep "Channel Width:" | head -1 | awk '{print $3}')
        if [ ! -z "$VHT_WIDTH" ]; then
            echo -e "${GREEN}  VHT Channel Width: ${VHT_WIDTH}${NC}"
        fi
    else
        echo -e "${RED}✗ VHT capabilities missing${NC}"
    fi
fi

# Check HE capabilities (for Wi-Fi 6)
if echo "$BEACON_ANALYSIS" | grep -q "HE Capabilities"; then
    echo -e "${GREEN}✓ HE (802.11ax/Wi-Fi 6) capabilities present${NC}"
else
    echo -e "${YELLOW}⚠ HE capabilities missing${NC}"
fi

# Check signal strength
SIGNAL=$(tshark -r "${CAPTURE_FILE}" -T fields -e radiotap.dbm_antsignal -Y "wlan.fc.type_subtype == 0x08" 2>/dev/null | head -1)
if [ ! -z "$SIGNAL" ]; then
    echo -e "${GREEN}✓ Signal strength: ${SIGNAL} dBm${NC}"
fi

echo ""

# Step 6: Cleanup
echo -e "${YELLOW}Cleaning up...${NC}"
ssh "${WLANPI_USER}@${WLANPI_IP}" "sudo pkill -9 hostapd 2>/dev/null || true"
echo -e "${GREEN}✓ Stopped hostapd${NC}"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}TEST COMPLETED SUCCESSFULLY${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Capture file: ${CAPTURE_FILE}"
echo "Packets captured: ${PACKET_COUNT}"
echo ""
echo "To view detailed analysis:"
echo "  tshark -r ${CAPTURE_FILE} -V -Y 'wlan.fc.type_subtype == 0x08' | less"
echo ""
