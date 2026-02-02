#!/bin/bash
# Apply MCS overrides to hostapd source files after extraction

set -e

cd "$(dirname "$0")/hostapd-2.11/src/ap"

echo "Applying MCS overrides..."

# HT MCS Override
sed -i '/os_memcpy(cap->supported_mcs_set, hapd->iface->current_mode->mcs_set,/a\
\
\t/* WLAN Pi Profiler: Override MCS set to advertise 4 spatial streams */\
\tcap->supported_mcs_set[0] = 0xff;  /* MCS 0-7  (SS1) */\
\tcap->supported_mcs_set[1] = 0xff;  /* MCS 8-15 (SS2) */\
\tcap->supported_mcs_set[2] = 0xff;  /* MCS 16-23 (SS3) */\
\tcap->supported_mcs_set[3] = 0xff;  /* MCS 24-31 (SS4) */\
\twpa_printf(MSG_DEBUG, "PROFILER: Set HT MCS to advertise 4 spatial streams");
' ieee802_11_ht.c

# VHT MCS Override  
sed -i '/os_memcpy(&cap->vht_supported_mcs_set, mode->vht_mcs_set, 8);/a\
\
\t/* WLAN Pi Profiler: Override VHT MCS set to advertise 4 spatial streams */\
\t/* Rx MCS Map: 0xffaa = MCS 0-9 for SS1-4, not supported for SS5-8 */\
\tcap->vht_supported_mcs_set.rx_map = host_to_le16(0xffaa);\
\t/* Tx MCS Map: same as Rx */\
\tcap->vht_supported_mcs_set.tx_map = host_to_le16(0xffaa);\
\twpa_printf(MSG_DEBUG, "PROFILER: Set VHT MCS to advertise 4 spatial streams");
' ieee802_11_vht.c

echo "✓ MCS overrides applied"
