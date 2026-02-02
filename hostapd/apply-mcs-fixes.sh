#!/bin/bash
#
# Apply MCS overrides to hostapd source files
# This script is called during the build process after the initial patch is applied
#

set -e

if [ ! -f "src/ap/ieee802_11_ht.c" ]; then
    echo "ERROR: Must be run from hostapd-2.11 directory"
    exit 1
fi

echo "Applying MCS overrides to advertise 4 spatial streams..."

# HT MCS Override
echo "  - Applying HT MCS override..."
cat > /tmp/ht_mcs_insert.txt << 'EOF'

	/* WLAN Pi Profiler: Override MCS set to advertise 4 spatial streams */
	cap->supported_mcs_set[0] = 0xff;  /* MCS 0-7  (SS1) */
	cap->supported_mcs_set[1] = 0xff;  /* MCS 8-15 (SS2) */
	cap->supported_mcs_set[2] = 0xff;  /* MCS 16-23 (SS3) */
	cap->supported_mcs_set[3] = 0xff;  /* MCS 24-31 (SS4) */
	wpa_printf(MSG_DEBUG, "PROFILER: Set HT MCS to advertise 4 spatial streams");
EOF
sed -i '/os_memcpy(cap->supported_mcs_set, hapd->iface->current_mode->mcs_set,/{
n
r /tmp/ht_mcs_insert.txt
}' src/ap/ieee802_11_ht.c

# VHT MCS Override
echo "  - Applying VHT MCS override..."
cat > /tmp/vht_mcs_insert.txt << 'EOF'

	/* WLAN Pi Profiler: Override VHT MCS set to advertise 4 spatial streams */
	/* Rx MCS Map: 0xffaa = MCS 0-9 for SS1-4, not supported for SS5-8 */
	cap->vht_supported_mcs_set.rx_map = host_to_le16(0xffaa);
	/* Tx MCS Map: same as Rx */
	cap->vht_supported_mcs_set.tx_map = host_to_le16(0xffaa);
	wpa_printf(MSG_DEBUG, "PROFILER: Set VHT MCS to advertise 4 spatial streams");
EOF
sed -i '/os_memcpy(&cap->vht_supported_mcs_set, mode->vht_mcs_set, 8);/r /tmp/vht_mcs_insert.txt' src/ap/ieee802_11_vht.c

# HE MCS Override
echo "  - Applying HE MCS override..."
cat > /tmp/he_mcs_insert.txt << 'EOF'

	/* WLAN Pi Profiler: Override HE MCS to advertise 4 spatial streams */
	cap->optional[0] = 0xaa;  /* Rx HE-MCS <= 80MHz: SS 1-2, MCS 0-11 each */
	cap->optional[1] = 0xaa;  /* Rx HE-MCS <= 80MHz: SS 3-4, MCS 0-11 each */
	cap->optional[2] = 0xaa;  /* Tx HE-MCS <= 80MHz: SS 1-2, MCS 0-11 each */
	cap->optional[3] = 0xaa;  /* Tx HE-MCS <= 80MHz: SS 3-4, MCS 0-11 each */
	if (mcs_nss_size >= 8) {
		cap->optional[4] = 0xaa;  /* Rx 160MHz: SS 1-2 */
		cap->optional[5] = 0xaa;  /* Rx 160MHz: SS 3-4 */
		cap->optional[6] = 0xaa;  /* Tx 160MHz: SS 1-2 */
		cap->optional[7] = 0xaa;  /* Tx 160MHz: SS 3-4 */
	}
	if (mcs_nss_size >= 12) {
		cap->optional[8] = 0xaa;   /* Rx 80+80MHz: SS 1-2 */
		cap->optional[9] = 0xaa;   /* Rx 80+80MHz: SS 3-4 */
		cap->optional[10] = 0xaa;  /* Tx 80+80MHz: SS 1-2 */
		cap->optional[11] = 0xaa;  /* Tx 80+80MHz: SS 3-4 */
	}
	wpa_printf(MSG_DEBUG, "PROFILER: Set HE MCS to advertise 4 spatial streams (mcs_nss_size=%u)", mcs_nss_size);
EOF
sed -i '/mode->he_capab\[opmode\].ppet,  ppet_size);/r /tmp/he_mcs_insert.txt' src/ap/ieee802_11_he.c

# EHT MCS Override
echo "  - Applying EHT MCS override..."
cat > /tmp/eht_mcs_insert.txt << 'EOF'

		/* WLAN Pi Profiler: Override EHT MCS to advertise 4 spatial streams */
		if (mcs_nss_len >= 3) {
			pos[0] = 0x44;  /* BW <= 80MHz: Rx/Tx MCS 0-9, 4 SS each */
			pos[1] = 0x44;  /* BW <= 80MHz: Rx/Tx MCS 10-11, 4 SS each */
			pos[2] = 0x44;  /* BW <= 80MHz: Rx/Tx MCS 12-13, 4 SS each */
		}
		if (mcs_nss_len >= 6) {
			pos[3] = 0x44;  /* BW = 160MHz: Rx/Tx MCS 0-9, 4 SS each */
			pos[4] = 0x44;  /* BW = 160MHz: Rx/Tx MCS 10-11, 4 SS each */
			pos[5] = 0x44;  /* BW = 160MHz: Rx/Tx MCS 12-13, 4 SS each */
		}
		if (mcs_nss_len >= 9) {
			pos[6] = 0x44;  /* BW = 320MHz: Rx/Tx MCS 0-9, 4 SS each */
			pos[7] = 0x44;  /* BW = 320MHz: Rx/Tx MCS 10-11, 4 SS each */
			pos[8] = 0x44;  /* BW = 320MHz: Rx/Tx MCS 12-13, 4 SS each */
		}
		wpa_printf(MSG_DEBUG, "PROFILER: Set EHT MCS to advertise 4 spatial streams (mcs_nss_len=%u)", mcs_nss_len);
EOF
sed -i '/os_memcpy(pos, eht_cap->mcs, mcs_nss_len);/r /tmp/eht_mcs_insert.txt' src/ap/ieee802_11_eht.c

rm -f /tmp/*_mcs_insert.txt

echo "✓ MCS overrides applied successfully"
