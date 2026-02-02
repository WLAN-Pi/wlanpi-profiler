# Hostapd Configuration Templates

This directory contains Jinja2 templates for generating hostapd configuration files for different frequency bands.

## Templates

### hostapd_2ghz.conf.j2
2.4 GHz band configuration (channels 1-14)

**Key Features**:
- HT (802.11n) with 40 MHz support
- NO VHT (802.11ac is 5 GHz only)
- HE (802.11ax / Wi-Fi 6) with 40 MHz max
- EHT (802.11be / Wi-Fi 7)
- WPA2/WPA3 transition mode
- 802.11r Fast Transition support
- 802.11k/v for roaming

### hostapd_5ghz.conf.j2
5 GHz band configuration (channels 36-173)

**Key Features**:
- HT (802.11n) with 40 MHz support
- VHT (802.11ac) with 160 MHz support
- HE (802.11ax / Wi-Fi 6) with 160 MHz support
- EHT (802.11be / Wi-Fi 7)
- WPA2/WPA3 transition mode
- 802.11r Fast Transition support
- 802.11k/v for roaming

## Template Variables

All templates accept the following variables:

### Basic Parameters
- `interface`: WLAN interface name (e.g., "wlan0")
- `ssid`: Network SSID (max 32 chars)
- `channel`: Channel number
- `hw_mode`: "g" for 2.4 GHz, "a" for 5 GHz
- `country_code`: Regulatory domain (e.g., "US")
- `generation_timestamp`: ISO timestamp of generation

### Capability Flags
- `ieee80211n_enabled`: Enable 802.11n (HT)
- `ieee80211ac_enabled`: Enable 802.11ac (VHT) - 5 GHz only
- `ieee80211ax_enabled`: Enable 802.11ax (HE)
- `ieee80211be_enabled`: Enable 802.11be (EHT)

### Security
- `wpa3_enabled`: Enable WPA3-SAE (requires driver support)
- `ft_enabled`: Enable 802.11r Fast Transition
- `mobility_domain`: 4-char hex mobility domain ID (e.g., "4133")

### VHT/HE/EHT Parameters (5 GHz)
- `vht_oper_chwidth`: VHT channel width (0=20/40, 1=80, 2=160)
- `vht_oper_centr_freq_seg0_idx`: VHT center frequency channel
- `he_oper_chwidth`: HE channel width (same as VHT)
- `he_oper_centr_freq_seg0_idx`: HE center frequency channel
- `eht_oper_chwidth`: EHT channel width (same as VHT/HE)
- `eht_oper_centr_freq_seg0_idx`: EHT center frequency channel

## Usage

Templates are automatically loaded by `profiler.config_generator.generate_hostapd_config()`.

Example:
```python
from profiler.config_generator import generate_hostapd_config

config_path = generate_hostapd_config(
    interface="wlan0",
    channel=36,
    ssid="Profiler Test",
    band="5ghz",
    ft_disabled=False,
    he_disabled=False,
    be_disabled=False,
    wpa3_enabled=True
)
```

## Capabilities Advertised

### Maximum Spatial Streams
Templates advertise **4 spatial streams** for HT/VHT/HE/EHT to trigger maximum client capabilities.

### Beamforming
- SU-BEAMFORMER/BEAMFORMEE (Single-User)
- MU-BEAMFORMER/BEAMFORMEE (Multi-User)
- BF-ANTENNA-4, SOUNDING-DIMENSION-4

### Channel Widths
- **2.4 GHz**: 20/40 MHz (HE), no VHT
- **5 GHz**: 20/40/80/160 MHz (VHT/HE/EHT)

### Security
- WPA2-PSK (backward compatible)
- WPA3-SAE (modern security)
- 802.11w Management Frame Protection (required for SAE)
- 802.11r Fast Transition (FT-PSK, FT-SAE)

## Notes

- 6 GHz templates not included (AFC not yet supported)
- All templates use passphrase "wlanpi!!" for testing
- Logging level set to minimal (level 2) to avoid disk filling
- WMM enabled for QoS support
- 802.11k/v enabled for improved roaming
