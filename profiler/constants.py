# -*- coding: utf-8 -*-
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2020-2021 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler.constants
~~~~~~~~~~~~~~~~~~

define constant values for app
"""

CONFIG_FILE = "/etc/wlanpi-profiler/config.ini"

DOT11_TYPE_MANAGEMENT = 0
DOT11_SUBTYPE_BEACON = 0x08
DOT11_SUBTYPE_PROBE_REQ = 0x04
DOT11_SUBTYPE_PROBE_RESP = 0x05
DOT11_SUBTYPE_ASSOC_REQ = 0x00
DOT11_SUBTYPE_ASSOC_RESP = 0x01
DOT11_SUBTYPE_REASSOC_REQ = 0x02
DOT11_SUBTYPE_AUTH_REQ = 0x0B

SSID_PARAMETER_SET_IE_TAG = 0
POWER_MIN_MAX_IE_TAG = 33  # power capability IE
SUPPORTED_CHANNELS_IE_TAG = 36  # client supported channels
HT_CAPABILITIES_IE_TAG = 45  # 802.11n
RSN_CAPABILITIES_IE_TAG = 48  # 802.11w
FT_CAPABILITIES_IE_TAG = 54  # 802.11r - mobility domain (MDE) IE
RM_CAPABILITIES_IE_TAG = 70  # 802.11k
EXT_CAPABILITIES_IE_TAG = 127  # 802.11v - Extended Capabilities
VHT_CAPABILITIES_IE_TAG = 191  # 802.11ac
VENDOR_SPECIFIC_IE_TAG = 221  # Vendor Specific IE
IE_EXT_TAG = 255  # Element ID Extension field
HE_CAPABILITIES_IE_EXT_TAG = 35  # 802.11ax HE Capabilities IE
HE_OPERATION_IE_EXT_TAG = 36  # 802.11ax HE Operation IE
HE_SPATIAL_REUSE_IE_EXT_TAG = 39  # 802.11ax Spatial Reuse Paramater IE
HE_6_GHZ_BAND_CAP_IE_EXT_TAG = 59  # 802.11ax 6 GHz capabilities IE

CHANNELS = {
    "2G": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    "5G": [
        36,
        40,
        44,
        48,
        52,
        56,
        60,
        64,
        100,
        104,
        108,
        112,
        116,
        120,
        124,
        128,
        132,
        136,
        140,
        149,
        153,
        157,
        161,
        165,
    ],
    "6G": [5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229],
}

_20MHZ_FREQUENCY_CHANNEL_MAP = {
    2412: 1,
    2417: 2,
    2422: 3,
    2427: 4,
    2432: 5,
    2437: 6,
    2442: 7,
    2447: 8,
    2452: 9,
    2457: 10,
    2462: 11,
    2467: 12,
    2472: 13,
    2484: 14,
    5160: 32,
    5170: 34,
    5180: 36,
    5190: 38,
    5200: 40,
    5210: 42,
    5220: 44,
    5230: 46,
    5240: 48,
    5250: 50,
    5260: 52,
    5270: 54,
    5280: 56,
    5290: 58,
    5300: 60,
    5310: 62,
    5320: 64,
    5340: 68,
    5480: 96,
    5500: 100,
    5510: 102,
    5520: 104,
    5530: 106,
    5540: 108,
    5550: 110,
    5560: 112,
    5570: 114,
    5580: 116,
    5590: 118,
    5600: 120,
    5610: 122,
    5620: 124,
    5630: 126,
    5640: 128,
    5660: 132,
    5670: 134,
    5680: 136,
    5700: 140,
    5710: 142,
    5720: 144,
    5745: 149,
    5755: 151,
    5765: 153,
    5775: 155,
    5785: 157,
    5795: 159,
    5805: 161,
    5825: 165,
    5955: 1,
    5975: 5,
    5995: 9,
    6015: 13,
    6035: 17,
    6055: 21,
    6075: 25,
    6095: 29,
    6115: 33,
    6135: 37,
    6155: 41,
    6175: 45,
    6195: 49,
    6215: 53,
    6235: 57,
    6255: 61,
    6275: 65,
    6295: 69,
    6315: 73,
    6335: 77,
    6355: 81,
    6375: 85,
    6395: 89,
    6415: 93,
    6435: 97,
    6455: 101,
    6475: 105,
    6495: 109,
    6515: 113,
    6535: 117,
    6555: 121,
    6575: 125,
    6595: 129,
    6615: 133,
    6635: 137,
    6655: 141,
    6675: 145,
    6695: 149,
    6715: 153,
    6735: 157,
    6755: 161,
    6775: 165,
    6795: 169,
    6815: 173,
    6835: 177,
    6855: 181,
    6875: 185,
    6895: 189,
    6915: 193,
    6935: 197,
    6955: 201,
    6975: 205,
    6995: 209,
    7015: 213,
    7035: 217,
    7055: 221,
    7075: 225,
    7095: 229,
    7115: 233,
}
