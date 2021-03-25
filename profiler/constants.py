# -*- coding: utf-8 -*-
#
# profiler: a Wi-Fi client capability analyzer
# Copyright 2021 Josh Schmelzle
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

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

CHANNELS = [
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
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
]

_20MHZ_CHANNEL_LIST = {
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
    5845: 169,
    5865: 173,
    4915: 183,
    4920: 184,
    4925: 185,
    4935: 187,
    4940: 188,
    4945: 189,
    4960: 192,
    4980: 196,
}
