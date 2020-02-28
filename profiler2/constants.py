# -*- coding: utf-8 -*-

"""
profiler2.constants
~~~~~~~~~~~~~~~~~~~

define constant values for app
"""

DOT11_TYPE_MANAGEMENT = 0
DOT11_SUBTYPE_BEACON = 0x08
DOT11_SUBTYPE_PROBE_REQ = 0x04
DOT11_SUBTYPE_PROBE_RESP = 0x05
DOT11_SUBTYPE_ASSOC_REQ = 0x00
DOT11_SUBTYPE_ASSOC_RESP = 0x01
DOT11_SUBTYPE_REASSOC_REQ = 0x02
DOT11_SUBTYPE_AUTH_REQ = 0x0B

POWER_MIN_MAX_TAG = 33  # power capability IE
SUPPORTED_CHANNELS_TAG = 36  # client supported channels
HT_CAPABILITIES_TAG = 45  # 802.11n
RSN_CAPABILITIES_TAG = 48  # 802.11w
FT_CAPABILITIES_TAG = 54  # 802.11r - mobility domain (MDE) IE
RM_CAPABILITIES_TAG = 70  # 802.11k
EXT_CAPABILITIES_TAG = 127  # 802.11v - Extended Capabilities
VHT_CAPABILITIES_TAG = 191  # 802.11ac
EXT_IE_TAG = 255  # Element ID Extension field

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
