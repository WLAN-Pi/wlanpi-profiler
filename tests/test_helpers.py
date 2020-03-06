# MAJOR TODO
import sys

sys.path.insert(0, "../")

from profiler2.helpers import is_ssid_valid

def test_is_ssid_valid():
    config = {}
    config["GENERAL"] = {}
    config["GENERAL"]["ssid"] = "WLAN Pi"
    assert is_ssid_valid(config) == True
    config["GENERAL"]["ssid"] = "WLAN Pi WLAN Pi WLAN Pi WLAN Pi WLAN Pi WLAN Pi"
    assert is_ssid_valid(config) == False