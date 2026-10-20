#!/usr/bin/env python3
#
# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
Test schema v2 JSON output validation
"""

SCHEMA_V2_REQUIRED_FIELDS = [
    "mac",
    "is_laa",
    "manuf",
    "chipset",
    "capture_ssid",
    "capture_bssid",
    "capture_manuf",
    "capture_band",
    "capture_channel",
    "features",
    "pcapng",
    "schema_version",
    "profiler_version",
]

EXPECTED_FEATURES = [
    "dot11k",
    "dot11n",
    "dot11n_nss",
    "dot11r",
    "dot11v",
    "dot11w",
    "dot11ac",
    "dot11ac_nss",
    "dot11ax",
    "dot11ax_nss",
    "dot11be",
]


def validate_schema_v2(json_data: dict) -> tuple:
    """
    Validate JSON output against schema v2 requirements.

    Returns:
        tuple: (is_valid: bool, errors: list)
    """
    errors = []

    if json_data.get("schema_version") != 2:
        errors.append(
            f"Expected schema_version 2, got {json_data.get('schema_version')}"
        )

    for field in SCHEMA_V2_REQUIRED_FIELDS:
        if field not in json_data:
            errors.append(f"Missing required field: {field}")

    mac = json_data.get("mac", "")
    if mac and not all(c in "0123456789abcdefABCDEF-" for c in mac):
        errors.append(f"Invalid MAC format: {mac}")

    if "is_laa" in json_data and not isinstance(json_data["is_laa"], bool):
        errors.append(f"is_laa must be boolean, got {type(json_data['is_laa'])}")

    if "capture_band" in json_data:
        if not isinstance(json_data["capture_band"], str):
            errors.append(
                f"capture_band must be string, got {type(json_data['capture_band'])}"
            )
        elif json_data["capture_band"] not in ["0", "2", "5", "6"]:
            errors.append(
                f"capture_band must be '0', '2', '5', or '6', got '{json_data['capture_band']}'"
            )

    if "capture_channel" in json_data and not isinstance(
        json_data["capture_channel"], int
    ):
        errors.append(
            f"capture_channel must be integer, got {type(json_data['capture_channel'])}"
        )

    if "features" in json_data:
        if not isinstance(json_data["features"], dict):
            errors.append(f"features must be dict, got {type(json_data['features'])}")

    if "profiler_version" in json_data and not isinstance(
        json_data["profiler_version"], str
    ):
        errors.append(
            f"profiler_version must be string, got {type(json_data['profiler_version'])}"
        )

    return (len(errors) == 0, errors)


def test_validate_good_schema_v2():
    """Test validation with valid schema v2 data"""
    good_data = {
        "mac": "aa-bb-cc-dd-ee-ff",
        "is_laa": True,
        "manuf": "Apple",
        "chipset": "Unknown",
        "capture_ssid": "TestSSID",
        "capture_bssid": "11:22:33:44:55:66",
        "capture_manuf": "Intel",
        "capture_band": "5",
        "capture_channel": 36,
        "features": {
            "dot11k": 1,
            "dot11n": 1,
            "dot11n_nss": 2,
        },
        "pcapng": "base64encodeddata",
        "schema_version": 2,
        "profiler_version": "1.0.22",
    }

    is_valid, errors = validate_schema_v2(good_data)
    assert is_valid, f"Valid data failed validation: {errors}"
    print("✓ Valid schema v2 data passed validation")


def test_validate_missing_field():
    """Test validation with missing required field"""
    bad_data = {
        "mac": "aa-bb-cc-dd-ee-ff",
        "is_laa": True,
        "capture_bssid": "11:22:33:44:55:66",
        "capture_manuf": "Intel",
        "capture_band": "5",
        "capture_channel": 36,
        "features": {},
        "pcapng": "base64encodeddata",
        "schema_version": 2,
        "profiler_version": "1.0.22",
    }

    is_valid, errors = validate_schema_v2(bad_data)
    assert not is_valid, "Invalid data passed validation"
    assert any("capture_ssid" in err for err in errors), "Missing field not detected"
    print("✓ Missing field correctly detected")


def test_validate_wrong_schema_version():
    """Test validation with wrong schema version"""
    bad_data = {
        "mac": "aa-bb-cc-dd-ee-ff",
        "is_laa": True,
        "manuf": "Apple",
        "chipset": "Unknown",
        "capture_ssid": "TestSSID",
        "capture_bssid": "11:22:33:44:55:66",
        "capture_manuf": "Intel",
        "capture_band": "5",
        "capture_channel": 36,
        "features": {},
        "pcapng": "base64encodeddata",
        "schema_version": 1,
        "profiler_version": "1.0.22",
    }

    is_valid, errors = validate_schema_v2(bad_data)
    assert not is_valid, "Invalid schema version passed validation"
    assert any("schema_version" in err for err in errors), (
        "Wrong schema version not detected"
    )
    print("✓ Wrong schema version correctly detected")


if __name__ == "__main__":
    print("Running schema v2 validation tests...")
    test_validate_good_schema_v2()
    test_validate_missing_field()
    test_validate_wrong_schema_version()
    print("\nAll tests passed! ✓")
