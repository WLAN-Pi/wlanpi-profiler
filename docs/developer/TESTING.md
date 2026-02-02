# Testing guide

Hardware test suite for validating profiler installations on WLAN Pi devices.

## Overview

The profiler includes a comprehensive test suite for on-device validation. Tests are isolated via pytest fixtures and run in stages to prevent state contamination.

## Running tests

### Run all tests

```bash
sudo profiler test
```

### Run with verbose output

```bash
sudo profiler test -v
```

### Run specific test categories

```bash
# Skip on-device tests (run offline tests only)
sudo profiler test -m "not ondevice"

# Run only on-device tests
sudo profiler test -m ondevice
```

## What gets tested

### Binary and tool availability

- Hostapd binary presence and executable permissions
- Hostapd_cli binary presence and executable permissions
- Profiler CLI availability in system PATH

### Configuration and environment

- Configuration file existence
- Required data directories
- Network interface discovery and capabilities
- Wireless tools availability (iw, ip, rfkill)

### Interface staging

- Interface preparation for monitor mode
- Virtual interface creation
- Mode switching validation

### Integration tests

- End-to-end profiler operation
- Frame capture validation
- Result file generation

## Test categories

### Unit tests

Fast tests that don't require hardware:

- Configuration parsing
- Data structure validation
- Utility function testing

Run with:

```bash
sudo profiler test -m "not ondevice"
```

### On-device tests

Tests requiring actual WLAN Pi hardware with wireless interfaces:

- Interface staging
- Frame injection
- Live capture validation

These tests are marked with `@pytest.mark.ondevice` and are skipped by default when wireless interfaces are not detected.

Run with:

```bash
sudo profiler test -m ondevice
```

## Test structure

```
tests/
├── conftest.py              # Shared fixtures and configuration
├── hardware/
│   ├── __init__.py
│   ├── test_interface_staging.py
│   └── test_ota_beacons.py
└── hardware/
    └── ondevice/
        ├── __init__.py
        ├── test_health_checks.py
        └── test_interface_staging.py
```

## Writing tests

### Basic test structure

```python
import pytest

def test_example():
    """Test description"""
    assert True
```

### On-device test marker

```python
import pytest

@pytest.mark.ondevice
def test_requires_hardware():
    """This test only runs on actual hardware"""
    # Test code here
    pass
```

### Using fixtures

```python
def test_with_interface(interface_fixture):
    """Test using the interface fixture"""
    # interface_fixture provides a prepared interface
    pass
```

## Continuous integration

Tests are run automatically on:

- Pull requests
- Releases
- Scheduled builds

CI runs use the `-m "not ondevice"` flag to skip hardware-dependent tests.

## Manual testing checklist

Before releasing:

- [ ] Run full test suite: `sudo profiler test`
- [ ] Test on clean WLAN Pi OS installation
- [ ] Test with different adapters (mt76x2u, iwlwifi, etc.)
- [ ] Verify pcap analysis mode works
- [ ] Test configuration file overrides
- [ ] Verify web interface displays results

## Troubleshooting tests

### Tests failing with permission errors

Ensure you're running with sudo:

```bash
sudo profiler test
```

### On-device tests being skipped

Check that wireless interfaces are available:

```bash
iw dev
```

### Test isolation failures

If tests are interfering with each other:

1. Reset the interface manually
2. Restart the test suite
3. Check for stale processes: `ps aux | grep hostapd`

## Test data

Test fixtures and sample data are stored in:

- `tests/fixtures/` - Sample pcap files and configurations
- `tests/data/` - Expected output files

## See also

- [Development guide](../DEVELOPMENT.md) - Building and contributing
- [Contributing guide](../CONTRIBUTING.md) - How to contribute
- [Interface staging](../INTERFACE_STAGING.md) - How interface preparation works
