"""
Pytest configuration for profiler.tests
"""


def pytest_configure(config):
    """Register custom markers to avoid warnings."""
    config.addinivalue_line(
        "markers",
        "ondevice: marks tests as requiring WLAN Pi hardware (deselect with '-m \"not ondevice\"')",
    )
