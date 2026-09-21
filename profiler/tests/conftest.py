"""
Pytest configuration for profiler.tests
"""

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers to avoid warnings."""
    config.addinivalue_line(
        "markers",
        "ondevice: marks tests as requiring WLAN Pi hardware (deselect with '-m \"not ondevice\"')",
    )
