# -*- coding: utf-8 -*-
"""
Shared pytest fixtures for wlanpi-profiler tests
"""

import pytest
from unittest import mock


def pytest_configure(config):
    """Register custom markers to avoid warnings."""
    config.addinivalue_line(
        "markers",
        "ondevice: marks tests as requiring WLAN Pi hardware (deselect with '-m \"not ondevice\"')",
    )


@pytest.fixture
def mock_permission_error():
    """Fixture to mock file permission errors"""
    return mock.patch("builtins.open", side_effect=PermissionError("Permission denied"))


@pytest.fixture
def mock_disk_full():
    """Fixture to mock disk full errors (ENOSPC)"""
    return mock.patch(
        "builtins.open", side_effect=OSError(28, "No space left on device")
    )


@pytest.fixture
def mock_interface_down():
    """Fixture to mock interface disappearing"""

    def create_mock():
        return mock.MagicMock()

    return create_mock
