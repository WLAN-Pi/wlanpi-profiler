# -*- coding: utf-8 -*-

import argparse
import sys

import mock
import pytest
from mock import PropertyMock, patch

fake_version_info = (3, 6)


@patch("sys.version_info", fake_version_info)
def test_version():
    with pytest.raises(SystemExit) as pytest_wrapped_exit:
        from profiler2 import __main__
    assert pytest_wrapped_exit.type == SystemExit


@patch("sys.platform", "win32")
def test_platform():
    with pytest.raises(SystemExit) as pytest_wrapped_exit:
        from profiler2 import __main__
    assert pytest_wrapped_exit.type == SystemExit


def test_main():
    with pytest.raises(SystemExit) as pytest_wrapped_exit:
        with patch("sys.argv", ["profiler2", "--pytest"]):
            from profiler2 import __main__

            __main__.main()
    assert str(pytest_wrapped_exit.value) == "pytest"


def test_init():
    from profiler2 import __main__

    with patch.object(__main__, "main", return_value=42):
        with patch.object(__main__, "__name__", "__main__"):
            with patch.object(__main__.sys, "exit") as mock_exit:
                __main__.init()

    assert mock_exit.call_args[0][0] == 42
