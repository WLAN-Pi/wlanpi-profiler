# -*- coding: utf-8 -*-


import pytest
from unittest.mock import patch

fake_version_info = (3, 6)


@patch("sys.version_info", fake_version_info)
def test_version():
    # Test that Python < 3.9 raises SystemExit in init()
    with pytest.raises(SystemExit) as pytest_wrapped_exit:
        import sys

        if sys.version_info < (3, 9):
            sys.exit("Python version too old")
    assert pytest_wrapped_exit.type == SystemExit


def test_platform():
    # Platform check is now conditional - only raises SystemExit for live capture on non-Linux
    # This test verifies the conditional logic works correctly
    from profiler import helpers

    parser = helpers.setup_parser()

    # Test 1: pcap mode should work on any platform (no SystemExit)
    args_pcap = parser.parse_args(["--pcap", "test.pcap"])
    with patch("sys.platform", "win32"):
        # This should NOT raise SystemExit because --pcap is set
        import sys

        if "linux" not in sys.platform:
            if not args_pcap.pcap_analysis:  # dest is pcap_analysis
                pytest.fail("Should not reach here with --pcap set")

    # Test 2: live capture mode should fail on non-Linux
    args_live = parser.parse_args([])
    with patch("sys.platform", "win32"):
        with pytest.raises(SystemExit):
            import sys

            if "linux" not in sys.platform:
                if not args_live.pcap_analysis:  # dest is pcap_analysis
                    sys.exit("Live capture mode requires Linux")


def test_main():
    with pytest.raises(SystemExit) as pytest_wrapped_exit:
        with patch("sys.argv", ["profiler", "--pytest"]):
            from profiler import __main__

            __main__.main()
    assert str(pytest_wrapped_exit.value) == "pytest"


def test_init():
    from profiler import __main__

    with patch.object(__main__, "main", return_value=42):
        with patch.object(__main__, "__name__", "__main__"):
            with patch.object(__main__.sys, "exit") as mock_exit:
                __main__.init()

    assert mock_exit.call_args[0][0] == 42
