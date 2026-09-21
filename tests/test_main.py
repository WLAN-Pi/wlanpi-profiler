from unittest.mock import patch

import pytest


def test_version(monkeypatch):
    """init() refuses to run on Python older than 3.13"""
    from profiler import __main__

    monkeypatch.setattr(__main__.sys, "version_info", (3, 6))
    with pytest.raises(SystemExit):
        __main__.init()


def test_platform(monkeypatch):
    """--pcap is allowed off-Linux; live capture is refused"""
    from profiler import __main__, manager

    monkeypatch.setattr(__main__.sys, "platform", "win32")
    monkeypatch.setattr(manager, "start", lambda args: None)

    # pcap mode is allowed on non-Linux
    monkeypatch.setattr(__main__.sys, "argv", ["profiler", "--pcap", "x.pcap"])
    __main__.main()

    # live capture mode exits on non-Linux
    monkeypatch.setattr(__main__.sys, "argv", ["profiler"])
    with pytest.raises(SystemExit):
        __main__.main()


def test_main(monkeypatch):
    from profiler import __main__

    monkeypatch.setattr(__main__.sys, "argv", ["profiler", "--pytest"])
    with pytest.raises(SystemExit) as exc:
        __main__.main()
    assert str(exc.value) == "pytest"


def test_init():
    from profiler import __main__

    with patch.object(__main__, "main") as mock_main:
        with patch.object(__main__, "__name__", "__main__"):
            __main__.init()

    mock_main.assert_called_once()


def test_handle_broken_pipe_without_sigpipe(monkeypatch):
    """handle_broken_pipe must not raise on platforms without SIGPIPE (Windows)."""
    import signal

    from profiler import __main__ as main_mod

    monkeypatch.delattr(signal, "SIGPIPE", raising=False)
    main_mod.handle_broken_pipe()
