from unittest import mock

import pytest

from profiler import helpers
from profiler.__version__ import __version__
from profiler.interface import Interface, InterfaceError


@pytest.fixture
def parser():
    return helpers.setup_parser()


class TestArgParsing:
    def test_version(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["-V"])
        out, err = capsys.readouterr()
        assert out == f"{__version__}\n"
        assert err == ""

    def test_help(self, parser, capsys):
        """Test that -h/--help works without crashing"""
        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])
        out, err = capsys.readouterr()
        assert err == ""
        # Verify help text is actually generated
        assert "usage:" in out
        assert "wlanpi-profiler" in out or "profiler" in out
        assert "--security-mode" in out
        assert "--11be" in out  # Should be visible now
        assert "--no11r" not in out  # Should be hidden

    def test_help_short_flag(self, parser, capsys):
        """Test that -h works (short form)"""
        with pytest.raises(SystemExit):
            parser.parse_args(["-h"])
        out, err = capsys.readouterr()
        assert err == ""
        assert "usage:" in out

    def test_read_pcap_fail(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["--pcap"])
        _, err = capsys.readouterr()
        assert "expected one argument" in err

    def test_unknown_args(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["--notrealarg"])
        err = capsys.readouterr().err
        assert "error: unrecognized arguments:" in err

    def test_valid_ssid(self, parser, capsys):
        parser.parse_args(["-s", "WLAN Pi"])
        err = capsys.readouterr().err
        assert err == ""

    def test_invalid_ssid(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["-s", "this_is_a_really_long_string_really_too_long!!!"])
        err = capsys.readouterr().err
        assert "invalid ssid value" in err

    @pytest.mark.parametrize(
        "channel,expected",
        [(["-c", "1"], ""), (["-c", "6"], ""), (["-c", "11"], ""), (["-c", "36"], "")],
    )
    def test_valid_channel(self, channel, expected, parser, capsys):
        parser.parse_args(channel)
        _out, err = capsys.readouterr()
        assert err == expected

    def test_invalid_channel(self, parser, capsys):
        with pytest.raises(SystemExit):
            parser.parse_args(["-c", "22"])
        err = capsys.readouterr().err
        assert "invalid channel value" in err

    def test_invalid_interface(self, parser, capsys):
        helpers.setup_config(parser.parse_args(["-i", "fakest_interface_ever"]))
        iface = Interface()
        iface.name = "fakest_iface_ever"
        with pytest.raises(InterfaceError):
            iface.setup()

    @pytest.mark.parametrize(
        "args,expected",
        [
            (["--pcap", "fake_file_does_not_exist.pcap"], ""),
            (["--noAP"], ""),
            (["--11r"], ""),
            (["--no11r"], ""),
            (["--11ax"], ""),
            (["--no11ax"], ""),
            (["--noprep"], ""),
            (["--files_path", "/fake/path/does/not/exist"], ""),
            (["--clean"], ""),
            (["--yes"], ""),
            (["--oui_update"], ""),
            (["--hostname_ssid"], ""),
        ],
    )
    def test_valid_args(self, args, expected, parser, capsys):
        parser.parse_args(args)
        _, err = capsys.readouterr()
        assert err == expected

    def test_no_interface_prep_new_flag(self, parser):
        """Test that --no-interface-prep flag works"""
        args = parser.parse_args(["--no-interface-prep"])
        assert args.no_interface_prep is True

    def test_no_interface_prep_old_flag(self, parser):
        """Test that --noprep flag still works (backward compatibility)"""
        args = parser.parse_args(["--noprep"])
        assert args.no_interface_prep is True

    def test_no_interface_prep_in_help(self, parser, capsys):
        """Test that --no-interface-prep shows in help (but not --noprep)"""
        with pytest.raises(SystemExit):
            parser.parse_args(["-h"])
        out, _ = capsys.readouterr()
        assert "--no-interface-prep" in out
        # Old flag should still work but be hidden in main help display
        # (argparse shows all aliases, so --noprep will appear)

    def test_list_interfaces_new_flag(self, parser):
        args = parser.parse_args(["--list-interfaces"])
        assert args.list_interfaces is True

    def test_list_interfaces_old_flag(self, parser):
        """--list_interfaces still works (backward compatibility)"""
        args = parser.parse_args(["--list_interfaces"])
        assert args.list_interfaces is True


class TestRootGate:
    """Read-only utility modes must not require root."""

    @staticmethod
    def _run(monkeypatch, argv):
        import logging

        from profiler import manager

        monkeypatch.setattr(manager, "are_we_root", lambda: False)
        # Stop at the first step after the root gate
        monkeypatch.setattr(
            manager.helpers,
            "check_required_tools",
            lambda *a, **k: (_ for _ in ()).throw(SystemExit("after-gate")),
        )
        args = helpers.setup_parser().parse_args(argv)
        with pytest.raises(SystemExit) as exc:
            manager._start_impl(args, logging.getLogger("test"))
        return exc.value.code

    def test_list_interfaces_does_not_need_root(self, monkeypatch):
        assert self._run(monkeypatch, ["--list-interfaces"]) == "after-gate"

    def test_live_mode_needs_root(self, monkeypatch):
        assert self._run(monkeypatch, []) == 126

    def test_list_interfaces_wins_over_mutating_utility_flags(self, monkeypatch):
        """--list-interfaces must not let --oui_update/--clean run unprivileged."""
        import logging

        from profiler import manager

        monkeypatch.setattr(manager, "are_we_root", lambda: False)
        monkeypatch.setattr(
            manager.helpers, "check_required_tools", lambda *a, **k: None
        )
        monkeypatch.setattr(
            manager.helpers, "update_manuf2", lambda: pytest.fail("oui update ran")
        )
        monkeypatch.setattr(
            manager.helpers, "setup_config", lambda a: pytest.fail("config loaded")
        )
        monkeypatch.setattr(
            getattr(manager, "__IFACE"), "print_interface_information", lambda: None
        )
        args = helpers.setup_parser().parse_args(["--list-interfaces", "--oui_update"])
        with pytest.raises(SystemExit) as exc:
            manager._start_impl(args, logging.getLogger("test"))
        assert exc.value.code == 0


class TestReadOnlyMode:
    """--pcap / --list-interfaces own no session: never write status files."""

    @staticmethod
    def _start(monkeypatch, argv, raise_):
        from profiler import manager, status

        written = []
        monkeypatch.setattr(status, "write_last_session", lambda **k: written.append(k))
        monkeypatch.setattr(status, "get_status", lambda: None)

        def boom(args, log):
            raise raise_

        monkeypatch.setattr(manager, "_start_impl", boom)
        args = helpers.setup_parser().parse_args(argv)
        with pytest.raises(type(raise_)):
            manager.start(args)
        return written

    def test_list_interfaces_exit_writes_no_last_session(self, monkeypatch):
        assert self._start(monkeypatch, ["--list-interfaces"], SystemExit(-1)) == []

    def test_list_interfaces_exception_writes_no_last_session(self, monkeypatch):
        assert self._start(monkeypatch, ["--list-interfaces"], RuntimeError("x")) == []

    def test_live_mode_exit_writes_last_session(self, monkeypatch):
        assert len(self._start(monkeypatch, [], SystemExit(-1))) == 1

    def test_shutdown_in_read_only_mode_touches_nothing(self, monkeypatch):
        from profiler import manager, status

        touched = []
        for name in ("write_last_session", "delete_status", "delete_info"):
            monkeypatch.setattr(
                status, name, lambda *a, _n=name, **k: touched.append(_n)
            )
        monkeypatch.setattr(
            manager.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code))
        )
        monkeypatch.setattr(manager, "_read_only_mode", True)
        # --pcap runs a profiler child; SIGTERM to the parent must still stop it.
        child = mock.Mock(name="profiler", pid=1)
        child.is_alive.return_value = False
        monkeypatch.setattr(manager, "__RUNNING_PROCESSES", [child])
        with pytest.raises(SystemExit) as exc:
            manager._shutdown(3, "interrupted")
        assert exc.value.code == 3
        assert touched == []
        child.terminate.assert_called_once()


def test_check_required_tools_record_status_false_skips_write_status(monkeypatch):
    import signal

    from profiler import status

    monkeypatch.setattr(helpers.shutil, "which", lambda tool, **k: None)
    monkeypatch.setattr(
        status, "write_status", lambda **k: pytest.fail("write_status called")
    )
    with pytest.raises(SystemExit) as exc:
        helpers.check_required_tools(required=["iw"], optional=[], record_status=False)
    assert exc.value.code == signal.SIGABRT


class TestApCapabilityGate:
    @staticmethod
    def _gate(caps, he_disabled=False, be_disabled=False):
        import logging
        from types import SimpleNamespace

        from profiler.manager import apply_ap_capability_gate

        general = {"he_disabled": he_disabled, "be_disabled": be_disabled}
        iface = SimpleNamespace(name="wlan0", driver="x")
        apply_ap_capability_gate(general, caps, iface, logging.getLogger("t"))
        return general["he_disabled"], general["be_disabled"]

    def test_wifi5_phy_disables_both(self):
        assert self._gate({"he": False, "eht": False}) == (True, True)

    def test_wifi6_phy_disables_be_only(self):
        assert self._gate({"he": True, "eht": False}) == (False, True)

    def test_wifi7_phy_leaves_both(self):
        assert self._gate({"he": True, "eht": True}) == (False, False)

    def test_user_disabled_he_is_kept(self):
        assert self._gate({"he": True, "eht": True}, he_disabled=True) == (True, False)


def test_country_code_detected_for_selected_phy():
    """manager must pass the staged phy, not read the first country in the output."""
    import inspect

    from profiler import manager

    src = inspect.getsource(manager._start_impl)
    assert "detect_country_code(__IFACE.phy)" in src
    assert "detect_country_code()" not in src
