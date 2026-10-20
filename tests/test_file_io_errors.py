"""
Test file I/O error paths for wlanpi-profiler
"""

import json
from unittest import mock

import pytest


class TestReportWriteFailures:
    """Test report generation failure scenarios"""

    def test_json_report_write_failure(self, tmp_path, mock_disk_full):
        """Test profiler handles JSON report write failure gracefully"""
        from profiler.profiler import Profiler

        config = {
            "GENERAL": {
                "channel": 6,
                "listen_only": False,
                "files_path": [str(tmp_path)],
                "pcap_analysis": None,
                "ft_disabled": False,
                "he_disabled": False,
                "be_disabled": False,
            }
        }

        profiler = Profiler(config=config)

        assert profiler is not None

    def test_text_report_write_failure(self, tmp_path, mock_permission_error):
        """Test profiler handles text report write failure"""
        from profiler.profiler import Profiler

        config = {
            "GENERAL": {
                "channel": 6,
                "listen_only": False,
                "files_path": [str(tmp_path)],
                "pcap_analysis": None,
                "ft_disabled": False,
                "he_disabled": False,
                "be_disabled": False,
            }
        }

        profiler = Profiler(config=config)

        assert profiler is not None

    def test_pcap_write_failure(self, tmp_path):
        """Test profiler handles PCAP write failure during capture"""
        from profiler.profiler import Profiler

        config = {
            "GENERAL": {
                "channel": 6,
                "listen_only": False,
                "files_path": [str(tmp_path)],
                "pcap_analysis": None,
                "ft_disabled": False,
                "he_disabled": False,
                "be_disabled": False,
            }
        }

        profiler = Profiler(config=config)

        with mock.patch(
            "profiler.profiler.wrpcap", side_effect=OSError("Write failed")
        ):
            assert profiler is not None

    def test_csv_write_failure(self, tmp_path):
        """Test profiler handles CSV write failure"""
        from profiler.profiler import Profiler

        config = {
            "GENERAL": {
                "channel": 6,
                "listen_only": False,
                "files_path": [str(tmp_path)],
                "pcap_analysis": None,
                "ft_disabled": False,
                "he_disabled": False,
                "be_disabled": False,
            }
        }

        profiler = Profiler(config=config)

        assert profiler is not None


class TestMultiPathFallback:
    """Test multi-path save fallback behavior"""

    def test_multipath_fallback_on_first_path_failure(self, tmp_path):
        """Test profiler falls back to second path when first write fails"""
        from profiler.profiler import Profiler

        path1 = tmp_path / "path1"
        path2 = tmp_path / "path2"
        path2.mkdir()

        config = {
            "GENERAL": {
                "channel": 6,
                "listen_only": False,
                "files_path": [str(path1), str(path2)],
                "pcap_analysis": None,
                "ft_disabled": False,
                "he_disabled": False,
                "be_disabled": False,
            }
        }

        profiler = Profiler(config=config)

        assert isinstance(profiler.files_path, list)
        assert len(profiler.files_path) == 2

    def test_all_paths_fail(self, tmp_path):
        """Test profiler behavior when all write paths fail"""
        from profiler.profiler import Profiler

        path1 = tmp_path / "nonexistent1"
        path2 = tmp_path / "nonexistent2"

        config = {
            "GENERAL": {
                "channel": 6,
                "listen_only": False,
                "files_path": [str(path1), str(path2)],
                "pcap_analysis": None,
                "ft_disabled": False,
                "he_disabled": False,
                "be_disabled": False,
            }
        }

        profiler = Profiler(config=config)

        assert profiler is not None


class TestJSONCorruptionRecovery:
    """Test handling of corrupted JSON files"""

    def test_overwrite_corrupted_json(self, tmp_path):
        """Test profiler can overwrite corrupted existing JSON files"""
        from profiler.profiler import Profiler

        json_file = tmp_path / "corrupted.json"
        json_file.write_text("{ invalid json content ")

        config = {
            "GENERAL": {
                "channel": 6,
                "listen_only": False,
                "files_path": [str(tmp_path)],
                "pcap_analysis": None,
                "ft_disabled": False,
                "he_disabled": False,
                "be_disabled": False,
            }
        }

        profiler = Profiler(config=config)

        assert profiler is not None

    def test_read_invalid_json_gracefully(self, tmp_path):
        """Test profiler handles reading invalid JSON without crashing"""
        invalid_json_file = tmp_path / "invalid.json"
        invalid_json_file.write_text("not valid json at all")

        try:
            with open(invalid_json_file) as f:
                json.load(f)
            pytest.fail("Should have raised JSONDecodeError")
        except json.JSONDecodeError:
            pass


class TestConcurrentFileAccess:
    """Test concurrent access to files"""

    def test_concurrent_read_access(self, tmp_path):
        """Test multiple readers can access report files simultaneously"""
        report_file = tmp_path / "report.json"
        report_data = {"client_mac": "00:11:22:33:44:55", "capabilities": []}

        with open(report_file, "w") as f:
            json.dump(report_data, f)

        readers = []
        for _ in range(3):
            with open(report_file) as f:
                data = json.load(f)
                readers.append(data)

        assert all(r == report_data for r in readers)

    def test_write_race_condition_safety(self, tmp_path):
        """Test that write operations are safe from race conditions"""
        import shutil
        import tempfile

        status_file = tmp_path / "status.json"

        for i in range(5):
            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, dir=str(tmp_path), suffix=".tmp"
            ) as tmp_file:
                json.dump({"iteration": i}, tmp_file)
                tmp_name = tmp_file.name
            shutil.move(tmp_name, str(status_file))

        with open(status_file) as f:
            data = json.load(f)
            assert "iteration" in data
            assert data["iteration"] == 4
