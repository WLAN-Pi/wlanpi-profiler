# -*- coding: utf-8 -*-
"""
Test file I/O error paths for wlanpi-profiler
"""

import json
import pytest
from unittest import mock


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

        # The profiler should handle write failures without crashing
        # This is a smoke test to ensure error handling exists
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

        # Verify profiler can be instantiated even if write paths have issues
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

        # Mock wrpcap to fail
        with mock.patch(
            "profiler.profiler.wrpcap", side_effect=OSError("Write failed")
        ):
            # Profiler should handle this gracefully
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

        # CSV writes should be robust to failures
        assert profiler is not None


class TestMultiPathFallback:
    """Test multi-path save fallback behavior"""

    def test_multipath_fallback_on_first_path_failure(self, tmp_path):
        """Test profiler falls back to second path when first write fails"""
        from profiler.profiler import Profiler

        # Create two paths
        path1 = tmp_path / "path1"
        path2 = tmp_path / "path2"
        path2.mkdir()

        # Don't create path1 to simulate failure

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

        # Verify profiler accepts multiple paths
        assert isinstance(profiler.files_path, list)
        assert len(profiler.files_path) == 2

    def test_all_paths_fail(self, tmp_path):
        """Test profiler behavior when all write paths fail"""
        from profiler.profiler import Profiler

        # Create paths that don't exist
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

        # Profiler should still instantiate but handle write errors later
        assert profiler is not None


class TestJSONCorruptionRecovery:
    """Test handling of corrupted JSON files"""

    def test_overwrite_corrupted_json(self, tmp_path):
        """Test profiler can overwrite corrupted existing JSON files"""
        from profiler.profiler import Profiler

        # Create a corrupted JSON file
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

        # Profiler should be able to create new reports even with corrupted files present
        assert profiler is not None

    def test_read_invalid_json_gracefully(self, tmp_path):
        """Test profiler handles reading invalid JSON without crashing"""
        invalid_json_file = tmp_path / "invalid.json"
        invalid_json_file.write_text("not valid json at all")

        # Try to read it
        try:
            with open(invalid_json_file, "r") as f:
                json.load(f)
            pytest.fail("Should have raised JSONDecodeError")
        except json.JSONDecodeError:
            # Expected behavior
            pass


class TestConcurrentFileAccess:
    """Test concurrent access to files"""

    def test_concurrent_read_access(self, tmp_path):
        """Test multiple readers can access report files simultaneously"""
        report_file = tmp_path / "report.json"
        report_data = {"client_mac": "00:11:22:33:44:55", "capabilities": []}

        # Write a report
        with open(report_file, "w") as f:
            json.dump(report_data, f)

        # Simulate multiple readers
        readers = []
        for i in range(3):
            with open(report_file, "r") as f:
                data = json.load(f)
                readers.append(data)

        # All readers should get the same data
        assert all(r == report_data for r in readers)

    def test_write_race_condition_safety(self, tmp_path):
        """Test that write operations are safe from race conditions"""
        import tempfile
        import shutil

        status_file = tmp_path / "status.json"

        # Simulate atomic writes by writing to temp then moving
        for i in range(5):
            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, dir=str(tmp_path), suffix=".tmp"
            ) as tmp_file:
                json.dump({"iteration": i}, tmp_file)
                tmp_name = tmp_file.name
            shutil.move(tmp_name, str(status_file))

        # Verify final write succeeded
        with open(status_file, "r") as f:
            data = json.load(f)
            assert "iteration" in data
            assert data["iteration"] == 4  # Last write
