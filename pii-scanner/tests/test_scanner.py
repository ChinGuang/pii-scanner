"""Unit tests for the Scanner aggregation logic."""

from pathlib import Path
import tempfile
import os

import pytest
from pii_scanner.scanner import Scanner, Report
from pii_scanner.detectors import Leak


class TestScannerAggregation:
    def _write_temp_py(self, content: str, tmp_dir: str) -> str:
        path = os.path.join(tmp_dir, "sample.py")
        Path(path).write_text(content, encoding="utf-8")
        return path

    def test_returns_report_with_no_leaks_on_clean_file(self, tmp_path):
        (tmp_path / "clean.py").write_text('x = "hello world"\n', encoding="utf-8")
        report = Scanner().scan(source_dir=str(tmp_path), log_file=None)
        assert isinstance(report, Report)
        assert report.leaks == []

    def test_detects_nric_in_source(self, tmp_path):
        (tmp_path / "svc.py").write_text(
            'logger.info(f"IC: S1234567A")\n', encoding="utf-8"
        )
        report = Scanner().scan(source_dir=str(tmp_path), log_file=None)
        assert len(report.leaks) == 1
        assert report.leaks[0].pii_class == "NRIC"

    def test_detects_card_in_log_file(self, tmp_path):
        log = tmp_path / "app.log"
        log.write_text("INFO card=4111111111111111 processed\n", encoding="utf-8")
        report = Scanner().scan(source_dir=None, log_file=str(log))
        assert len(report.leaks) == 1
        assert report.leaks[0].pii_class == "CARD"

    def test_detects_email_in_log_file(self, tmp_path):
        log = tmp_path / "app.log"
        log.write_text("INFO user alice@example.com logged in\n", encoding="utf-8")
        report = Scanner().scan(source_dir=None, log_file=str(log))
        assert len(report.leaks) == 1
        assert report.leaks[0].pii_class == "EMAIL"

    def test_aggregates_leaks_from_multiple_files(self, tmp_path):
        (tmp_path / "a.py").write_text('ic = "S1234567A"\n', encoding="utf-8")
        (tmp_path / "b.py").write_text('email = "x@y.com"\n', encoding="utf-8")
        report = Scanner().scan(source_dir=str(tmp_path), log_file=None)
        assert len(report.leaks) == 2

    def test_one_leak_per_line_first_detector_wins(self, tmp_path):
        # A line with both NRIC and email — only first detector (NRIC) should fire
        (tmp_path / "c.py").write_text(
            'log(f"IC S1234567A email x@y.com")\n', encoding="utf-8"
        )
        report = Scanner().scan(source_dir=str(tmp_path), log_file=None)
        assert len(report.leaks) == 1
        assert report.leaks[0].pii_class == "NRIC"

    def test_report_to_text_clean(self):
        report = Report(leaks=[])
        assert "[OK]" in report.to_text()

    def test_report_to_text_with_leaks(self):
        leak = Leak("svc.py", 3, "EMAIL", "INFO user [EMAIL:jo***@bank.com]")
        report = Report(leaks=[leak])
        text = report.to_text()
        assert "svc.py:3" in text
        assert "EMAIL" in text

    def test_report_to_json(self):
        import json
        leak = Leak("svc.py", 3, "EMAIL", "INFO user [EMAIL:jo***@bank.com]")
        report = Report(leaks=[leak])
        data = json.loads(report.to_json())
        assert isinstance(data, list)
        assert data[0]["pii_class"] == "EMAIL"
        assert data[0]["line_number"] == 3
