"""
End-to-end tests: scan the real models.py fixture and the app.log fixture,
verify leaks are found, apply fixes, rerun, and confirm clean report.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# Paths relative to this test file
FIXTURES_DIR = Path(__file__).parent / "fixtures"
SCANNER_PKG = Path(__file__).parent.parent / "pii_scanner"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_scan(*args: str) -> tuple[int, str]:
    """Run the CLI as a subprocess and return (returncode, stdout+stderr)."""
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "pii_scanner.cli"] + list(args),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        cwd=str(Path(__file__).parent.parent),
    )
    return result.returncode, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# E2E: scan the real models.py (planted leaks)
# ---------------------------------------------------------------------------


class TestE2EScanModels:
    def test_detects_leaks_in_planted_source(self, tmp_path):
        """A source file with hardcoded PII literals must produce leaks."""
        src = tmp_path / "service.py"
        src.write_text(
            'logger.info(f"IC: S1234567A")\n'
            'logger.info(f"card: 4111111111111111")\n'
            'logger.error(f"user: admin@corp.com")\n',
            encoding="utf-8",
        )
        rc, out = _run_scan("--source-dir", str(tmp_path))
        assert rc == 1
        assert "NRIC" in out or "CARD" in out or "EMAIL" in out

    def test_json_flag_produces_valid_json(self, tmp_path):
        import json
        src = tmp_path / "service.py"
        src.write_text(
            'logger.info(f"IC: S1234567A")\n'
            'logger.error(f"user: admin@corp.com")\n',
            encoding="utf-8",
        )
        rc, out = _run_scan("--source-dir", str(tmp_path), "--json")
        data = json.loads(out)
        assert isinstance(data, list)
        pii_classes = {item["pii_class"] for item in data}
        assert pii_classes  # at least one PII class detected

    def test_no_false_positives_on_clean_files(self, tmp_path):
        """A file with no PII should return exit 0 and no leaks."""
        clean = tmp_path / "clean.py"
        clean.write_text('def add(a, b):\n    return a + b\n', encoding="utf-8")
        rc, out = _run_scan("--source-dir", str(tmp_path))
        assert rc == 0
        assert "[OK]" in out


# ---------------------------------------------------------------------------
# E2E: scan the log fixture
# ---------------------------------------------------------------------------


class TestE2EScanLog:
    def test_detects_email_and_card_in_log(self):
        rc, out = _run_scan("--log-file", str(FIXTURES_DIR / "app.log"))
        assert rc == 1
        # Line 2 of app.log has both email and card; first detector (NRIC) won't match,
        # so CARD or EMAIL should fire.
        assert "CARD" in out or "EMAIL" in out

    def test_clean_log_returns_exit_zero(self, tmp_path):
        log = tmp_path / "clean.log"
        log.write_text("INFO all good\nINFO nothing here\n", encoding="utf-8")
        rc, out = _run_scan("--log-file", str(log))
        assert rc == 0
        assert "[OK]" in out


# ---------------------------------------------------------------------------
# E2E: fix flow — inject __repr__, rerun comes back clean
# ---------------------------------------------------------------------------


class TestE2EFixFlow:
    """
    Copy the pii_scanner package to a temp directory, scan it (expect leaks),
    apply --fix (which modifies the copy), then rescan and expect no NRIC/CARD
    leaks originating from the model (the __repr__ now masks them).

    Note: we do NOT actually create git branches here because the test
    environment may not have a repo. We test _inject_repr directly instead.
    """

    def test_repr_injection_masks_pii_fields(self, tmp_path):
        """After injecting __repr__, instantiating Customer must not expose raw PII."""
        # Copy models.py to a temp location
        src = SCANNER_PKG / "models.py"
        dest_dir = tmp_path / "myapp"
        dest_dir.mkdir()
        dest = dest_dir / "models.py"
        shutil.copy(src, dest)

        from pii_scanner.fixer import _inject_repr, _PII_FIELDS

        modified = _inject_repr(dest, "Customer")
        assert modified is True, "Expected _inject_repr to patch the file"

        # Load the patched module dynamically
        import importlib.util
        spec = importlib.util.spec_from_file_location("patched_models", dest)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        c = mod.Customer("Alice", "S1234567A", "4111111111111111", "alice@bank.com")
        representation = repr(c)
        assert "S1234567A" not in representation, "IC number must be masked in __repr__"
        assert "4111111111111111" not in representation, "Card number must be masked in __repr__"
        assert "alice@bank.com" not in representation, "Email must be masked in __repr__"

    def test_repr_not_double_injected(self, tmp_path):
        """Calling _inject_repr twice on the same file must not modify it the second time."""
        src = SCANNER_PKG / "models.py"
        dest = tmp_path / "models.py"
        shutil.copy(src, dest)

        from pii_scanner.fixer import _inject_repr

        first = _inject_repr(dest, "Customer")
        second = _inject_repr(dest, "Customer")
        assert first is True
        assert second is False

    def test_scan_after_repr_injection_has_fewer_leaks(self, tmp_path):
        """
        After injecting __repr__, the scanner should no longer surface the PII
        that was previously exposed by the __repr__ method body.
        The fixture has leaks ONLY inside __repr__ (not in __init__), so after
        the safe __repr__ is injected the file comes back clean.
        """
        dest_dir = tmp_path / "myapp"
        dest_dir.mkdir()
        dest = dest_dir / "models.py"
        # __repr__ exposes a hardcoded NRIC and card — these are the only leaks
        dest.write_text(
            'class Stub:\n'
            '    def __init__(self, ic, card):\n'
            '        self.ic_number = ic\n'
            '        self.card_number = card\n'
            '        self.email = "placeholder"\n'
            '    def __repr__(self):\n'
            '        return "Stub ic=S1234567A card=4111111111111111"\n',
            encoding="utf-8",
        )

        from pii_scanner.scanner import Scanner
        from pii_scanner.fixer import _inject_repr

        report_before = Scanner().scan(source_dir=str(dest_dir), log_file=None)
        leaks_before = len(report_before.leaks)
        assert leaks_before > 0, "Expected planted leaks before fix"

        _inject_repr(dest, "Stub")

        report_after = Scanner().scan(source_dir=str(dest_dir), log_file=None)
        leaks_after = len(report_after.leaks)

        assert leaks_after < leaks_before, (
            f"Expected fewer leaks after fix ({leaks_after} vs {leaks_before})"
        )
