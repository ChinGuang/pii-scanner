"""
Scanner: walks a source directory and an optional log file, applies all
detectors to every line, and aggregates the results into a Report.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from pii_scanner.detectors import ALL_DETECTORS, Leak


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@dataclass
class Report:
    """Aggregated list of Leaks from a single scan run."""

    leaks: list[Leak] = field(default_factory=list)

    def to_text(self) -> str:
        if not self.leaks:
            return "[OK] No PII leaks detected."
        lines = [f"[!!] {len(self.leaks)} PII leak(s) found:\n"]
        for leak in self.leaks:
            lines.append(
                f"  [{leak.pii_class}] {leak.artefact_path}:{leak.line_number}\n"
                f"    > {leak.redacted_snippet}"
            )
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(
            [
                {
                    "artefact_path": lk.artefact_path,
                    "line_number": lk.line_number,
                    "pii_class": lk.pii_class,
                    "redacted_snippet": lk.redacted_snippet,
                }
                for lk in self.leaks
            ],
            indent=2,
        )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    """Orchestrates detection across all artefacts."""

    def scan(self, source_dir: str | None, log_file: str | None) -> Report:
        leaks: list[Leak] = []

        if source_dir:
            for py_path in sorted(Path(source_dir).rglob("*.py")):
                leaks.extend(self._scan_file(str(py_path)))

        if log_file:
            leaks.extend(self._scan_file(log_file))

        return Report(leaks=leaks)

    def _scan_file(self, path: str) -> list[Leak]:
        leaks: list[Leak] = []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    for detector in ALL_DETECTORS:
                        result = detector(line, path, lineno)
                        if result is not None:
                            leaks.append(result)
                            break  # one leak per line — first matching detector wins
        except OSError:
            pass
        return leaks
