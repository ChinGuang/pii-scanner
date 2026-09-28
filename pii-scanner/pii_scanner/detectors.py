"""
PII detectors: one function per pattern.

Each detector takes a single line of text plus its source location and returns
a Leak dataclass if the pattern matches, or None if it does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Leak dataclass
# ---------------------------------------------------------------------------


@dataclass
class Leak:
    """A single PII finding in a scanned artefact."""

    artefact_path: str
    line_number: int
    pii_class: str
    redacted_snippet: str


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Malaysian / Singaporean NRIC: letter [STFG] + 7 digits + letter
_NRIC_RE = re.compile(r"\b[STFG]\d{7}[A-Z]\b")

# Card numbers: 13–19 consecutive digits (spaces/dashes stripped before Luhn check)
_CARD_RE = re.compile(r"\b(\d[ -]?){13,19}\b")

# Email addresses (RFC-5322-lite)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


# ---------------------------------------------------------------------------
# Luhn validation
# ---------------------------------------------------------------------------


def _luhn_valid(digits: str) -> bool:
    """Return True if *digits* passes the Luhn checksum."""
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Detector functions
# ---------------------------------------------------------------------------


def detect_nric(line: str, path: str, lineno: int) -> Leak | None:
    """Detect Malaysian/Singaporean NRIC numbers."""
    match = _NRIC_RE.search(line)
    if not match:
        return None
    value = match.group()
    redacted = line.replace(value, f"[NRIC:{value[:1]}***{value[-1]}]").strip()
    return Leak(artefact_path=path, line_number=lineno, pii_class="NRIC", redacted_snippet=redacted)


def detect_card(line: str, path: str, lineno: int) -> Leak | None:
    """Detect credit/debit card numbers (Luhn-validated)."""
    for match in _CARD_RE.finditer(line):
        raw = match.group()
        digits = re.sub(r"[ -]", "", raw)
        if len(digits) < 13 or not _luhn_valid(digits):
            continue
        masked = digits[:4] + "****" + digits[-4:]
        redacted = line.replace(raw, f"[CARD:{masked}]").strip()
        return Leak(
            artefact_path=path,
            line_number=lineno,
            pii_class="CARD",
            redacted_snippet=redacted,
        )
    return None


def detect_email(line: str, path: str, lineno: int) -> Leak | None:
    """Detect email addresses."""
    match = _EMAIL_RE.search(line)
    if not match:
        return None
    value = match.group()
    local, domain = value.split("@", 1)
    masked_local = local[:2] + "***" if len(local) > 2 else "***"
    redacted = line.replace(value, f"[EMAIL:{masked_local}@{domain}]").strip()
    return Leak(artefact_path=path, line_number=lineno, pii_class="EMAIL", redacted_snippet=redacted)


# ---------------------------------------------------------------------------
# All detectors in call order
# ---------------------------------------------------------------------------

ALL_DETECTORS = [detect_nric, detect_card, detect_email]
