"""Unit tests for individual PII detectors."""

import pytest
from pii_scanner.detectors import detect_nric, detect_card, detect_email, _luhn_valid, Leak


# ---------------------------------------------------------------------------
# Luhn helper
# ---------------------------------------------------------------------------


class TestLuhn:
    def test_valid_visa(self):
        assert _luhn_valid("4111111111111111") is True

    def test_valid_mastercard(self):
        assert _luhn_valid("5500005555555559") is True

    def test_invalid_random_digits(self):
        assert _luhn_valid("1234567890123456") is False

    def test_single_digit_zero(self):
        assert _luhn_valid("0") is True

    def test_all_zeros(self):
        # 0*n always passes Luhn (sum=0, 0%10==0) — valid edge case
        assert _luhn_valid("00") is True


# ---------------------------------------------------------------------------
# NRIC detector
# ---------------------------------------------------------------------------


class TestDetectNric:
    def test_detects_valid_nric(self):
        leak = detect_nric("IC: S1234567A", "test.py", 1)
        assert leak is not None
        assert leak.pii_class == "NRIC"
        assert leak.line_number == 1
        assert "S1234567A" not in leak.redacted_snippet

    def test_detects_nric_starting_with_t(self):
        leak = detect_nric("customer id T9876543Z registered", "a.py", 5)
        assert leak is not None
        assert leak.pii_class == "NRIC"

    def test_no_match_on_plain_text(self):
        assert detect_nric("Hello world", "a.py", 1) is None

    def test_no_match_on_wrong_format(self):
        # Wrong prefix letter (A is not valid)
        assert detect_nric("A1234567B", "a.py", 1) is None

    def test_returns_leak_dataclass(self):
        leak = detect_nric("IC: F1234567J", "service.py", 10)
        assert isinstance(leak, Leak)
        assert leak.artefact_path == "service.py"


# ---------------------------------------------------------------------------
# Card detector
# ---------------------------------------------------------------------------


class TestDetectCard:
    def test_detects_valid_visa(self):
        leak = detect_card("card=4111111111111111 ok", "svc.py", 3)
        assert leak is not None
        assert leak.pii_class == "CARD"
        assert "4111111111111111" not in leak.redacted_snippet

    def test_no_match_on_luhn_invalid(self):
        assert detect_card("card=1234567890123456", "svc.py", 1) is None

    def test_no_match_on_short_digits(self):
        assert detect_card("ref=123456", "svc.py", 1) is None

    def test_detects_card_with_spaces(self):
        leak = detect_card("4111 1111 1111 1111", "svc.py", 1)
        assert leak is not None
        assert leak.pii_class == "CARD"

    def test_returns_none_on_plain_text(self):
        assert detect_card("no numbers here", "a.py", 1) is None


# ---------------------------------------------------------------------------
# Email detector
# ---------------------------------------------------------------------------


class TestDetectEmail:
    def test_detects_email(self):
        leak = detect_email("user: john.doe@bank.com connected", "log.log", 7)
        assert leak is not None
        assert leak.pii_class == "EMAIL"
        assert "john.doe@bank.com" not in leak.redacted_snippet

    def test_detects_email_with_plus(self):
        leak = detect_email("addr=alice+test@example.org", "a.py", 1)
        assert leak is not None

    def test_no_match_on_plain_text(self):
        assert detect_email("just some text", "a.py", 1) is None

    def test_no_match_on_incomplete_email(self):
        assert detect_email("user@", "a.py", 1) is None

    def test_redacted_snippet_masks_local_part(self):
        leak = detect_email("email: bob@acme.io", "a.py", 1)
        assert leak is not None
        assert "bob" not in leak.redacted_snippet
        assert "@acme.io" in leak.redacted_snippet
