"""
Mock customer service with intentionally planted PII leaks for demo purposes.

Leaks:
  1. Obvious     – direct IC field interpolation in logger.info
  2. Object log  – whole Customer object passed to logger.info (default __repr__)
  3. Exception   – card number embedded in ValueError message, caught and logged
  4. (log file)  – leak 4 lives in tests/fixtures/app.log (email + card in a log line)
"""

import logging

logger = logging.getLogger(__name__)


class Customer:
    """Mock customer model. __repr__ intentionally exposes all fields (pre-fix state)."""

    def __init__(self, name: str, ic_number: str, card_number: str, email: str) -> None:
        self.name = name
        self.ic_number = ic_number
        self.card_number = card_number
        self.email = email

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"Customer(name={self.name!r}, ic_number={self.ic_number!r}, "
            f"card_number={self.card_number!r}, email={self.email!r})"
        )


# ---------------------------------------------------------------------------
# Service functions that contain planted leaks
# ---------------------------------------------------------------------------


def process_customer(customer: Customer) -> None:
    """Leak 1 – obvious: IC number interpolated directly into log message."""
    logger.info(f"Processing customer with IC: {customer.ic_number}")


def load_customer(customer: Customer) -> None:
    """Leak 2 – object logging: entire Customer object passed to logger."""
    logger.info(f"Loaded customer: {customer}")


def validate_card(customer: Customer) -> bool:
    """Leak 3 – exception message: card number embedded in raised ValueError."""
    try:
        if not customer.card_number.isdigit():
            raise ValueError(f"Invalid card number for customer: {customer.card_number}")
        return True
    except ValueError as exc:
        logger.error(f"Card validation failed: {exc}")
        return False


def get_customer_summary(customer: Customer) -> dict:
    """Safe function – returns a sanitised summary dict (no PII leak)."""
    return {"name": customer.name, "has_card": bool(customer.card_number)}
