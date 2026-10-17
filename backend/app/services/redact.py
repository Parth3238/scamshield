"""Redact private numbers before saving messages to the database."""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

# name@bank, e.g. ram@okhdfc. Redact first so the name part is not left behind.
UPI_RE = re.compile(r"\b[a-zA-Z0-9._\-]{2,}@[a-zA-Z]{2,}\b")

# 12-19 digits with optional spaces/dashes, e.g. card numbers.
CARD_RE = re.compile(r"\b\d(?:[\s\-]?\d){11,18}\b")

# Indian phone numbers: optional +91, 10 digits starting 6-9, spaces/dashes allowed.
PHONE_RE = re.compile(r"(?<!\w)(?:\+?91[\s\-]?)?[6-9](?:[\s\-]?\d){9}\b")

# Short secret numbers like OTPs: 4-8 digits.
OTP_RE = re.compile(r"\b\d{4,8}\b")


def redact_pii(text: str) -> str:
    """Replace UPI IDs, card numbers, phone numbers and OTPs with [REDACTED]."""
    if not text:
        return text
    red = UPI_RE.sub(REDACTED, text)
    # Phone before card: "+91 9876543210" would otherwise look like 12 digits.
    red = PHONE_RE.sub(REDACTED, red)
    red = CARD_RE.sub(REDACTED, red)
    red = OTP_RE.sub(REDACTED, red)
    return red
