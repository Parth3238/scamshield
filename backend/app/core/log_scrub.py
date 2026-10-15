"""Scrub sensitive values out of anything written to logs.

Only metadata (method, path, status, ids) is logged; bodies and secrets are
never logged. This helper is a second safety net: pass any string through
scrub_for_log() before logging it, and tokens, passwords, OTPs and UPI IDs
come out as [REDACTED].
"""

from __future__ import annotations

import re

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # API keys: ss_live_<token> (full value, not just the prefix).
    (re.compile(r"ss_live_[A-Za-z0-9_\-~+/=]+"), "ss_live_[REDACTED]"),
    # Bearer / JWT tokens in headers.
    (re.compile(r"(?i)\b(bearer|jwt|token)\s+[A-Za-z0-9_\-~+/=.]+\b"), r"\1 [REDACTED]"),
    # Password assignments in bodies, queries or logs.
    (re.compile(r"(?i)(password['\"]?\s*[:=]\s*)(['\"]?)[^'\"\s,}]+"), r"\1[REDACTED]"),
    # Cookie values (session, JWT).
    (re.compile(r"(?i)\b(cookie\s*:\s*)([^\s;]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(access_token\s*=\s*)([^;\s]+)"), r"\1[REDACTED]"),
    # OTP-like standalone numbers (4-8 digits).
    (re.compile(r"(?<![\w.])\d{4,8}(?![\w.])"), "[REDACTED]"),
    # Full UPI IDs (name@handle): mask the name part.
    (re.compile(r"(?<![\w.])[A-Za-z0-9._]{2,}@[A-Za-z]{2,}"), "***@[REDACTED]"),
)


def scrub_for_log(value: object) -> str:
    """Return a log-safe string with secrets replaced by [REDACTED]."""
    text = value if isinstance(value, str) else str(value)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
