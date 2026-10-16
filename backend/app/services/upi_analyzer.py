"""Rule-based UPI ID analyzer. No network calls."""

from __future__ import annotations

import re

from app.models.finding import Finding
from app.rules.brands import BRAND_OFFICIAL_DOMAINS
from app.rules.upi_rules import KNOWN_UPI_HANDLES, SUPPORT_WORDS
from app.services.text_utils import levenshtein

LOCAL_RE = re.compile(r"^[a-z0-9.\-_]{2,50}$")
HANDLE_RE = re.compile(r"^[a-z]{2,30}$")

# Candidate inside free text: local 2-50, handle 2-30 letters.
EXTRACT_RE = re.compile(r"(?<!\w)([A-Za-z0-9._\-]{2,50})@([A-Za-z]{2,30})\b")

EMAIL_PROVIDERS = {
    "gmail",
    "googlemail",
    "yahoo",
    "outlook",
    "hotmail",
    "live",
    "icloud",
    "protonmail",
    "proton",
    "zoho",
    "aol",
    "gmx",
    "yandex",
    "rediffmail",
    "mail",
    "email",
    "inbox",
    "fastmail",
}


def normalize_upi(upi_id: str) -> str:
    """Lowercase and strip whitespace."""
    return (upi_id or "").strip().lower()


def is_valid_upi_format(upi_id: str) -> bool:
    """Exactly one '@', local 2-50 of letters/digits/.-_, handle 2-30 letters."""
    s = normalize_upi(upi_id)
    if not s or s.count("@") != 1:
        return False
    local, handle = s.split("@", 1)
    if not LOCAL_RE.fullmatch(local):
        return False
    if not HANDLE_RE.fullmatch(handle):
        return False
    return True


def extract_upi_ids(text: str) -> list[str]:
    """Find UPI IDs inside free text.

    Skips normal email addresses: a match is rejected when the handle is
    followed by a dot plus a letter (name@gmail.com, name@company.co.in)
    or when the handle is a known email provider.
    """
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for m in EXTRACT_RE.finditer(text):
        local, handle = m.group(1), m.group(2)
        handle_l = handle.lower()
        # Email with domain continuation: name@gmail.com -> after "gmail"
        # comes ".com". A trailing sentence period (dot + space/end) is OK.
        if m.end() < len(text) and text[m.end()] == ".":
            nxt = text[m.end() + 1] if m.end() + 1 < len(text) else ""
            if nxt.isalnum():
                continue
        if handle_l in EMAIL_PROVIDERS:
            continue
        candidate = f"{local}@{handle}"
        norm = normalize_upi(candidate)
        if not is_valid_upi_format(norm):
            continue
        if norm not in seen:
            seen.add(norm)
            found.append(norm)
    return found


def mask_upi(upi_id: str) -> str:
    """Mask for storage: first 2 chars + '***@' + handle."""
    s = normalize_upi(upi_id)
    if "@" in s:
        local, handle = s.rsplit("@", 1)
        if not handle:
            return (local[:2] + "***") if local else "***"
        prefix = local[:2] if len(local) >= 2 else local
        return f"{prefix}***@{handle}" if prefix else f"***@{handle}"
    return (s[:2] + "***") if len(s) >= 2 else "***"


def check_invalid_format(normalized: str) -> Finding | None:
    if not is_valid_upi_format(normalized):
        return Finding(
            "INVALID_UPI_FORMAT",
            15,
            "This UPI ID does not look like a valid UPI address with one @ sign.",
        )
    return None


def check_unknown_handle(handle: str) -> Finding | None:
    if handle not in KNOWN_UPI_HANDLES:
        return Finding(
            "UNKNOWN_UPI_HANDLE",
            15,
            "This UPI handle is not in the list of common handles, so be careful.",
        )
    return None


def check_lookalike_handle(handle: str) -> Finding | None:
    # Known handles are never lookalikes, even when two known handles
    # differ by one letter (for example ybl vs ibl).
    if handle in KNOWN_UPI_HANDLES:
        return None
    for known in KNOWN_UPI_HANDLES:
        if handle != known and levenshtein(handle, known) == 1:
            return Finding(
                "LOOKALIKE_UPI_HANDLE",
                30,
                "This UPI handle looks almost the same as a well-known handle with one letter changed.",
            )
    return None


def check_brand_in_name(local: str, handle: str) -> Finding | None:
    for brand in BRAND_OFFICIAL_DOMAINS:
        b = brand.lower()
        if b and b in local and b not in handle:
            return Finding(
                "BRAND_IN_UPI_NAME",
                30,
                f"This UPI name uses the brand name '{b}' but the handle is not the official {b} handle.",
            )
    return None


def check_support_word(local: str) -> Finding | None:
    for w in SUPPORT_WORDS:
        if w.lower() in local:
            return Finding(
                "SUPPORT_WORD_IN_UPI",
                25,
                "This UPI name uses a support or refund word that scammers often use.",
            )
    return None


def check_random_looking(local: str) -> Finding | None:
    # A plain 10-digit mobile number is normal, never flag it.
    if re.fullmatch(r"\d{10}", local):
        return None
    digits = sum(c.isdigit() for c in local)
    has_letter = any(c.isalpha() for c in local)
    if digits >= 3 and has_letter:
        return Finding(
            "RANDOM_LOOKING_UPI",
            10,
            "This UPI name has random-looking letters mixed with many numbers.",
        )
    return None


def analyze_upi(upi_id: str, db=None) -> list[Finding]:
    """Analyze one UPI ID. Pass db session to enable KNOWN_BAD_INDICATOR."""
    normalized = normalize_upi(upi_id)
    findings: list[Finding] = []

    invalid = check_invalid_format(normalized)
    if invalid is not None:
        findings.append(invalid)
        # A lookalike such as oksb1 (digit 1 for i) fails the letters-only
        # format check, but we still want UNKNOWN/LOOKALIKE signals, so keep
        # checking the parts when there is exactly one '@'.
        if normalized.count("@") == 1:
            local, handle = normalized.split("@", 1)
            # Only run part checks on non-empty parts to avoid noise.
            if local and handle:
                for f in (
                    check_unknown_handle(handle),
                    check_lookalike_handle(handle),
                    check_brand_in_name(local, handle),
                    check_support_word(local),
                    check_random_looking(local),
                ):
                    if f is not None:
                        findings.append(f)
        if db is not None:
            try:
                from app.services.indicators import is_known_bad

                if is_known_bad(db, "upi", normalized):
                    findings.append(
                        Finding(
                            "KNOWN_BAD_INDICATOR",
                            50,
                            "This UPI ID was reported before as unsafe, so do not pay.",
                        )
                    )
            except Exception:  # nosec B110 - community lookup is best-effort; analyzer must never crash
                pass
        return findings

    local, handle = normalized.split("@", 1)

    for f in (
        check_unknown_handle(handle),
        check_lookalike_handle(handle),
        check_brand_in_name(local, handle),
        check_support_word(local),
        check_random_looking(local),
    ):
        if f is not None:
            findings.append(f)

    if db is not None:
        try:
            from app.services.indicators import is_known_bad

            if is_known_bad(db, "upi", normalized):
                findings.append(
                    Finding(
                        "KNOWN_BAD_INDICATOR",
                        50,
                        "This UPI ID was reported before as unsafe, so do not pay.",
                    )
                )
        except Exception:  # nosec B110 - community lookup is best-effort; analyzer must never crash
            pass

    return findings
