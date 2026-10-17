"""Parse UPI QR payloads (upi://pay?...) and flag QR-specific risks."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from app.models.finding import Finding
from app.rules.brands import BRAND_OFFICIAL_DOMAINS
from app.services.upi_analyzer import analyze_upi

# Generic words that appear in many payee names; skip them for brand checks.
_GENERIC_BRANDS = {"upi", "bhim", "npci"}

NOTE_SCAM_WORDS = {"refund", "reward", "cashback", "claim"}


def parse_upi_uri(payload: str) -> dict[str, str | None]:
    """Extract pa, pn, am, tn, cu, mc from a upi://pay?... string."""
    result: dict[str, str | None] = {
        "pa": None,
        "pn": None,
        "am": None,
        "tn": None,
        "cu": None,
        "mc": None,
    }
    if not payload or not payload.strip().lower().startswith("upi://pay?"):
        return result
    try:
        parsed = urlparse(payload.strip())
        params = parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return result
    for key in result:
        values = params.get(key)
        if values:
            value = values[0].strip()
            result[key] = value if value != "" else None
    return result


def _pn_tokens(pn: str) -> set[str]:
    return set(p for p in re.split(r"[^a-z0-9]+", (pn or "").lower()) if p)


def check_payee_name_mismatch(pa: str | None, pn: str | None) -> Finding | None:
    """Flag when the payee name claims a brand the UPI handle doesn't match."""
    if not pa or not pn:
        return None
    tokens = _pn_tokens(pn)
    handle = pa.rsplit("@", 1)[-1].lower() if "@" in pa else ""
    for brand in BRAND_OFFICIAL_DOMAINS:
        b = brand.lower()
        if len(b) < 3 or b in _GENERIC_BRANDS:
            continue
        if b not in tokens:
            continue
        # The handle belongs to the brand only when it contains the brand.
        if b not in handle:
            return Finding(
                "QR_PAYEE_NAME_MISMATCH",
                20,
                f"This QR code says the payee is '{pn.strip()}' but the UPI ID does not belong to {b}.",
            )
    return None


def check_prefilled_amount(am: str | None) -> Finding | None:
    if am is not None and am.strip() != "":
        return Finding(
            "QR_PREFILLED_AMOUNT",
            10,
            "This QR code already has an amount filled in. Check it before paying.",
        )
    return None


def check_note_scam_words(tn: str | None) -> Finding | None:
    note = (tn or "").lower()
    for word in NOTE_SCAM_WORDS:
        if word in note:
            return Finding(
                "QR_NOTE_SCAM_WORDS",
                15,
                "This QR code note uses a word scammers often use to trick you.",
            )
    return None


def analyze_upi_qr(payload: str, db=None) -> list[Finding]:
    """Run QR-specific checks plus the normal UPI analyzer on pa."""
    parsed = parse_upi_uri(payload)
    findings: list[Finding] = []
    for f in (
        check_payee_name_mismatch(parsed.get("pa"), parsed.get("pn")),
        check_prefilled_amount(parsed.get("am")),
        check_note_scam_words(parsed.get("tn")),
    ):
        if f is not None:
            findings.append(f)
    pa = parsed.get("pa")
    if pa:
        findings.extend(analyze_upi(pa, db))
    return findings
