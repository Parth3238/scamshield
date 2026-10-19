"""Helpers for community scam reports. No network calls."""

from __future__ import annotations

import datetime
import re
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.db_models import Campaign, Indicator
from app.rules.brands import BRAND_OFFICIAL_DOMAINS
from app.services.upi_analyzer import is_valid_upi_format, mask_upi, normalize_upi
from app.services.url_analyzer import get_registered_domain

SCAM_TYPE_TITLES = {
    "phishing": "Phishing",
    "upi_fraud": "UPI fraud",
    "fake_kyc": "Fake KYC",
    "lottery": "Lottery",
    "digital_arrest": "Digital arrest",
    "other": "Scam",
}


class InvalidTargetError(ValueError):
    """Raised when a report target is neither a URL, domain nor UPI ID."""


def normalize_report_target(raw: str) -> tuple[str, str]:
    """Turn a user-supplied URL, domain or UPI ID into (type, normalized value).

    URLs and bare domains become ("domain", registered_domain).
    UPI IDs become ("upi", normalized_upi_id).
    Raises InvalidTargetError with a clear message when it is neither.
    """
    text = (raw or "").strip()
    if not text:
        raise InvalidTargetError("Tell us the suspicious link, domain or UPI ID.")
    if len(text) > 500:
        raise InvalidTargetError("That target is too long to report.")

    # UPI ID, e.g. name@okhdfc. Anything with a scheme or spaces is not one.
    if "@" in text and "://" not in text and " " not in text:
        normalized = normalize_upi(text)
        if is_valid_upi_format(normalized):
            return ("upi", normalized)
        raise InvalidTargetError(
            "That UPI ID does not look valid. Check it and try again."
        )

    # URL or bare domain, e.g. https://evil.xyz/login or evil.xyz.
    try:
        candidate = text if "://" in text else "https://" + text
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").strip().lower().rstrip(".")
    except Exception:
        raise InvalidTargetError(
            "That link does not look valid. Check it and try again."
        )
    if not host:
        raise InvalidTargetError(
            "That link does not look valid. Check it and try again."
        )
    registered = get_registered_domain(host)
    if not registered or not re.fullmatch(r"[a-z0-9.\-]+", registered):
        raise InvalidTargetError(
            "That link does not look valid. Check it and try again."
        )
    if "." not in registered:
        # Single-label hosts like "localhost" cannot be reported usefully.
        raise InvalidTargetError(
            "That link does not look valid. Check it and try again."
        )
    if len(registered) > 320:
        raise InvalidTargetError("That target is too long to report.")
    return ("domain", registered)


def is_official_domain(value: str) -> bool:
    """True when the value is (or sits under) a real brand domain from brands.py."""
    v = (value or "").strip().lower().rstrip(".")
    if not v:
        return False
    for domains in BRAND_OFFICIAL_DOMAINS.values():
        for official in domains:
            official = official.lower()
            if v == official or v.endswith("." + official):
                return True
    return False


def campaign_title_for(scam_type: str, target_type: str | None, target_value: str | None) -> str:
    """Build a public-safe campaign title. UPI IDs are masked, never raw.

    Truncated to 200 characters to fit the campaigns.title column.
    SQLite ignores String lengths, but PostgreSQL enforces varchar(200)
    and would raise on a long "campaign targeting <value>" title.
    """
    label = SCAM_TYPE_TITLES.get(scam_type, "Scam")
    if target_type == "upi" and target_value:
        title = f"{label} campaign targeting {mask_upi(target_value)}"
    elif target_type == "domain" and target_value:
        title = f"{label} campaign targeting {target_value}"
    else:
        title = f"{label} campaign"
    return title[:200]


def find_or_create_campaign(
    db: Session,
    scam_type: str,
    target_type: str | None,
    target_value: str | None,
) -> Campaign:
    """Reuse the campaign of an existing indicator for this value, else create one."""
    existing = None
    if target_value:
        existing = (
            db.query(Indicator).filter(Indicator.value == target_value).first()
        )
        if existing is not None and existing.campaign_id is not None:
            campaign = db.get(Campaign, existing.campaign_id)
            if campaign is not None:
                return campaign
    now = datetime.datetime.now(datetime.timezone.utc)
    campaign = Campaign(
        title=campaign_title_for(scam_type, target_type, target_value),
        scam_type=scam_type,
        report_count=0,
        first_seen=now,
        last_seen=now,
    )
    db.add(campaign)
    db.flush()
    if target_value and existing is not None and existing.campaign_id is None:
        existing.campaign_id = campaign.id
    return campaign
