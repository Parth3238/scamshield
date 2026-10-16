"""Rule-based message scam analyzer. No network calls."""

from __future__ import annotations

import re

from app.models.finding import Finding
from app.rules.message_patterns import (
    ACCOUNT_THREAT_PATTERNS,
    AUTHORITY_PATTERNS,
    NEGATION_PATTERNS,
    REMOTE_APPS,
    REWARD_PATTERNS,
    SECRET_REQUEST_VERBS,
    SECRET_WORDS,
    SHORTENER_DOMAINS,
    URGENCY_PATTERNS,
)

URL_RE = re.compile(r"https?://[^\s,;()<>\"']+", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|in|co\.in|org|net|xyz|top|click|ly|io|me|info|biz|online|site|store|app|link)\b(?:/[^\s,;()<>\"']*)?",
    re.IGNORECASE,
)


def normalize_text(text: str) -> str:
    """Lowercase and collapse whitespace."""
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _contains_any(normalized: str, phrases: list[str]) -> bool:
    for p in phrases:
        if re.search(r"\b" + re.escape(p.lower()) + r"\b", normalized):
            return True
    return False


def extract_urls(text: str) -> list[str]:
    """Find up to 3 unique URLs: http(s) links and bare domains like bit.ly/abc."""
    if not text:
        return []
    http_hits: list[tuple[int, str]] = []
    for m in URL_RE.finditer(text):
        u = m.group(0).strip().rstrip(".,!?:;)'\"")
        if u:
            http_hits.append((m.start(), u))
    http_spans = [(m.start(), m.end()) for m in URL_RE.finditer(text)]

    def _inside_http(pos: int) -> bool:
        return any(s <= pos < e for s, e in http_spans)

    bare_hits: list[tuple[int, str]] = []
    for m in BARE_DOMAIN_RE.finditer(text):
        if _inside_http(m.start()):
            continue
        u = m.group(0).strip().rstrip(".,!?:;)'\"")
        if u:
            bare_hits.append((m.start(), u))

    ordered = sorted(http_hits + bare_hits, key=lambda x: x[0])
    found: list[str] = []
    seen: set[str] = set()
    for _, u in ordered:
        key = u.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append(u)
        if len(found) >= 3:
            break
    return found


def check_urgency(norm: str) -> Finding | None:
    if _contains_any(norm, URGENCY_PATTERNS):
        return Finding(
            "URGENCY_LANGUAGE",
            10,
            "This message pressures you to act fast, which scammers do to stop you from thinking.",
        )
    return None


def check_account_threat(norm: str) -> Finding | None:
    if _contains_any(norm, ACCOUNT_THREAT_PATTERNS):
        return Finding(
            "ACCOUNT_THREAT",
            20,
            "This message threatens that your account or KYC will be blocked, which scammers use to scare you.",
        )
    # Flexible: "account will be blocked" with filler words.
    if re.search(r"\baccount\b.{0,25}\b(blocked|suspended|closed)\b", norm):
        return Finding(
            "ACCOUNT_THREAT",
            20,
            "This message threatens that your account or KYC will be blocked, which scammers use to scare you.",
        )
    if re.search(r"\bkhata\b.{0,25}\b(band|blocked|closed)\b", norm):
        return Finding(
            "ACCOUNT_THREAT",
            20,
            "This message threatens that your account or KYC will be blocked, which scammers use to scare you.",
        )
    if re.search(r"\bkyc\b.{0,25}\b(pending|expired|blocked|suspended|closed)\b", norm):
        return Finding(
            "ACCOUNT_THREAT",
            20,
            "This message threatens that your account or KYC will be blocked, which scammers use to scare you.",
        )
    return None


def check_reward_bait(norm: str) -> Finding | None:
    if _contains_any(norm, REWARD_PATTERNS):
        return Finding(
            "REWARD_BAIT",
            20,
            "This message promises a prize or reward, which scammers use to tempt you.",
        )
    return None


def _negation_re() -> re.Pattern:
    parts = [re.escape(p.lower()) for p in NEGATION_PATTERNS]
    return re.compile(r"\b(?:%s)\b" % "|".join(parts))


_NEG_RE: re.Pattern | None = None


def check_asks_for_secret(norm: str) -> Finding | None:
    global _NEG_RE
    if _NEG_RE is None:
        _NEG_RE = _negation_re()
    verbs = "|".join(re.escape(v.lower()) for v in SECRET_REQUEST_VERBS)
    secrets = "|".join(re.escape(s.lower()) for s in SECRET_WORDS)
    patterns = [
        re.compile(r"\b(?:%s)\b.{0,30}\b(?:%s)\b" % (verbs, secrets)),
        re.compile(r"\b(?:%s)\b.{0,30}\b(?:%s)\b" % (secrets, verbs)),
    ]
    for pat in patterns:
        for m in pat.finditer(norm):
            window = norm[max(0, m.start() - 30) : m.end()]
            if _NEG_RE.search(window):
                continue
            return Finding(
                "ASKS_FOR_SECRET",
                35,
                "This message asks you to share your OTP, PIN, CVV or password. Real banks never ask for these.",
            )
    return None


def check_install_app(norm: str) -> Finding | None:
    if re.search(r"\bapk\b", norm):
        return Finding(
            "ASKS_TO_INSTALL_APP",
            30,
            "This message asks you to install an app or file that can let scammers control your phone.",
        )
    apps = "|".join(re.escape(a.lower()) for a in REMOTE_APPS)
    if re.search(r"\b(?:install|download)\b.{0,30}\b(?:%s)\b" % apps, norm) or re.search(
        r"\b(?:%s)\b.{0,30}\b(?:install|download)\b" % apps, norm
    ):
        return Finding(
            "ASKS_TO_INSTALL_APP",
            30,
            "This message asks you to install an app or file that can let scammers control your phone.",
        )
    return None


def check_money_back_trick(norm: str) -> Finding | None:
    if re.search(r"\bsent\s+money\s+by\s+mistake\b", norm):
        return Finding(
            "MONEY_BACK_TRICK",
            30,
            "This message tricks you into returning money or entering your UPI PIN. You never need a PIN to receive money.",
        )
    if re.search(r"\bgalti\s+se\s+(?:paise|paisa|money)\b", norm):
        return Finding(
            "MONEY_BACK_TRICK",
            30,
            "This message tricks you into returning money or entering your UPI PIN. You never need a PIN to receive money.",
        )
    if "upi pin" in norm and "receive" in norm:
        return Finding(
            "MONEY_BACK_TRICK",
            30,
            "This message tricks you into returning money or entering your UPI PIN. You never need a PIN to receive money.",
        )
    if "collect request" in norm and re.search(
        r"\b(approve|accept|authorize|authorise)\b", norm
    ):
        return Finding(
            "MONEY_BACK_TRICK",
            30,
            "This message tricks you into returning money or entering your UPI PIN. You never need a PIN to receive money.",
        )
    return None


def check_authority(norm: str) -> Finding | None:
    if _contains_any(norm, AUTHORITY_PATTERNS):
        return Finding(
            "AUTHORITY_IMPERSONATION",
            25,
            "This message pretends to be from the police or another authority to frighten you.",
        )
    return None


def check_short_link(norm: str) -> Finding | None:
    if _contains_any(norm, SHORTENER_DOMAINS):
        return Finding(
            "SHORT_LINK",
            10,
            "This message uses a shortened link that hides the real website address.",
        )
    return None


def analyze_message(text: str) -> list[Finding]:
    """Analyze message text. Returns findings, highest severity handled by scoring."""
    norm = normalize_text(text)
    if not norm:
        return []
    findings: list[Finding] = []
    for f in (
        check_urgency(norm),
        check_account_threat(norm),
        check_reward_bait(norm),
        check_asks_for_secret(norm),
        check_install_app(norm),
        check_money_back_trick(norm),
        check_authority(norm),
        check_short_link(norm),
    ):
        if f is not None:
            findings.append(f)
    return findings
