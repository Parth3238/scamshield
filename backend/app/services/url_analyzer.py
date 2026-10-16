"""Rule-based URL analyzer. No network calls. Score weights are fixed here."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.models.finding import Finding
from app.rules.brands import BRAND_OFFICIAL_DOMAINS
from app.rules.keywords import SCAM_KEYWORDS
from app.rules.tlds import SUSPICIOUS_TLDS
from app.services.text_utils import levenshtein

# Common two-part public suffixes we handle without a full PSL library.
TWO_PART_SUFFIXES = {
    "co.in",
    "co.uk",
    "com.au",
    "co.nz",
    "co.za",
    "com.br",
    "com.mx",
    "co.jp",
    "com.sg",
    "co.kr",
}


def get_registered_domain(host: str) -> str:
    """Return e.g. example.com from a.b.example.com.

    Simple approach: last 2 labels, or last 3 when ending in a known
    two-part suffix like co.in / com.au / co.uk.
    LIMITATION: this is not the full Public Suffix List, so it is wrong for
    suffixes like appspot.com, github.io, s3.amazonaws.com etc. where the
    real registered domain has more parts. Good enough for scoring, but a
    proper PSL library should replace this later.
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    labels = [p for p in h.split(".") if p]
    if len(labels) <= 2:
        return h
    last_two = ".".join(labels[-2:])
    if last_two in TWO_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _tokens(text: str) -> set[str]:
    return set(p for p in re.split(r"[^a-z0-9]+", (text or "").lower()) if p)


# Re-exported here so old imports (app.services.url_analyzer.levenshtein)
# keep working after the move to text_utils.
__all__ = [  # noqa: F822
    "get_registered_domain",
    "levenshtein",
    "analyze_url",
]


def check_no_https(parsed) -> Finding | None:
    if (parsed.scheme or "").lower() == "http":
        return Finding("NO_HTTPS", 10, "This link uses http instead of https, so data is not encrypted.")
    return None


def check_ip_address_host(host: str) -> Finding | None:
    h = (host or "").strip().rstrip(".")
    if not h:
        return None
    try:
        ipaddress.ip_address(h)
        return Finding("IP_ADDRESS_HOST", 25, "This link uses an IP address instead of a normal website name, which is suspicious.")
    except ValueError:
        return None


def check_suspicious_tld(host: str) -> Finding | None:
    h = (host or "").lower()
    for tld in SUSPICIOUS_TLDS:
        if h == tld.lstrip(".") or h.endswith(tld):
            return Finding("SUSPICIOUS_TLD", 15, f"This link ends with {tld}, which scammers use often. Be careful.")
    return None


def check_at_symbol(url: str, parsed) -> Finding | None:
    # Only flag '@' in the network location (user info trick), not in path.
    if "@" in (parsed.netloc or ""):
        return Finding("AT_SYMBOL_IN_URL", 25, "This link has an @ sign hiding the real website address.")
    return None


def check_too_many_subdomains(host: str, registered: str) -> Finding | None:
    h = (host or "").lower().rstrip(".")
    if not h or not registered or h == registered:
        return None
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    if h.endswith("." + registered):
        sub = h[: -len(registered) - 1]
        levels = [p for p in sub.split(".") if p]
        if len(levels) > 3:
            return Finding("TOO_MANY_SUBDOMAINS", 10, "This link has too many parts before the main domain, which scammers use to confuse you.")
    return None


def check_long_url(url: str) -> Finding | None:
    if len(url or "") > 100:
        return Finding("LONG_URL", 5, "This link is very long, which scammers use to hide the real address.")
    return None


def check_punycode(host: str) -> Finding | None:
    if "xn--" in (host or "").lower():
        return Finding("PUNYCODE_DOMAIN", 20, "This link uses special foreign characters that can fake a real website name.")
    return None


def check_brand_in_subdomain(host: str, path_query: str, registered: str) -> Finding | None:
    host_l = (host or "").lower()
    combined_tokens = _tokens(host_l + " " + (path_query or ""))
    reg_l = (registered or "").lower()
    for brand, official in BRAND_OFFICIAL_DOMAINS.items():
        official_l = [d.lower() for d in official]
        if reg_l in official_l:
            continue  # real official domain, not abuse
        if brand.lower() in combined_tokens:
            return Finding(
                "BRAND_IN_SUBDOMAIN",
                30,
                f"This link mentions {brand} but does not go to the official {brand} website.",
            )
    return None


def check_lookalike(registered: str) -> Finding | None:
    reg = (registered or "").lower().rstrip(".")
    if not reg:
        return None
    try:
        ipaddress.ip_address(reg)
        return None
    except ValueError:
        pass
    for brand, official_list in BRAND_OFFICIAL_DOMAINS.items():
        for official in official_list:
            off = official.lower()
            if reg == off:
                continue  # exact official domain: never flag
            # Skip very short names (sbi, upi) to avoid false positives.
            sld = off.split(".")[0]
            if len(sld) < 4:
                continue
            if 1 <= levenshtein(reg, off) <= 2:
                return Finding(
                    "LOOKALIKE_DOMAIN",
                    35,
                    f"This website name looks almost the same as the real {brand} website, with 1-2 letters changed.",
                )
    return None


def check_scam_keywords(url: str) -> Finding | None:
    u = (url or "").lower()
    for kw in SCAM_KEYWORDS:
        if kw.lower() in u:
            return Finding("SCAM_KEYWORDS_IN_URL", 10, f"This link contains the word '{kw}', which scammers use to create fear or greed.")
    return None


def check_domain_age(age_days: int | None) -> Finding | None:
    """Flag a young domain by its RDAP age in days. Offline and pure.

    age_days None (unknown) and old domains (90+ days) give no finding.
    An old domain is never called safe: age alone proves nothing.
    """
    if age_days is None:
        return None
    try:
        age = int(age_days)
    except (TypeError, ValueError):
        return None
    if age < 30:
        return Finding(
            "DOMAIN_VERY_NEW",
            30,
            f"This website was created only {age} days ago. Scam sites are often brand new.",
        )
    if age < 90:
        return Finding(
            "DOMAIN_NEW",
            15,
            f"This website was created {age} days ago, which is quite new. Be careful.",
        )
    return None


def _chain_list(fetch_result) -> list[str]:
    if fetch_result is None:
        return []
    if isinstance(fetch_result, dict):
        chain = fetch_result.get("redirect_chain") or []
        return list(chain)
    chain = getattr(fetch_result, "redirect_chain", None) or []
    return list(chain)


def check_redirect_chain_long(fetch_result) -> Finding | None:
    chain = _chain_list(fetch_result)
    if chain and len(chain) - 1 > 2:
        return Finding("REDIRECT_CHAIN_LONG", 10, "This link jumps through too many redirects before reaching the final page.")
    return None


def check_redirect_cross_domain(fetch_result, original_url: str) -> Finding | None:
    chain = _chain_list(fetch_result)
    if not chain:
        return None
    first = chain[0]
    final = chain[-1]
    if isinstance(fetch_result, dict):
        final = fetch_result.get("final_url") or final
    else:
        final = getattr(fetch_result, "final_url", final) or final
    try:
        first_host = (urlparse(first).hostname or "").lower()
        final_host = (urlparse(final).hostname or "").lower()
    except Exception:
        return None
    if not first_host or not final_host:
        return None
    if get_registered_domain(first_host) != get_registered_domain(final_host):
        return Finding("REDIRECT_CROSS_DOMAIN", 15, "This link finally opens a different website than where it started.")
    return None


def check_known_bad_domain(registered: str, db=None) -> Finding | None:
    """Flag registered domains the community has reported. Needs a db session."""
    if db is None or not registered:
        return None
    try:
        from app.services.indicators import is_known_bad

        if is_known_bad(db, "domain", registered):
            return Finding(
                "KNOWN_BAD_INDICATOR",
                50,
                "Other users have reported this website as unsafe. Treat it with care, but this alone does not prove it is a scam.",
            )
    except Exception:  # nosec B110 - community lookup is best-effort; analyzer must never crash
        pass
    return None


def analyze_url(url: str, fetch_result=None, db=None, age_days: int | None = None) -> list[Finding]:
    """Analyze a URL string. Optionally also analyze fetch_result chain.

    Pass db to also check the registered domain against community indicators.
    Pass age_days (from RDAP) to flag very new domains; None skips the check
    so this function stays offline and string-only.
    """
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower()
    registered = get_registered_domain(host) if host else ""
    path_query = (parsed.path or "") + "?" + (parsed.query or "")

    findings: list[Finding] = []
    for f in (
        check_no_https(parsed),
        check_ip_address_host(host),
        check_suspicious_tld(host),
        check_at_symbol(url, parsed),
        check_too_many_subdomains(host, registered),
        check_long_url(url),
        check_punycode(host),
        check_brand_in_subdomain(host, path_query, registered),
        check_lookalike(registered),
        check_scam_keywords(url),
        check_domain_age(age_days),
        check_redirect_chain_long(fetch_result),
        check_redirect_cross_domain(fetch_result, url),
        check_known_bad_domain(registered, db),
    ):
        if f is not None:
            findings.append(f)
    return findings
