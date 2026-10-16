"""Validate editable rule data files. Fails with a clear message on bad data.

These tests read backend/app/rules/data/*.yaml directly (with
yaml.safe_load only) so contributors get a fast, specific failure without
running the whole app. The same checks also run in scripts/validate_rules.py.
"""

from __future__ import annotations

import concurrent.futures
import re
import time
from pathlib import Path

import yaml

DATA_DIR = Path(__file__).parent.parent / "app" / "rules" / "data"

MAX_PATTERN_LENGTH = 200
REGEX_TIMEOUT_SECONDS = 1.0
REGEX_SLOW_SECONDS = 0.5

_NESTED_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*]")
_STACKED_RE = re.compile(r"(?:\+\+|\*\*|\+\*|\*\+)")

_TEST_STRINGS = [
    "a" * 2000,
    "a" * 2000 + "!",
    "ab " * 1000,
]


def _load(name: str):
    path = DATA_DIR / name
    assert path.exists(), f"missing rule file: {name}"
    with open(path, encoding="utf-8") as f:
        # NOTE: safe_load only. Never yaml.load (it can run arbitrary code).
        data = yaml.safe_load(f)
    assert data is not None, f"{name} is empty"
    assert isinstance(data, dict), f"{name} top level must be a mapping"
    return data, path


def _search_timeout(compiled: re.Pattern, text: str, timeout: float) -> float:
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(compiled.search, text)
        try:
            fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise AssertionError(
                f"pattern {compiled.pattern!r} timed out after {timeout}s "
                "(possible catastrophic backtracking)"
            )
    return time.perf_counter() - start


def test_brands_have_official_domains():
    data, _ = _load("brands.yaml")
    assert set(data.keys()) == {"brands"}, f"brands.yaml top level must be exactly {{'brands'}}, got {set(data.keys())}"
    brands = data["brands"]
    assert isinstance(brands, dict) and brands, "brands.yaml must contain at least one brand"
    for brand, entry in brands.items():
        assert isinstance(entry, dict), f"brand {brand!r} entry must be a mapping"
        assert set(entry.keys()) == {"official_domains"}, (
            f"brand {brand!r} has unknown fields {set(entry.keys()) - {'official_domains'}}"
        )
        domains = entry["official_domains"]
        assert isinstance(domains, list) and len(domains) >= 1, f"brand {brand!r} has no official domain"


def test_brand_domains_lowercase_no_scheme_or_path():
    data, _ = _load("brands.yaml")
    for brand, entry in data["brands"].items():
        for d in entry["official_domains"]:
            assert isinstance(d, str) and d, f"brand {brand!r} has an empty domain"
            assert d == d.lower(), f"domain {d!r} (brand {brand!r}) must be lowercase"
            assert "://" not in d, f"domain {d!r} (brand {brand!r}) must not contain a scheme (no https://)"
            assert "/" not in d, f"domain {d!r} (brand {brand!r}) must not contain a path (no /login)"
            assert " " not in d, f"domain {d!r} (brand {brand!r}) must not contain spaces"


def test_shortener_domains_lowercase_no_scheme_or_path():
    data, _ = _load("message_patterns.yaml")
    domains = data["patterns"]["SHORT_LINK"]["domains"]
    for d in domains:
        assert isinstance(d, str) and d, "shortener domain must be a non-empty string"
        assert d == d.lower(), f"shortener domain {d!r} must be lowercase"
        assert "://" not in d, f"shortener domain {d!r} must not contain a scheme"
        assert "/" not in d, f"shortener domain {d!r} must not contain a path"


def test_tlds_have_leading_dot():
    data, _ = _load("suspicious_tlds.yaml")
    assert set(data.keys()) == {"suspicious_tlds"}, f"suspicious_tlds.yaml has unknown fields: {set(data.keys())}"
    tlds = data["suspicious_tlds"]
    assert isinstance(tlds, list) and tlds, "suspicious_tlds must be a non-empty list"
    for tld in tlds:
        assert isinstance(tld, str), f"TLD {tld!r} must be a string"
        assert tld.startswith("."), f"TLD {tld!r} lacks the leading dot (e.g. '.xyz')"
        assert tld == tld.lower(), f"TLD {tld!r} must be lowercase"


def test_no_duplicate_entries():
    data, _ = _load("scam_keywords.yaml")
    assert set(data.keys()) == {"scam_keywords"}, "scam_keywords.yaml has unknown fields"
    kws = data["scam_keywords"]
    lowered = [str(k).lower() for k in kws]
    assert len(set(lowered)) == len(lowered), f"duplicate scam keyword found in {kws}"

    data, _ = _load("suspicious_tlds.yaml")
    tlds = [str(t).lower() for t in data["suspicious_tlds"]]
    assert len(set(tlds)) == len(tlds), "duplicate TLD found"

    data, _ = _load("upi_handles.yaml")
    assert set(data.keys()) == {"known_upi_handles"}, "upi_handles.yaml has unknown fields"
    handles = [str(h).lower() for h in data["known_upi_handles"]]
    assert len(set(handles)) == len(handles), "duplicate UPI handle found"

    data, _ = _load("support_words.yaml")
    assert set(data.keys()) == {"support_words"}, "support_words.yaml has unknown fields"
    words = [str(w).lower() for w in data["support_words"]]
    assert len(set(words)) == len(words), "duplicate support word found"


def test_message_regexes_compile_and_fast():
    data, _ = _load("message_patterns.yaml")
    pats = data["patterns"]
    phrases: list[str] = []
    for key in ("URGENCY_LANGUAGE", "ACCOUNT_THREAT", "REWARD_BAIT", "AUTHORITY_IMPERSONATION"):
        for lang in ("english", "hinglish"):
            phrases.extend(pats[key].get(lang, []) or [])
    for sub in ("secret_words", "request_verbs", "negations"):
        for lang in ("english", "hinglish"):
            phrases.extend(pats["ASKS_FOR_SECRET"][sub].get(lang, []) or [])
    phrases.extend(pats["ASKS_TO_INSTALL_APP"].get("remote_apps", []) or [])
    phrases.extend(pats["SHORT_LINK"].get("domains", []) or [])
    assert phrases, "message_patterns.yaml contains no phrases"

    for raw in phrases:
        assert isinstance(raw, str) and raw.strip(), "message pattern must be a non-empty string"
        assert len(raw) <= MAX_PATTERN_LENGTH, f"pattern {raw!r} too long (max {MAX_PATTERN_LENGTH})"
        assert not _NESTED_RE.search(raw), f"pattern {raw!r} looks dangerous (nested quantifiers like (a+)+)"
        assert not _STACKED_RE.search(raw), f"pattern {raw!r} looks dangerous (stacked quantifiers)"
        try:
            compiled = re.compile(r"\b" + re.escape(raw.lower()) + r"\b")
        except re.error as exc:
            raise AssertionError(f"pattern {raw!r} does not compile: {exc}") from None
        for test in _TEST_STRINGS:
            elapsed = _search_timeout(compiled, test, REGEX_TIMEOUT_SECONDS)
            assert elapsed <= REGEX_SLOW_SECONDS, (
                f"pattern {raw!r} is too slow ({elapsed:.2f}s, possible catastrophic backtracking)"
            )


def test_no_unknown_yaml_fields():
    data, _ = _load("brands.yaml")
    assert set(data.keys()) == {"brands"}, f"brands.yaml has unknown fields: {set(data.keys()) - {'brands'}}"

    data, _ = _load("message_patterns.yaml")
    assert set(data.keys()) == {"patterns"}, f"message_patterns.yaml has unknown fields: {set(data.keys())}"
    expected_groups = {
        "URGENCY_LANGUAGE",
        "ACCOUNT_THREAT",
        "REWARD_BAIT",
        "ASKS_FOR_SECRET",
        "ASKS_TO_INSTALL_APP",
        "AUTHORITY_IMPERSONATION",
        "SHORT_LINK",
    }
    assert set(data["patterns"].keys()) == expected_groups, (
        f"message_patterns.yaml groups must be exactly {expected_groups}, got {set(data['patterns'].keys())}"
    )
    for key in ("URGENCY_LANGUAGE", "ACCOUNT_THREAT", "REWARD_BAIT", "AUTHORITY_IMPERSONATION"):
        assert set(data["patterns"][key].keys()) == {"english", "hinglish"}, (
            f"{key} must have exactly english/hinglish keys"
        )
    secret = data["patterns"]["ASKS_FOR_SECRET"]
    assert set(secret.keys()) == {"secret_words", "request_verbs", "negations"}, (
        "ASKS_FOR_SECRET must have exactly secret_words/request_verbs/negations"
    )
    for sub in ("secret_words", "request_verbs", "negations"):
        assert set(secret[sub].keys()) == {"english", "hinglish"}, f"ASKS_FOR_SECRET.{sub} must have english/hinglish"
    assert set(data["patterns"]["ASKS_TO_INSTALL_APP"].keys()) == {"remote_apps"}, (
        "ASKS_TO_INSTALL_APP must have exactly remote_apps"
    )
    assert set(data["patterns"]["SHORT_LINK"].keys()) == {"domains"}, "SHORT_LINK must have exactly domains"

    data, _ = _load("combos.yaml")
    assert set(data.keys()) == {"url_finding_codes", "combos"}, (
        f"combos.yaml has unknown fields: {set(data.keys())}"
    )
    for entry in data["combos"]:
        allowed = {"rule_code", "bonus", "group_a", "group_b", "any_other", "any_url", "explanation"}
        assert set(entry.keys()) <= allowed, f"combo {entry.get('rule_code')} has unknown fields: {set(entry.keys()) - allowed}"


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def test_no_cross_brand_lookalike_domains():
    """One brand's official domain must not look like another brand's domain.

    Otherwise every visit to the real site would trigger LOOKALIKE_DOMAIN
    for the other brand (1-2 letter difference, same rule as the analyzer).
    """
    data, _ = _load("brands.yaml")
    items: list[tuple[str, str]] = []
    for brand, entry in data["brands"].items():
        for d in entry["official_domains"]:
            items.append((brand, str(d).lower()))
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            b1, d1 = items[i]
            b2, d2 = items[j]
            if b1 == b2 or d1 == d2:
                continue
            # Mirror url_analyzer.check_lookalike: skip very short names.
            if len(d1.split(".")[0]) < 4 or len(d2.split(".")[0]) < 4:
                continue
            dist = _levenshtein(d1, d2)
            assert not (1 <= dist <= 2), (
                f"official domain {d1!r} (brand {b1!r}) looks like {d2!r} "
                f"(brand {b2!r}): distance {dist}. It would always flag LOOKALIKE_DOMAIN."
            )
