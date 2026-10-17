"""Golden verdict tests: hand-written cases through analyzers + scoring.

URLs are address-only (no fetching), UPI uses db=None. Each case is its own
test so failures name the exact case. The assert message prints the case,
the score and the findings.
"""

from __future__ import annotations

import json
import os

import pytest

from app.services.message_analyzer import analyze_message, extract_urls
from app.services.scoring import ScoreResult, calculate_score
from app.services.upi_analyzer import analyze_upi, extract_upi_ids, normalize_upi
from app.services.url_analyzer import analyze_url

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "golden_cases.json")


def load_cases() -> list[dict]:
    with open(DATA_PATH, encoding="utf-8") as f:
        cases = json.load(f)
    return cases


def score_case(case_type: str, text: str, age_days=None) -> ScoreResult:
    """Mirror the endpoint's analyzer mix, without fetching or a database."""
    if case_type == "url":
        url = (text or "").strip()
        if "://" not in url:
            url = "https://" + url
        findings = analyze_url(url, age_days=age_days)
    elif case_type == "upi":
        findings = analyze_upi(normalize_upi(text))
    elif case_type == "message":
        findings = list(analyze_message(text or ""))
        for u in extract_urls(text or "")[:3]:
            link = u.strip()
            if "://" not in link:
                link = "https://" + link
            findings.extend(analyze_url(link))
        for uid in extract_upi_ids(text or "")[:3]:
            findings.extend(analyze_upi(uid))
    else:
        raise ValueError(f"unknown case type: {case_type!r}")
    return calculate_score(findings)


def _case_ids() -> list[str]:
    return [c["id"] for c in load_cases()]


@pytest.mark.parametrize("case_id", _case_ids())
def test_golden_case_verdict(case_id: str):
    cases = {c["id"]: c for c in load_cases()}
    case = cases[case_id]
    scored = score_case(case["type"], case["input"], case.get("age_days"))
    detail = ", ".join(f"{f.rule_code}({f.severity})" for f in scored.findings)
    assert scored.verdict == case["expected"], (
        f"case {case_id} [{case['type']}] {case['input']!r}: "
        f"expected {case['expected']}, got {scored.verdict} "
        f"(score={scored.risk_score}, findings=[{detail}])"
    )
