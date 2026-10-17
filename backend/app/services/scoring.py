"""Rule-based scoring. Sum severities, add combination bonuses, cap at 100.

No LLM, no randomness. Combination bonuses come from app/rules/combos.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.finding import Finding
from app.rules.combos import COMBOS, URL_FINDING_CODES


@dataclass
class ScoreResult:
    risk_score: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""


SUMMARIES = {
    "safe": "No strong scam signs found, but stay careful with payments.",
    "suspicious": "This link shows some warning signs. Do not pay or share OTPs before verifying.",
    "dangerous": "This link looks dangerous. Do not pay, click further, or share personal details.",
}


def _verdict_for(score: int) -> str:
    if score <= 30:
        return "safe"
    if score <= 60:
        return "suspicious"
    return "dangerous"


def _combo_fires(rule, codes: set[str]) -> bool:
    """True when group_a matches and at least one group_b/other/url matches."""
    if not any(c in codes for c in rule.group_a):
        return False
    if rule.group_b and any(c in codes for c in rule.group_b):
        return True
    if rule.any_other and any(c not in rule.group_a for c in codes):
        return True
    if rule.any_url and any(c in codes for c in URL_FINDING_CODES):
        return True
    return False


def combo_findings(codes: set[str]) -> list[Finding]:
    """Build one COMBO_ finding per matching combination rule."""
    out: list[Finding] = []
    for rule in COMBOS:
        if _combo_fires(rule, codes):
            out.append(Finding(rule.rule_code, rule.bonus, rule.explanation))
    return out


def calculate_score(findings: list[Finding]) -> ScoreResult:
    """Dedup by rule_code (keep highest severity), add combos, cap 100."""
    best: dict[str, Finding] = {}
    for f in findings or []:
        prev = best.get(f.rule_code)
        if prev is None or f.severity > prev.severity:
            best[f.rule_code] = f
    unique = list(best.values())
    codes = set(best.keys())
    combined = unique + combo_findings(codes)
    total = sum(f.severity for f in combined)
    total = max(0, min(100, total))
    verdict = _verdict_for(total)
    ordered = sorted(combined, key=lambda f: f.severity, reverse=True)
    return ScoreResult(
        risk_score=total,
        verdict=verdict,
        findings=ordered,
        summary=SUMMARIES[verdict],
    )
