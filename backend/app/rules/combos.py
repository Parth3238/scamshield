"""Combination bonuses: extra risk when two warning signs appear together.

Edit backend/app/rules/data/combos.yaml instead. This module is a thin
wrapper over the loader so scoring behavior is unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.rules.loader import load_rules


@dataclass(frozen=True)
class ComboRule:
    rule_code: str
    bonus: int
    # At least one of these must be present.
    group_a: tuple[str, ...]
    # At least one of these must be present (empty = no constraint).
    group_b: tuple[str, ...] = ()
    # Also fire when ANY other finding is present besides group_a.
    any_other: bool = False
    # Also fire when ANY URL-analyzer finding is present.
    any_url: bool = False
    explanation: str = ""


_rules = load_rules()

# Every rule_code produced by app/services/url_analyzer.py.
URL_FINDING_CODES: frozenset[str] = _rules.url_finding_codes

COMBOS: tuple[ComboRule, ...] = tuple(
    ComboRule(
        rule_code=c["rule_code"],
        bonus=c["bonus"],
        group_a=tuple(c["group_a"]),
        group_b=tuple(c["group_b"]),
        any_other=bool(c["any_other"]),
        any_url=bool(c["any_url"]),
        explanation=c["explanation"],
    )
    for c in _rules.combos
)
