"""Evaluate golden cases: confusion matrix, false positives/negatives.

Usage: python scripts/evaluate.py
Runs tests/data/golden_cases.json through the analyzers (address-only,
no fetching, no database) and prints expected-vs-predicted counts.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.test_golden_cases import load_cases, score_case

LABELS = ("safe", "suspicious", "dangerous")


def main() -> None:
    cases = load_cases()
    matrix: dict[str, dict[str, int]] = {
        exp: {pred: 0 for pred in LABELS} for exp in LABELS
    }
    false_positives: list[str] = []
    false_negatives: list[str] = []
    for case in cases:
        scored = score_case(case["type"], case["input"])
        predicted = scored.verdict
        expected = case["expected"]
        matrix[expected][predicted] += 1
        if expected == "safe" and predicted in ("suspicious", "dangerous"):
            false_positives.append(case["id"])
        if expected == "dangerous" and predicted == "safe":
            false_negatives.append(case["id"])

    header = "expected \\ predicted" + "".join(f"{p:>12}" for p in LABELS)
    print(header)
    for exp in LABELS:
        row = "".join(f"{matrix[exp][p]:>12}" for p in LABELS)
        print(f"{exp:<20}{row}")
    print(f"cases: {len(cases)}")
    print(
        f"false positives (safe flagged as suspicious/dangerous): "
        f"{len(false_positives)} {false_positives}"
    )
    print(
        f"false negatives (dangerous marked safe): "
        f"{len(false_negatives)} {false_negatives}"
    )


if __name__ == "__main__":
    main()
