from app.models.finding import Finding
from app.services.scoring import calculate_score


def test_empty_is_safe():
    r = calculate_score([])
    assert r.risk_score == 0
    assert r.verdict == "safe"


def test_boundary_30_safe():
    r = calculate_score([Finding("A", 10, "a"), Finding("B", 20, "b")])
    assert r.risk_score == 30
    assert r.verdict == "safe"


def test_boundary_31_suspicious():
    r = calculate_score([Finding("A", 15, "a"), Finding("B", 16, "b")])
    assert r.risk_score == 31
    assert r.verdict == "suspicious"


def test_boundary_60_suspicious():
    r = calculate_score([Finding("A", 25, "a"), Finding("B", 35, "b")])
    assert r.risk_score == 60
    assert r.verdict == "suspicious"


def test_boundary_61_dangerous():
    r = calculate_score(
        [Finding("A", 26, "a"), Finding("B", 35, "b")]
    )
    assert r.risk_score == 61
    assert r.verdict == "dangerous"


def test_cap_at_100():
    many = [Finding(f"R{i}", 30, "x") for i in range(5)]  # 150 -> 100
    r = calculate_score(many)
    assert r.risk_score == 100
    assert r.verdict == "dangerous"


def test_duplicate_rule_counted_once():
    r = calculate_score(
        [Finding("X", 10, "low"), Finding("X", 25, "high"), Finding("Y", 10, "y")]
    )
    assert r.risk_score == 35  # 25 + 10, not 10 + 25 + 10
    assert [f.rule_code for f in r.findings].count("X") == 1


def test_sorted_highest_first():
    r = calculate_score(
        [Finding("LOW", 5, "l"), Finding("HIGH", 35, "h"), Finding("MID", 15, "m")]
    )
    assert [f.severity for f in r.findings] == [35, 15, 5]
