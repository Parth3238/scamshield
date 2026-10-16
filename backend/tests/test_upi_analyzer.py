"""Unit tests for the UPI analyzer. No real internet."""

from __future__ import annotations

from app.models.db_models import Indicator
from app.services.upi_analyzer import (
    analyze_upi,
    extract_upi_ids,
    is_valid_upi_format,
    normalize_upi,
)


def _codes(upi_id, db=None):
    return [f.rule_code for f in analyze_upi(upi_id, db)]


def test_normalize():
    assert normalize_upi("  Rahul@OKAxis ") == "rahul@okaxis"


def test_valid_ids_have_no_findings():
    assert analyze_upi("9876543210@ybl") == []
    assert analyze_upi("rahul.sharma@okaxis") == []


def test_mobile_number_not_flagged_random():
    assert "RANDOM_LOOKING_UPI" not in _codes("9876543210@ybl")


def test_invalid_format():
    assert "INVALID_UPI_FORMAT" in _codes("not-a-upi")
    assert "INVALID_UPI_FORMAT" in _codes("a@b")
    assert "INVALID_UPI_FORMAT" in _codes("rahul@ok123")
    assert "INVALID_UPI_FORMAT" in _codes("a@@b")
    assert not is_valid_upi_format("badupi")
    assert is_valid_upi_format("rahul@okaxis")


def test_unknown_handle():
    assert "UNKNOWN_UPI_HANDLE" in _codes("rahul@unknownhandle")


def test_lookalike_handle():
    assert "LOOKALIKE_UPI_HANDLE" in _codes("rahul@oksb1")
    assert "LOOKALIKE_UPI_HANDLE" in _codes("rahul@okhdfcbnk")
    # Known handles are never lookalikes of each other.
    assert "LOOKALIKE_UPI_HANDLE" not in _codes("9876543210@ybl")


def test_brand_in_name():
    assert "BRAND_IN_UPI_NAME" in _codes("paytmuser@ybl")
    # Brand's own handle must not flag.
    assert "BRAND_IN_UPI_NAME" not in _codes("myname@paytm")


def test_support_word():
    assert "SUPPORT_WORD_IN_UPI" in _codes("rahul.support@ybl")
    assert "SUPPORT_WORD_IN_UPI" in _codes("kyc.update@okaxis")


def test_random_looking():
    assert "RANDOM_LOOKING_UPI" in _codes("rahul8472903x@okaxis")
    assert "RANDOM_LOOKING_UPI" not in _codes("rahul.sharma@okaxis")


def test_explanations_plain_english():
    for f in analyze_upi("sbi.refund.support@unknownhandle"):
        assert isinstance(f.explanation, str) and len(f.explanation.split()) >= 5


def test_extract_skips_emails():
    assert extract_upi_ids("mail me at name@gmail.com please") == []
    assert extract_upi_ids("contact name@company.co.in today") == []
    assert extract_upi_ids("Hi, dinner at 8?") == []


def test_extract_finds_upi():
    found = extract_upi_ids("pay to rahul@okaxis please")
    assert found == ["rahul@okaxis"]
    found = extract_upi_ids("pay to ram@okhdfc.")
    assert found == ["ram@okhdfc"]


def _make_mem_db():
    # In-memory SQLite by default; PostgreSQL when TEST_DATABASE_URL is
    # set (see tests/db_helper.py). Never point it at the app database.
    from tests.db_helper import make_test_engine, make_testing_session

    engine = make_test_engine()
    return make_testing_session(engine)


def test_known_bad_indicator():
    TestingSession = _make_mem_db()
    db = TestingSession()
    try:
        db.add(Indicator(type="upi", value="badguy@oksbi", confidence=100, source="manual"))
        db.commit()
        assert "KNOWN_BAD_INDICATOR" in _codes("badguy@oksbi", db)
        assert "KNOWN_BAD_INDICATOR" not in _codes("goodguy@oksbi", db)
    finally:
        db.close()
