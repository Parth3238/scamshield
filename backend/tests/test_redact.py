"""Unit tests for PII redaction before database storage."""

from app.services.redact import redact_pii


def test_redacts_otp():
    assert redact_pii("My OTP is 123456") == "My OTP is [REDACTED]"
    assert "[REDACTED]" in redact_pii("code 4829 ok")
    assert "123456" not in redact_pii("My OTP is 123456")


def test_redacts_phone_number():
    red = redact_pii("Call me at 9876543210 now")
    assert "9876543210" not in red
    assert "[REDACTED]" in red


def test_redacts_phone_with_country_code():
    red = redact_pii("Call +91 9876543210 now")
    assert "9876543210" not in red
    assert "[REDACTED]" in red


def test_redacts_card_number():
    assert "[REDACTED]" in redact_pii("My card 4111111111111111 expired")
    assert "4111111111111111" not in redact_pii("My card 4111111111111111 expired")


def test_redacts_card_with_spaces():
    red = redact_pii("My card 4111 1111 1111 1111 expired")
    assert "4111" not in red
    assert "[REDACTED]" in red


def test_redacts_upi_id():
    red = redact_pii("Pay to ram@okhdfc now")
    assert "ram@okhdfc" not in red
    assert "[REDACTED]" in red


def test_harmless_text_untouched():
    assert redact_pii("Hi, are we meeting for dinner at 8?") == (
        "Hi, are we meeting for dinner at 8?"
    )


def test_redacts_all_types_together():
    text = "OTP 482910 phone 9811045678 card 4111111111111111 upi test@okaxis"
    red = redact_pii(text)
    assert "482910" not in red
    assert "9811045678" not in red
    assert "4111111111111111" not in red
    assert "test@okaxis" not in red
    assert red.count("[REDACTED]") == 4
