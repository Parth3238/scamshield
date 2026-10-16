"""Unit tests for the message scam analyzer."""

from app.services.message_analyzer import analyze_message, extract_urls, normalize_text
from app.services.scoring import calculate_score
from app.services.url_analyzer import analyze_url


def _codes(text: str) -> list[str]:
    return [f.rule_code for f in analyze_message(text)]


def test_normalize_collapses_whitespace_and_lowercases():
    assert normalize_text("  Hello   WORLD\n\tnew  ") == "hello world new"


def test_harmless_message_has_no_findings():
    assert analyze_message("Hi, are we meeting for dinner at 8?") == []


def test_sbi_message_has_several_findings_and_scores_high():
    text = "Your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz"
    msg_findings = analyze_message(text)
    assert "ACCOUNT_THREAT" in _codes(text)
    assert "URGENCY_LANGUAGE" in _codes(text)
    # Merge with address-only URL analysis, like the endpoint does.
    from app.services.message_analyzer import extract_urls as eu

    urls = eu(text)
    assert urls == ["http://sbi-kyc-update.xyz"]
    url_findings = []
    for u in urls:
        url_findings.extend(analyze_url(u))
    scored = calculate_score(list(msg_findings) + list(url_findings))
    assert len(scored.findings) >= 3
    assert scored.verdict in ("suspicious", "dangerous")


def test_hinglish_scam_returns_findings():
    text = "Turant KYC update karo warna khata band ho jayega, abhi click karo"
    codes = _codes(text)
    assert "URGENCY_LANGUAGE" in codes
    assert "ACCOUNT_THREAT" in codes


def test_warning_does_not_flag_secret_but_request_does():
    assert "ASKS_FOR_SECRET" not in _codes("Do not share your OTP with anyone")
    assert "ASKS_FOR_SECRET" not in _codes("Never share your PIN with anyone")
    assert "ASKS_FOR_SECRET" not in _codes("Don't share your CVV with anyone")
    assert "ASKS_FOR_SECRET" in _codes("Please share your OTP to claim reward")
    assert "ASKS_FOR_SECRET" in _codes("Send your PIN now to verify")
    assert "ASKS_FOR_SECRET" in _codes("Apna OTP batao jaldi")


def test_urgency_rule():
    assert "URGENCY_LANGUAGE" in _codes("Urgent: act immediately, today only!")
    assert "URGENCY_LANGUAGE" in _codes("Last chance, within 24 hours")
    assert "URGENCY_LANGUAGE" in _codes("Turant action lo, abhi")


def test_account_threat_rule():
    assert "ACCOUNT_THREAT" in _codes("Your account has been suspended")
    assert "ACCOUNT_THREAT" in _codes("KYC pending, update now")
    assert "ACCOUNT_THREAT" in _codes("KYC expired last week")
    assert "ACCOUNT_THREAT" in _codes("khata band ho jayega")


def test_reward_bait_rule():
    assert "REWARD_BAIT" in _codes("You have won a lottery prize")
    assert "REWARD_BAIT" in _codes("Claim your cashback and free gift")
    assert "REWARD_BAIT" in _codes("Lucky draw inaam jeeta apne")


def test_install_app_rule():
    assert "ASKS_TO_INSTALL_APP" in _codes("Please install AnyDesk to get support")
    assert "ASKS_TO_INSTALL_APP" in _codes("Download TeamViewer quickly")
    assert "ASKS_TO_INSTALL_APP" in _codes("Install QuickSupport app now")
    assert "ASKS_TO_INSTALL_APP" in _codes("Download the update.apk file")


def test_money_back_trick_rule():
    assert "MONEY_BACK_TRICK" in _codes("I sent money by mistake please return it")
    assert "MONEY_BACK_TRICK" in _codes("Enter your UPI PIN to receive money")
    assert "MONEY_BACK_TRICK" in _codes("Approve the collect request to get refund")


def test_authority_rule():
    assert "AUTHORITY_IMPERSONATION" in _codes("CBI officer calling about digital arrest")
    assert "AUTHORITY_IMPERSONATION" in _codes("RBI bank manager customs police notice")


def test_short_link_rule():
    assert "SHORT_LINK" in _codes("Open bit.ly/abc to claim")
    assert "SHORT_LINK" in _codes("See https://tinyurl.com/xyz now")


def test_explanations_are_plain_english():
    for f in analyze_message(
        "Urgent! Your account will be blocked. You won a lottery! Share your OTP. "
        "Install AnyDesk. I sent money by mistake. CBI digital arrest. bit.ly/abc"
    ):
        assert isinstance(f.explanation, str) and len(f.explanation.split()) >= 5


def test_extract_urls_finds_http_and_bare_domains():
    urls = extract_urls("Pay at bit.ly/abc now")
    assert urls == ["bit.ly/abc"]
    urls = extract_urls("See https://example.com/x and http://test.in/y")
    assert "https://example.com/x" in urls
    assert "http://test.in/y" in urls


def test_extract_urls_max_three_and_unique():
    text = (
        "https://a.com/1 https://b.com/2 https://a.com/1 "
        "https://c.com/3 https://d.com/4 bit.ly/abc"
    )
    urls = extract_urls(text)
    assert len(urls) == 3
    assert len(set(urls)) == 3


def test_extract_urls_empty():
    assert extract_urls("") == []
    assert extract_urls("Hi, dinner at 8?") == []
