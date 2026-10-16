from app.services.url_analyzer import analyze_url


class FakeFetch:
    def __init__(self, chain):
        self.redirect_chain = chain
        self.final_url = chain[-1] if chain else ""
        self.status_code = 200
        self.body = ""


def codes(url, fetch=None):
    return [f.rule_code for f in analyze_url(url, fetch)]


def test_no_https():
    assert "NO_HTTPS" in codes("http://example.com")


def test_ip_address_host():
    assert "IP_ADDRESS_HOST" in codes("https://93.184.216.34/login")


def test_suspicious_tld():
    assert "SUSPICIOUS_TLD" in codes("https://example.xyz/page")


def test_at_symbol():
    assert "AT_SYMBOL_IN_URL" in codes("https://example.com@evil.com/")


def test_too_many_subdomains():
    assert "TOO_MANY_SUBDOMAINS" in codes("https://a.b.c.d.example.com/")


def test_long_url():
    assert "LONG_URL" in codes("https://example.com/" + "a" * 90)


def test_punycode():
    assert "PUNYCODE_DOMAIN" in codes("https://xn--example-abc.com/")


def test_brand_in_subdomain():
    assert "BRAND_IN_SUBDOMAIN" in codes("https://paytm.secure-login.com/")


def test_lookalike():
    assert "LOOKALIKE_DOMAIN" in codes("https://paytrn.com/")
    assert "LOOKALIKE_DOMAIN" in codes("https://g00gle.com/")
    # Exact official domain must NOT flag.
    assert "LOOKALIKE_DOMAIN" not in codes("https://www.google.com/search")


def test_scam_keywords():
    assert "SCAM_KEYWORDS_IN_URL" in codes("https://example.com/kyc-verify")


def test_redirect_chain_long():
    fetch = FakeFetch(
        [
            "https://example.com/a",
            "https://example.com/b",
            "https://example.com/c",
            "https://example.com/d",
        ]
    )
    assert "REDIRECT_CHAIN_LONG" in codes("https://example.com/a", fetch)


def test_redirect_cross_domain():
    fetch = FakeFetch(["https://example.com/start", "https://evil.com/final"])
    assert "REDIRECT_CROSS_DOMAIN" in codes("https://example.com/start", fetch)


def test_normal_url_no_findings():
    assert analyze_url("https://www.google.com/search") == []


def test_multi_finding_url():
    findings = analyze_url("https://paytm.secure-login-verify.xyz/kyc")
    got = {f.rule_code for f in findings}
    assert len(findings) >= 3
    assert "SUSPICIOUS_TLD" in got
    assert "BRAND_IN_SUBDOMAIN" in got
    assert "SCAM_KEYWORDS_IN_URL" in got
