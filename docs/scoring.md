# Scoring rules

Generated from the real sources (`app/services/*_analyzer.py`, `upi_qr_parser.py`, `app/rules/*`). Weights are fixed severities; `calculate_score` (`app/services/scoring.py`) dedups by rule code (keeps highest), sums, adds combination bonuses, caps at 100. Verdicts: **0–30 safe, 31–60 suspicious, 61+ dangerous.**

## URL rules (`url_analyzer.py`)

| Code | Weight | Triggers when | Possible false positive |
|---|---|---|---|
| `NO_HTTPS` | 10 | Scheme is `http` | Old but legit sites without TLS |
| `IP_ADDRESS_HOST` | 25 | Host is an IP literal | Dev/self-hosted URLs pasted by mistake |
| `SUSPICIOUS_TLD` | 15 | Ends with `.xyz .top .click .zip .work .support .loan .gq .tk .ml .cf` (`rules/tlds.py`) | Legit sites on cheap TLDs |
| `AT_SYMBOL_IN_URL` | 25 | `@` in the netloc (userinfo trick) | Rare legit userinfo URLs |
| `TOO_MANY_SUBDOMAINS` | 10 | >3 subdomain levels above the registered domain | Deep corporate/college subdomains |
| `LONG_URL` | 5 | URL longer than 100 chars | Long shopping/tracking links |
| `PUNYCODE_DOMAIN` | 20 | Host contains `xn--` | Legit internationalized domains |
| `BRAND_IN_SUBDOMAIN` | 30 | Brand token in host/path but registered domain isn't official (`rules/brands.py`, 19 brands) | Resellers, fan pages mentioning brands |
| `LOOKALIKE_DOMAIN` | 35 | Registered domain 1–2 edits (Levenshtein) from an official domain; short names skipped | Coincidental near-names |
| `SCAM_KEYWORDS_IN_URL` | 10 | Contains kyc/refund/verify/reward/lottery/prize/claim/urgent/blocked/suspended (`rules/keywords.py`) | Legit support pages ("verify", "claim") |
| `DOMAIN_VERY_NEW` | 30 | RDAP age < 30 days | Genuinely new legit sites |
| `DOMAIN_NEW` | 15 | RDAP age 30–89 days (90+ and unknown: silent) | Same as above, milder |
| `REDIRECT_CHAIN_LONG` | 10 | More than 2 redirect hops | Ad-tech/tracking chains |
| `REDIRECT_CROSS_DOMAIN` | 15 | Final host's registered domain ≠ first | URL shorteners, login SSO flows |
| `KNOWN_BAD_INDICATOR` | 50 | Registered domain approved in community reports | Reviewer error (needs admin approval first) |

Registered domain = last 2 labels (last 3 for `co.in`, `co.uk`, `com.au`, … — see `TWO_PART_SUFFIXES`, not a full PSL).

## Message rules (`message_analyzer.py`, Hinglish included)

| Code | Weight | Triggers when | Possible false positive |
|---|---|---|---|
| `URGENCY_LANGUAGE` | 10 | urgent/immediately/today only/within 24 hours/hurry/jaldi/abhi… | Genuine deadline reminders |
| `ACCOUNT_THREAT` | 20 | account blocked/KYC pending (+flexible "account … blocked" / khata variants) | Real bank alerts |
| `REWARD_BAIT` | 20 | won/lottery/prize/cashback/reward/free gift… | Real promotions |
| `ASKS_FOR_SECRET` | 35 | Request verb + OTP/PIN/CVV/password within 30 chars, no negation nearby ("never share your OTP" is safe) | Discussing OTPs with verbs but no negation |
| `ASKS_TO_INSTALL_APP` | 30 | `apk`, or install/download ± AnyDesk/TeamViewer/QuickSupport | Legit IT support |
| `MONEY_BACK_TRICK` | 30 | "sent money by mistake", UPI-PIN-to-receive, approve-collect-request | Talking about a real mistaken transfer |
| `AUTHORITY_IMPERSONATION` | 25 | police/CBI/customs/RBI/digital arrest/bank manager/income tax | Real notices, news text |
| `SHORT_LINK` | 10 | bit.ly/tinyurl/t.co/goo.gl/is.gd/ow.ly/buff.ly/rb.gy/cutt.ly/tiny.cc | Everyday shortened links |

## UPI rules (`upi_analyzer.py`, handles from `rules/upi_rules.py`)

| Code | Weight | Triggers when | Possible false positive |
|---|---|---|---|
| `INVALID_UPI_FORMAT` | 15 | Not exactly `local@handle` (local 2–50, handle 2–30 letters) | Typos when pasting |
| `UNKNOWN_UPI_HANDLE` | 15 | Handle not in the 26 known handles | New/small-bank handles |
| `LOOKALIKE_UPI_HANDLE` | 30 | Handle 1 edit from a known handle (`oksb1` vs `oksbi`); known handles exempt | Coincidence |
| `BRAND_IN_UPI_NAME` | 30 | Brand word in local part, handle not official | Real brand merchants on other handles |
| `SUPPORT_WORD_IN_UPI` | 25 | support/helpdesk/refund/kyc/claim/… in local part | Genuine support IDs |
| `RANDOM_LOOKING_UPI` | 10 | ≥3 digits mixed with letters (plain 10-digit mobiles exempt) | Business names with numbers |
| `KNOWN_BAD_INDICATOR` | 50 | UPI ID approved in community reports | Reviewer error |

## QR rules (`upi_qr_parser.py`, plus full `analyze_upi` on the payee ID)

| Code | Weight | Triggers when | Possible false positive |
|---|---|---|---|
| `QR_PAYEE_NAME_MISMATCH` | 20 | Payee name claims a brand the handle doesn't match | Nickname ≠ account name |
| `QR_PREFILLED_AMOUNT` | 10 | `am` parameter present | Legit fixed-price QRs |
| `QR_NOTE_SCAM_WORDS` | 15 | Note contains refund/reward/cashback/claim | Legit refund QRs |

Every QR result also carries the pay-to-receive warning note (`QR_PAY_NOTE`).

## Combination bonuses (`rules/combos.py`)

| Code | Bonus | Fires when |
|---|---|---|
| `COMBO_BRAND_AND_SUSPICIOUS_TLD` | 15 | (BRAND_IN_SUBDOMAIN or LOOKALIKE_DOMAIN) + SUSPICIOUS_TLD |
| `COMBO_BRAND_AND_SCAM_KEYWORDS` | 10 | (BRAND_IN_SUBDOMAIN or LOOKALIKE_DOMAIN) + SCAM_KEYWORDS_IN_URL |
| `COMBO_THREAT_AND_URGENCY` | 10 | ACCOUNT_THREAT + URGENCY_LANGUAGE |
| `COMBO_SECRET_WITH_OTHER_SIGNS` | 10 | ASKS_FOR_SECRET + any other finding |
| `COMBO_REWARD_WITH_LINK` | 10 | REWARD_BAIT + SHORT_LINK (or any URL finding) |
| `COMBO_UPI_BRAND_WITH_BAD_HANDLE` | 15 | (SUPPORT_WORD_IN_UPI or BRAND_IN_UPI_NAME) + (LOOKALIKE or UNKNOWN handle) |
