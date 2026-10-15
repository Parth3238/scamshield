# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for a suspected vulnerability. Report it
privately so it can be fixed before attackers learn about it:

- Email: **https://github.com/Parth3238/scamshield/security/advisories/new**
- Include: what you found, where (file/endpoint), and steps to reproduce.

You will get a first response within 7 days. Once a fix is released, you
will be credited in the release notes if you want.

## Supported versions

Only the latest commit on the default branch is supported. There are no
long-term-support releases; update to the newest code before reporting.

## Scope

In scope:

- Authentication and session handling (`backend/app/api/routes_auth.py`,
  `backend/app/core/security.py`, `backend/app/api/deps.py`).
- SSRF protection in URL fetching (`backend/app/services/safe_fetch.py`).
- Rate limiting and API-key handling (`backend/app/core/rate_limit.py`,
  `backend/app/services/api_throttle.py`).
- Secrets handling: anything that logs, stores, or leaks passwords, keys,
  tokens, OTPs, or personal data (`backend/app/core/log_scrub.py`,
  `backend/app/services/redact.py`, Docker/compose files).
- Access-control bugs (reading another user's scans, reports, or keys).

Out of scope:

- The rule-based verdicts themselves (a missed scam is a quality issue,
  not a vulnerability — file it as a normal bug with an example).
- Third-party services (RDAP, Docker base images, hosting providers).
- Social-engineering attacks against users or moderators.

## Important note about what this tool is

ScamShield gives **risk signals, not guarantees**. A "safe" verdict means
"no warning signs found", never "this is proven safe". Do not use it as
the only protection for money decisions, and do not present its output
as a security certification of any link, message, or UPI ID.
