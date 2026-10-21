# Threat model

## Assets we protect

- **Users**: their money, OTPs/PINs, phone numbers, UPI IDs, browsing behavior.
- **Credentials**: argon2 password hashes, JWT session cookies, API keys (hash-only).
- **Data integrity**: scan history, community reports, campaign/indicator lists.
- **The server itself**: from being turned into an SSRF proxy or malware host.
- **Logs**: must never become a second database of secrets.

## Attackers

- Scammers abusing reports/campaigns to whitelist or blacklist domains.
- Curious or malicious API users probing other users' keys, scans, or endpoints.
- Network attackers (MITM, malicious DNS) targeting fetches and sessions.
- Anyone pasting hostile strings (SQLi, XSS, traversal, bombs) into inputs.

## Threat table

| Threat | How it could happen in THIS app | Mitigation in the code | Residual risk |
|---|---|---|---|
| SSRF (fetch internal hosts) | `POST /api/scan` with `http://169.254.169.254/` | `app/services/safe_fetch.py`: scheme/port allow-list, all resolved IPs checked, literals + tricky numeric IPv4 covered | A compromised public site could proxy to internal hosts (no egress firewall) |
| DNS rebinding | Malicious DNS answers public IP at check, private IP at connect | `safe_fetch.py`: resolve once per hop, connect to validated IP, failover only within that answer set | TTL games across *redirect hops* still re-resolve (each hop re-validated, so impact is limited) |
| Redirect abuse | 302 to `http://127.0.0.1/`, infinite loops | Manual redirects (max 5) with full re-validation per hop (`safe_fetch.py`, `routes_scan.py` fetch note) | Open-redirector chains can still waste the 5 s / 1 MB budget |
| Malicious file upload | Fake PNG, huge file, polyglot | `qr_decoder.py`: 5 MB cap, format allow-list, real decode + dimension check (25 MP), metadata stripped; middleware 6 MB cap | Novel decoder bugs in Pillow/OpenCV remain possible |
| Decompression bomb | Tiny file, giant pixels | `Image.MAX_IMAGE_PIXELS` = 25 MP before open; pixel-count check (`qr_decoder.py`) | Memory spike up to the cap is still possible |
| Report poisoning | Flooding fake "safe" reports to whitelist a domain | Pending-only visibility, 5/hour limit, 24 h duplicates, official-domain refusal, admin approval gate (`routes_reports.py`) | Reviewer throughput bounds how fast truth appears |
| Defamation via reports | Reporting `google.com` as scam | `is_official_domain()` refusal (422) in `routes_reports.py` via `rules/brands.py` | Non-brand legitimate small sites can still be reported (reviewers decide) |
| Credential stuffing | Password guessing at login | argon2 + dummy-hash timing parity, 5/15 min per email+IP limit, generic 401 (`routes_auth.py`, `security.py`) | No CAPTCHA / breach-list checks |
| API key theft | DB leak, log leak, shoulder-surfing UI | Hash-only storage, one-time display, copy button, revoke (`routes_keys.py`, `ApiKeysView.tsx`); keys never logged (`log_scrub.py`) | A live key copied at creation time is usable until revoked |
| Account enumeration | "Email taken" oracle at register/login | Same generic register message + dummy hash; same 401 either way (`routes_auth.py`) | Timing differences are narrowed, not proven zero |
| XSS (stored/reflected) | Report/scan text rendered as HTML | React default escaping, no `dangerouslySetInnerHTML`, defanged plain-text URLs (`Header.tsx`, views, `defang.ts`); backend never echoes raw input in 422s (`main.py`) | A future `dangerouslySetInnerHTML` would reopen it |
| CSRF | Cookie-authenticated POSTs from evil sites | SameSite=Lax cookie + same-origin proxy so no CORS needed; state-changing calls are JSON (`deps.py`, `next.config.ts`) | Top-level GET navigations still send the cookie (Lax default behavior) |
| Log leakage | Passwords/keys/OTPs in logs | Metadata-only JSON logs + `scrub_for_log()` safety net (`middleware.py`, `log_scrub.py`); PII redacted pre-storage (`redact.py`) | A future `logger.info(user_input)` without scrub would leak |
| Rate-limit evasion | Spoofed `X-Forwarded-For`, many processes | `client.host` only unless `TRUST_PROXY=true` (`api_throttle.py`); counters shared in Redis across replicas with `Retry-After` | Redis outage falls back to per-process counting until Redis is back |

## Out of scope and known limits

- **Rate limits fall back to per-process counting** when Redis is unreachable (`FailoverLimiter` in `rate_limit.py`): an attacker who can also take down Redis gets N× the limit until Redis recovers. Redis holds no persistent data (counters only, no volume).
- **No proof of safety**: verdicts are heuristic signals; false positives (e.g. URL shorteners, new legit sites) and false negatives both exist.
- **No WAF / outbound firewall / IDS** in front of the app.
- **Heuristic suffix handling** (`get_registered_domain`): wrong on exotic public suffixes, which can misattribute brand checks.
- **No E2E encryption or private-mode guarantees** beyond redaction and no-store headers.
