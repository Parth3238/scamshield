# ScamShield

**Paste a suspicious link, message, UPI ID or QR image. Get the warning signs back in plain words.**

ScamShield is for ordinary people — not security experts — who get a scary "account blocked" text, a too-good prize offer, or a QR code from a stranger and want a second opinion before paying or sharing an OTP. It checks the input against a set of fixed, explainable rules and returns a risk score (0–100), a verdict (safe / suspicious / dangerous), and a list of findings in simple language.

No AI decides the score. Every point comes from a named rule you can read in `backend/app/services/` and `backend/app/rules/`.

## Disclaimer

ScamShield gives **risk signals, not guarantees**. A "safe" verdict means
"no warning signs found" — it can never prove that a link, message, UPI ID,
or QR code is safe. Do not use it as your only protection before paying
money or sharing OTPs/PINs, and do not present its output as a security
certification of anything.

## Features

- **Link / message / UPI / QR checks** (`POST /api/scan`, `POST /api/scan/qr`) with SSRF-safe fetching (private IPs blocked, redirects re-validated, DNS-rebinding pinning, 1 MB / 5 s limits).
- **Community reports** (`POST /api/reports`) with duplicate detection, official-domain protection, and rate limits.
- **Trending campaigns & search** (`GET /api/campaigns/trending`, `/api/campaigns/search`) built only from admin-approved reports; UPI IDs masked in public output.
- **Admin moderation queue** (`GET /api/admin/reports`, approve/reject) — approving a report feeds the `KNOWN_BAD_INDICATOR` rule.
- **Developer API keys** (`POST/GET/DELETE /api/keys`, per-key usage) with per-minute/daily sliding-window limits and `X-API-Key` auth on scan/report endpoints.
- **Domain-age check** via RDAP (`rdap.org`), cached 7 days (failures 1 hour), max 2 lookups per scan.
- **Accounts with secure auth**: argon2 passwords, JWT in an httpOnly SameSite=Lax cookie, generic login errors, login rate limiting.
- **Hardened HTTP layer**: security headers, allow-list CORS (default empty — the frontend proxies `/api`), 6 MB / 20 KB body limits, production docs switch-off, generic 500s with error IDs, JSON request logs with secret scrubbing.
- **Next.js frontend** (App Router): checker, history, report form, trending + search, API-keys dashboard with one-time key display, admin page, mobile-friendly and keyboard-accessible.

## Tech stack

| Layer      | Technology | Notes |
|------------|-----------|-------|
| Frontend   | Next.js 16 (App Router, TypeScript), React 19 | `/api/*` rewritten to the backend, cookie auth, no `localStorage` tokens |
| Backend    | FastAPI (Python 3.12), Uvicorn | Typed schemas, dependency-injected fakes for tests |
| Database   | **PostgreSQL 16** (via `docker-compose.yml`) | Via SQLAlchemy 2 + Alembic migrations; plain `sqlite:///./scamshield.db` still works for local dev without Docker |
| Auth crypto| argon2-cffi (passwords), PyJWT HS256 (sessions) | API keys stored as SHA-256 hashes only |
| QR / images| OpenCV (`opencv-python-headless`), Pillow, NumPy | 5 MB file cap, 25 MP pixel cap, metadata stripped |
| RDAP       | httpx to `rdap.org` | 3 s timeout, 200 KB cap, ≤2 https-only redirects |
| Tests      | pytest (backend, 279 tests), Vitest + Testing Library (frontend) | No real internet in tests |
| Scanners   | pip-audit, bandit (dev) | Both clean |

## How it works

1. The browser talks only to Next.js. `/api/*` requests are proxied to `http://127.0.0.1:8000`, so the httpOnly login cookie works without CORS.
2. `POST /api/scan` identifies the caller (login cookie, `X-API-Key`, or anonymous IP) and enforces that identity's rate limit.
3. String analyzers run first (URL / message / UPI rules — pure functions, no network).
4. For links, `safe_fetch` resolves the host once, blocks non-public IPs, connects to a validated IP (original hostname kept in `Host`/TLS SNI), follows ≤5 redirects with re-validation, streams ≤1 MB.
5. RDAP domain age (≤2 lookups, cached) can add `DOMAIN_VERY_NEW` / `DOMAIN_NEW`.
6. `calculate_score` dedups findings by rule, sums severities, adds combination bonuses, caps at 100 → verdict (≤30 safe, ≤60 suspicious, else dangerous).
7. The scan (with PII redacted) is saved; the response carries findings, notes, and rate-limit headers.

Details: `docs/architecture.md`. Rule reference: `docs/scoring.md`. Threats: `docs/threat-model.md`.

## Run it locally on Windows (PowerShell)

Prereqs: Python 3.12 (python.org, tick **Add python.exe to PATH**), Node.js 20+.

**Backend** (from the `backend/` folder):
```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
$env:SECRET_KEY = "a-random-string-at-least-32-characters-long"
.venv\Scripts\python.exe -m alembic upgrade head
.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```
Shortcuts live in `backend/scripts/`: `setup_dev.ps1`, `run_backend.ps1`, `test.ps1`, `migrate.ps1`.

**Frontend** (from the `frontend/` folder):
```powershell
npm install
npm run dev
```
Open `http://localhost:3000`. The API stays at `http://127.0.0.1:8000`.

**Tests:**
```powershell
# backend (from backend/)
.venv\Scripts\python.exe -m pytest
# frontend (from frontend/)
npm test; npm run lint; npm run build
```

**First admin — no default admin accounts exist:**
```powershell
# from backend/, SECRET_KEY must be set
.venv\Scripts\python.exe scripts/create_admin.py admin@example.com
```
You will be asked for a password (10–128 chars). Log in with it: the Admin link appears.

## Screenshots (placeholders)

- `docs/screenshots/check.png` — checker with verdict card *(to add)*
- `docs/screenshots/trending.png` — trending scams list *(to add)*
- `docs/screenshots/api-keys.png` — one-time key display *(to add)*

## Disclaimer

ScamShield gives **risk signals, not guarantees**. A "safe" verdict means
"no warning signs found" — it can never prove a link, message, UPI ID, or QR
code is safe. A "dangerous" verdict means "many warning signs found" — it is
not proof of fraud. Always verify through a trusted channel before paying,
sharing an OTP, or installing anything. Do not use this tool as the only
protection for money decisions, and do not present its output as a security
certification.

## Limitations (honest)

- **Heuristics, not proof.** A "safe" verdict means "no warning signs found", never "this is safe". Old domains are never called safe; brand-new domains only add suspicion.
- **Local dev is SQLite + single process.** Without Docker, the app uses a local SQLite file and the rate limiter is in-memory: with two server processes each counts separately. The compose stack fixes both (PostgreSQL + Redis).
- **No full Public Suffix List.** `get_registered_domain` handles common two-part suffixes (`co.in`, `co.uk`…) but is wrong for suffixes like `github.io` or `s3.amazonaws.com`.
- **Fetching has edges.** IP pinning stops DNS rebinding, but there is no outbound firewall; a compromised site could still proxy to internal hosts. QR decode needs a clear image (≤5 MB, ≤25 MP).
- **RDAP coverage varies.** Some TLDs/registries answer slowly or not at all → "could not check age" note, no finding.
- **Community data needs moderators.** Reports stay invisible until an admin approves them; trending reflects reviewer throughput.
- **Rate limits need Redis in multi-process setups.** The compose stack counts limits in Redis; without `REDIS_URL` each server process counts separately.

## Roadmap (planned, not built)

- **CI** (lint + pytest + vitest + pip-audit + bandit on every change).
- **Deployment** (HTTPS, `ENVIRONMENT=production`, `COOKIE_SECURE=true`, real `SECRET_KEY` management).
