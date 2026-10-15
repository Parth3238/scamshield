# Contributing to ScamShield

Small, focused changes are welcome. One feature or fix per change, with
tests for every analyzer or endpoint you touch.

## Run the tests

Backend (from `backend/`, needs Python 3.12):

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
$env:SECRET_KEY = "a-random-string-at-least-32-characters-long"
.venv\Scripts\python.exe -m pytest
```

Frontend (from `frontend/`, needs Node.js 20+):

```powershell
npm install
npm test
npm run lint
npm run build
```

## Contributing detection rules

To add or fix a scam rule you only edit YAML files, no Python needed.
Start here: [`docs/contributing-rules.md`](docs/contributing-rules.md).

Quick check before opening a change (from `backend/`):

```powershell
python scripts/validate_rules.py
```

It must print `All rule checks passed`. Also add a case to
`backend/tests/data/golden_cases.json` for your new pattern.

## Rules

1. **Never commit secrets.** No passwords, `SECRET_KEY` values, API keys,
   tokens, or private keys — in code, tests, docs, or screenshots.
   Secrets come from environment variables (see `.env.example`).
   Test data must use only fake values (`@example.com` addresses,
   `ss_live_` fakes in scrub tests, etc.).
2. Scoring stays rule-based and explainable. An LLM may only rewrite
   explanations, never decide the score.
3. Code that fetches user-supplied URLs must keep the SSRF guards:
   block private/loopback/link-local IPs, re-check after every redirect,
   use timeouts and a size limit.
4. Render user input and server data as plain text. Never use
   `dangerouslySetInnerHTML`. Never render scanned URLs as clickable links.
5. Keep `pip-audit` and `npm audit` clean; run them after changing
   dependencies.
