# ScamShield Web

Security web app that checks URLs, messages, UPI IDs and QR codes for scam signs
and explains the risk in simple language.

## Stack (for now)
- Backend: FastAPI (Python) in /backend
- Database: SQLite for now (switch to PostgreSQL later)
- Frontend: Next.js (TypeScript) in /frontend, built later
- No Docker and no Git/GitHub setup yet. Do not create Dockerfiles or run git commands.

## Rules
- Build ONE small feature at a time, then stop and wait for my next prompt.
- Scoring is rule-based and explainable. An LLM may only rewrite explanations, never decide the score.
- Any code that fetches user-supplied URLs must block private/loopback/link-local IPs,
  re-check after every redirect, and use timeouts and a size limit (SSRF protection).
- Write tests for every analyzer and run them before saying a task is done.
- Explain each file you create in 2-3 simple lines.
- Never hardcode secrets. Use environment variables.

## Scoring
Each rule returns a finding with a severity weight. Sum, cap at 100.
0-30 safe, 31-60 suspicious, 61+ dangerous.

## Frontend rules
- Next.js (App Router, TypeScript) in /frontend. Backend runs on http://127.0.0.1:8000.
- All API calls go through a Next.js rewrite from /api/* to the backend, so the httpOnly
  login cookie works without CORS and tokens are never stored in localStorage.
- NEVER use dangerouslySetInnerHTML. Always render user input and server data as plain text.
- Scanned or reported URLs are shown as plain text (defanged, like hxxps://example[.]com),
  never as clickable links.
- Simple language for normal people. Mobile-friendly. Keyboard accessible.
- No secrets in frontend code. No Docker, no Git commands.
- Docker is now allowed (Dockerfiles, docker compose, docker build/run commands).
- Git commands are still NOT allowed (GitHub comes later).
- Never put real secrets in Dockerfiles, compose files or images. Secrets come from
  environment variables at runtime.