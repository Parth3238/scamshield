# Interview notes

## SSRF
The scan endpoint fetches a URL the user typed. Without checks, an attacker types `http://169.254.169.254/` (cloud metadata) or `http://127.0.0.1:admin-port/` and our server — which sits inside the private network — happily returns secrets. We allow-list scheme/port, check every resolved IP, pin the connection to a validated IP, and cap time/size/redirects.

**What to say in an interview:** "Any endpoint that fetches user-supplied URLs is an SSRF risk. I validate scheme and port, resolve and check every IP including tricky numeric forms, and stream with strict timeout and size caps so the server can't be turned into an internal-network proxy."

## DNS rebinding
Validation and connection are two separate DNS lookups moments apart. Evil DNS answers "93.184.216.34" to the check and "127.0.0.1" to the real connection — a time-of-check/time-of-use race. We resolve exactly once per hop and connect to an already-checked IP, so the second answer is never requested.

**What to say in an interview:** "DNS rebinding exploits the gap between checking a hostname and connecting to it. I close it by resolving once, validating every returned IP, and opening the socket to a pinned IP from that same answer set."

## Redirect validation
Each redirect is a brand-new attacker-controlled URL, so following them blindly re-opens every SSRF hole. We follow manually (max 5), re-run the full validator on every hop, and flag long or cross-domain chains as findings.

**What to say in an interview:** "Redirects are untrusted input, so I follow them manually with a hop cap and re-validate scheme, port, and IPs on every hop — plus score suspicious redirect behavior itself."

## Cloud metadata endpoint
`169.254.169.254` answers only inside a cloud network and hands out credentials. It looks like a boring IP, so naive block-lists miss it. Ours is covered because *all* private/link-local/reserved ranges are blocked, not just `localhost`.

**What to say in an interview:** "The metadata IP is dangerous because it's reachable only from inside the cloud. I block the whole private/link-local/reserved space rather than a few famous addresses."

## Levenshtein lookalike detection
`paytmn.com` vs `paytm.com` differs by one letter — invisible at a glance. We compute edit distance against official brand domains and flag distance 1–2 (weight 35), skipping very short names to avoid noise.

**What to say in an interview:** "I detect typosquatting with Levenshtein distance 1–2 against a brand allow-list, exempting short names that would false-positive, instead of maintaining endless block-lists."

## Allowlist matching on registered domains
Matching `paytm` anywhere in the URL flags `paytm.com` itself. We reduce the host to its registered domain first, then compare against the official list — so the real site passes and only impersonators fire.

**What to say in an interview:** "Brand checks run on the registered domain, not the raw string, so official domains are exempt and only lookalikes or subdomain abuse score points."

## argon2 vs sha256
Passwords are human-guessable, so they need a *slow*, salted hash (argon2) that makes billion-guess attacks expensive. API keys are 256-bit random, so a fast SHA-256 is enough — guessing is infeasible — and its speed lets us hash-and-compare on every request.

**What to say in an interview:** "Passwords get argon2 because they're low-entropy and need slowness plus salt; API keys are high-entropy random tokens, so SHA-256 is the right tool — with only the hash stored."

## JWT in httpOnly cookie
Storing tokens in `localStorage` lets any injected script steal them. We keep the JWT in an httpOnly cookie (invisible to JavaScript) with SameSite=Lax, and the frontend proxies `/api` same-origin so CORS is never needed.

**What to say in an interview:** "httpOnly cookies keep tokens out of JavaScript's reach, SameSite=Lax blocks most cross-site sending, and a same-origin proxy removes the need for CORS entirely."

## CSRF and SameSite
Cookies ride along on cross-site requests by default, so evil.com could POST as you. SameSite=Lax stops cross-site POSTs from carrying the cookie, and our state-changing calls are JSON (not simple form posts), adding a second barrier.

**What to say in an interview:** "SameSite=Lax means the session cookie isn't sent on cross-site POSTs, which defuses classic CSRF; JSON-only state-changing endpoints add defense in depth."

## Account enumeration
"Email already registered" or different login errors tell attackers which accounts exist. We return the identical generic message for new and existing emails, and identical 401s for bad email vs bad password, with a dummy hash so timing matches too.

**What to say in an interview:** "I return byte-identical responses for existing and non-existing accounts, including a dummy password check to equalize timing, so auth endpoints aren't user oracles."

## Rate limiting
Login (5/15 min), reports (5/hour), scans (per-key 20/min + 200/day, anonymous 10/min + 100/day) use sliding windows with `Retry-After` and remaining-quota headers; only `client.host` is trusted for identity unless behind a known proxy.

**What to say in an interview:** "I use per-identity sliding-window limits with honest 429s and quota headers, keyed on data the client can't forge, with injectable clocks so the windows are fully tested."

## Error oracles
Different errors for "bad id" vs "not yours" let attackers probe private data. Private scans return the same generic 404 for missing, foreign, or malformed ids; other users' API keys 404 identically; validation errors never echo input.

**What to say in an interview:** "Every 'does it exist / is it mine' question gets one identical answer, so error messages can't be used as an oracle to enumerate private objects."

## Decompression bombs
A kilobyte file can unzip to gigapixels and OOM the server. We cap Pillow before opening (25 MP), verify real dimensions after decode, cap uploads at 5 MB, and strip metadata during re-encode.

**What to say in an interview:** "I set Pillow's pixel cap before opening anything, enforce file and dimension limits on the decoded content — not the filename — and strip metadata."

## Data minimization and redaction
We store the *minimum* needed: messages are redacted (UPI/phone/card/OTP → `[REDACTED]`) before saving, UPI scans store only masked IDs, reports hide reporter identity from admins, and public campaign output masks UPI samples.

**What to say in an interview:** "Sensitive values are redacted or masked before storage, reporter identity never leaves the server, and public outputs show only masked samples — a breach then leaks shapes, not secrets."

## Report poisoning
Attackers could mass-report rivals as scams (or their own domains as safe). Reports stay invisible until approved, official domains can't be reported at all, duplicates and hourly caps slow floods, and only approvals feed the block-list.

**What to say in an interview:** "Community input is untrusted: it's quarantined as pending, rate-limited and deduped, official domains are exempt, and only human approval promotes it into detection data."

## Database migrations
`create_all` can't evolve a live database or roll back. Every schema change is a numbered Alembic migration (upgrade + downgrade), startup refuses to run on an unmigrated DB, and a sync test fails if models drift from migrations.

**What to say in an interview:** "I manage schema with versioned Alembic migrations instead of create_all, gate startup on a migrated database, and test that models and migrations can never drift apart silently."
