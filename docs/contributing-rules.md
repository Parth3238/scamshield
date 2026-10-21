# Contributing detection rules

This guide is for anyone who wants to add or fix a scam rule. You do **not**
need to know Python. All editable rules live in `backend/app/rules/data/`.
You only edit YAML files, then run one check script.

No new detection features are needed for this change. Only edit the data files.

## Which file for which rule

| What you want to add | File to edit |
|---|---|
| A brand and its official websites (banks, wallets, shops) | `backend/app/rules/data/brands.yaml` |
| A risky website ending like `.xyz` | `backend/app/rules/data/suspicious_tlds.yaml` |
| A scary word looked for inside links, like `kyc` | `backend/app/rules/data/scam_keywords.yaml` |
| A UPI handle (the part after `@`), like `okaxis` | `backend/app/rules/data/upi_handles.yaml` |
| A support word in UPI names, like `support` | `backend/app/rules/data/support_words.yaml` |
| Words in messages (English and Hinglish), grouped by rule code | `backend/app/rules/data/message_patterns.yaml` |
| Extra risk when two signs appear together | `backend/app/rules/data/combos.yaml` |

Message groups and their rule codes:

- `URGENCY_LANGUAGE`: pressure words ("urgent", "turant").
- `ACCOUNT_THREAT`: blocked-account or KYC threats ("account blocked", "khata band").
- `REWARD_BAIT`: fake prizes ("lottery", "inaam jeeta").
- `ASKS_FOR_SECRET`: `secret_words` (otp, pin), `request_verbs` (share, batao),
  `negations` (do not, kabhi mat). Warnings like "never share your OTP" stay safe.
- `ASKS_TO_INSTALL_APP`: `remote_apps` (anydesk, teamviewer).
- `AUTHORITY_IMPERSONATION`: fake authority names (police, cbi, digital arrest).
- `SHORT_LINK`: `domains` of shorteners (bit.ly, tinyurl.com).

## Example 1: add a new bank

Say a new bank called "Example Bank" has the official site `examplebank.com`.

1. Open `backend/app/rules/data/brands.yaml`.
2. Add, keeping alphabetical order and lowercase:
   ```yaml
   examplebank:
     official_domains:
       - examplebank.com
   ```
3. **Only add official domains you verified from the brand's own website.**
   Open the bank's own site in your browser and copy the domain from there.
   Do not copy from search results, ads, messages, or other websites. A wrong
   domain here can mark the real bank as a scam, or miss a real scam.
4. Run the check:
   ```powershell
   # from backend/
   python scripts/validate_rules.py
   ```
   It must print `All rule checks passed`.

## Example 2: add a new Hinglish scam phrase

Say scammers write "account turant band hoga".

1. Open `backend/app/rules/data/message_patterns.yaml`.
2. Find `ACCOUNT_THREAT`, then `hinglish`, and add one line:
   ```yaml
   ACCOUNT_THREAT:
     english:
       # ... unchanged ...
     hinglish:
       - khata band
       - khata blocked
       - block ho jayega
       - account turant band hoga
   ```
3. Keep it a plain word or phrase. Do not use regex symbols like `(a+)+`,
   `.*`, or `[0-9]`. The loader rejects patterns that are too long, have
   nested quantifiers, or are too slow (see ReDoS note below).
4. Never name a real person or a private individual here (see why below).
5. Run `python scripts/validate_rules.py`. It must pass.

## Example 3: add a new suspicious TLD

Say scammers start using `.buzz`.

1. Open `backend/app/rules/data/suspicious_tlds.yaml`.
2. Add one line with the leading dot, lowercase:
   ```yaml
   suspicious_tlds:
     - .xyz
     # ... other lines ...
     - .buzz
   ```
3. Run `python scripts/validate_rules.py`. It must pass.

## How to add a test case to golden_cases.json

Golden cases lock in the verdict (safe / suspicious / dangerous).

1. Open `backend/tests/data/golden_cases.json`.
2. Copy one entry and give it a new `id`:
   ```json
   {
     "id": "susp-msg-06",
     "type": "message",
     "input": "Your account turant band hoga. Update KYC immediately: http://example-kyc.xyz",
     "expected": "suspicious"
   }
   ```
   `type` is one of `url`, `message`, `upi`. `expected` is the verdict you
   want: `safe`, `suspicious`, or `dangerous`.
3. Run the backend tests:
   ```powershell
   # from backend/, SECRET_KEY must be set
   $env:SECRET_KEY = "a-random-string-at-least-32-characters-long"
   .venv\Scripts\python.exe -m pytest tests/test_golden_cases.py tests/test_rules_data.py -q
   ```
   All tests must pass unchanged except your new case, which must also pass.

## ReDoS in one paragraph

ReDoS means one bad pattern can freeze the server. A pattern like `(a+)+`
tries an exponential number of ways to match a long input and never
finishes. That is why every contributed phrase is length-checked, rejected
if it has nested quantifiers, and timed against a long test string at
startup. If your phrase is rejected as too slow, use a shorter plain phrase.

## Why we never accept rules that name a real person

We never accept a rule that names a real person or a private individual
(name, phone number, UPI ID, address). Such rules can harm an innocent
person, leak private data, and go out of date quickly. Scam detection must
target reusable patterns (fake urgency, fake rewards, lookalike domains),
never a specific human. If you saw a scam from a person, report the message
pattern, not the person.
