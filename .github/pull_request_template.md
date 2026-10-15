# Pull request

## What changed?

Short description of the rule or fix. Link any related issue.

## Checklist

- [ ] Backend tests pass (`pytest` from `backend/`).
- [ ] `validate_rules` passes (`python scripts/validate_rules.py` from `backend/`).
- [ ] Golden case added to `backend/tests/data/golden_cases.json` for the new or fixed pattern.
- [ ] No secrets committed (no passwords, API keys, tokens, `SECRET_KEY` values).
- [ ] No personal data (no real names, phone numbers, private UPI IDs, or addresses).
- [ ] For brand changes: official domains were verified on the brand's own website.
- [ ] No clickable scam links in the description (defang like hxxps://example[.]com).
