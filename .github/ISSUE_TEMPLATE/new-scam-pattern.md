---
name: New scam pattern
about: Suggest a new scam phrase, brand, TLD, or UPI pattern
title: "[pattern] "
labels: ["new-pattern"]
---

## What is the new scam pattern?

Write the exact phrase, link text (defanged, like hxxps://example[.]com), or UPI pattern you saw.
Do NOT include real names, phone numbers, or private UPI IDs.

```text
Paste the pattern here.
```

## Where did you see it?

SMS, WhatsApp, email, QR code, other? No personal data please.

## Which file should change?

- [ ] `backend/app/rules/data/brands.yaml`
- [ ] `backend/app/rules/data/suspicious_tlds.yaml`
- [ ] `backend/app/rules/data/scam_keywords.yaml`
- [ ] `backend/app/rules/data/upi_handles.yaml` / `support_words.yaml`
- [ ] `backend/app/rules/data/message_patterns.yaml`
- [ ] `backend/app/rules/data/combos.yaml`
- [ ] Not sure

## Did you check it?

- [ ] I ran `python scripts/validate_rules.py` from `backend/` (or explain why not).
- [ ] I verified official domains on the brand's own website (for brand changes).
- [ ] No secrets or private personal data are included.
