"""Scam keywords looked for inside the URL. Edit backend/app/rules/data/scam_keywords.yaml instead."""

from app.rules.loader import get_scam_keywords

SCAM_KEYWORDS: set[str] = get_scam_keywords()
