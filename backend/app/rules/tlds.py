"""Suspicious top-level domains. Edit backend/app/rules/data/suspicious_tlds.yaml instead."""

from app.rules.loader import get_suspicious_tlds

SUSPICIOUS_TLDS: set[str] = get_suspicious_tlds()
