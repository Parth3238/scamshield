"""Easy-to-edit data for the UPI analyzer. Edit data/upi_handles.yaml and data/support_words.yaml instead."""

from app.rules.loader import get_known_upi_handles, get_support_words

KNOWN_UPI_HANDLES: set[str] = get_known_upi_handles()

SUPPORT_WORDS: set[str] = get_support_words()
