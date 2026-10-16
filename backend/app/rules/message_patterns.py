"""Editable word lists for the message scam analyzer.

Edit backend/app/rules/data/message_patterns.yaml instead.
Lists below are thin wrappers over the loader so behavior is unchanged.
"""

from app.rules.loader import load_rules

_rules = load_rules()

# Pressure tactics: "act now or else".
URGENCY_PATTERNS: list[str] = list(_rules.urgency_patterns)

# Threats to block/close accounts or KYC problems.
ACCOUNT_THREAT_PATTERNS: list[str] = list(_rules.account_threat_patterns)

# Fake prizes and rewards.
REWARD_PATTERNS: list[str] = list(_rules.reward_patterns)

# Words for secrets scammers ask for.
SECRET_WORDS: list[str] = list(_rules.secret_words)

# Verbs showing the reader is asked to give the secret.
SECRET_REQUEST_VERBS: list[str] = list(_rules.secret_request_verbs)

# Phrases that turn a secret mention into a safe warning (do NOT flag).
NEGATION_PATTERNS: list[str] = list(_rules.negation_patterns)

# Remote-access apps and installer files.
REMOTE_APPS: list[str] = list(_rules.remote_apps)

# Fake authority names.
AUTHORITY_PATTERNS: list[str] = list(_rules.authority_patterns)

# Known link shorteners.
SHORTENER_DOMAINS: list[str] = list(_rules.shortener_domains)
