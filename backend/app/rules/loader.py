"""Load editable detection-rule data from YAML files once at startup.

All rule text lives in backend/app/rules/data/*.yaml so outsiders can
contribute without touching Python. This loader reads every file once,
validates it with strict Pydantic models (unknown fields are rejected),
and compiles every contributed phrase into a regex. If any file is
invalid the app refuses to start with an error that names the file,
the line number and the problem.

ReDoS protection (why a contributed regex can be dangerous):
--------------------------------------------------------------
ReDoS (Regular-expression Denial of Service) means one small pattern can
take seconds, minutes or forever on a matching input. A classic example
is nested quantifiers such as (a+)+ : on the input "aaaaaaaaaaaaaaaa!"
the engine tries an exponential number of ways to split the a's before
failing. An attacker (or an innocent contributor) who adds such a pattern
would freeze every scan thread that evaluates it.

We defend in three layers, all applied at load time so a bad pattern
stops the app from starting instead of hanging it later:

1. Maximum pattern length (MAX_PATTERN_LENGTH). Very long patterns are
   almost always a mistake and bound how complex any pattern can be.
2. Static nested-quantifier rejection. We scan the raw text for the most
   common evil shape: a group that already contains + or * and is itself
   followed by + or *, e.g. (a+)+, (a*)*, (a+b*)+. This is cheap and
   catches the textbook cases without running anything.
3. Dynamic timing test. We compile the final word-boundary regex and run
   it against long pathological strings (thousands of "a"s, spaces, etc.)
   inside a worker thread with a hard timeout (REGEX_TIMEOUT_SECONDS).
   Safe literal phrases finish in microseconds; a backtracking pattern
   either times out or takes far too long, and we reject it. Python's `re`
   has no built-in timeout, so the thread + timeout is our safety net.

Only yaml.safe_load is used here (never yaml.load), so rule files cannot
execute arbitrary Python objects.
"""

from __future__ import annotations

import concurrent.futures
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

DATA_DIR = Path(__file__).parent / "data"

# Longest legitimate phrase today is ~30 chars ("congratulations you have won").
# 200 leaves generous room for new phrases while bounding regex complexity.
MAX_PATTERN_LENGTH = 200
# Safe literal phrases match a 2000-char string in a few milliseconds, even on
# a busy machine. The timeout (1s) is the hard hang guard; the slow limit
# (0.5s) still has ~100x margin over safe patterns but catches evil
# backtracking patterns, which take seconds on even short inputs.
REGEX_TIMEOUT_SECONDS = 1.0
REGEX_SLOW_SECONDS = 0.5

# Detects nested quantifiers such as (a+)+, (a*)*, (a+)*, (ab+cd*)+.
# Looks for an opening paren, then (without crossing the closing paren)
# a + or * character, then the closing paren followed by + or *.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*]")
# Detects stacked quantifiers such as a++, a**, a+*, a*+ outside groups.
_STACKED_QUANTIFIER_RE = re.compile(r"(?:\+\+|\*\*|\+\*|\*\+)")


def _find_line(path: Path, needle: str) -> int | str:
    """Return the 1-based line number where needle first appears, else '?'."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return "?"
    if not needle:
        return "?"
    needle_l = needle.lower()
    for i, line in enumerate(text.splitlines(), start=1):
        if needle_l in line.lower():
            return i
    return "?"


def _fail(filename: str, line: int | str, problem: str) -> RuntimeError:
    return RuntimeError(f"Invalid rule file {filename} line {line}: {problem}")


def _load_yaml_file(path: Path, model: type[BaseModel]) -> BaseModel:
    filename = path.name
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise _fail(filename, "?", "file is missing") from None
    except OSError as exc:
        raise _fail(filename, "?", f"cannot be read: {exc}") from None
    try:
        # NOTE: yaml.safe_load only. Never use yaml.load here:
        # yaml.load can construct arbitrary Python objects from tags.
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        line: int | str = "?"
        problem = str(exc).splitlines()[0] if str(exc) else "invalid YAML"
        try:
            mark = getattr(exc, "problem_mark", None)
            if mark is not None and getattr(mark, "line", None) is not None:
                line = int(mark.line) + 1
            problem_node = getattr(exc, "problem", None)
            if problem_node:
                problem = str(problem_node)
        except Exception:
            pass
        raise _fail(filename, line, problem) from None
    if data is None:
        raise _fail(filename, 1, "file is empty")
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        # Report the first error with file, line and problem.
        first = exc.errors()[0] if exc.errors() else None
        if first is None:
            raise _fail(filename, "?", str(exc)) from None
        loc = ".".join(str(p) for p in first.get("loc", ()))
        msg = first.get("msg", "invalid value")
        ctx = first.get("ctx", {})
        # Try to locate the offending key or value in the file for a line no.
        # Try the most specific location part first (e.g. "evil_field" before
        # "brands"), then the raw input value, so unknown fields resolve to
        # their own line instead of line 1.
        candidates: list[str] = []
        if loc:
            for part in reversed(str(loc).split(".")):
                if part:
                    candidates.append(part[:80])
        try:
            inp = first.get("input", "")
            if inp not in (None, ""):
                candidates.append(str(inp)[:80])
        except Exception:
            pass
        line_no: int | str = "?"
        for needle in candidates:
            if not needle:
                continue
            found = _find_line(path, needle)
            if found != "?":
                line_no = found
                break
        if loc:
            problem = f"'{loc}': {msg}"
        else:
            problem = str(msg)
        if ctx and "expected" in ctx:
            problem += f" (expected {ctx['expected']})"
        raise _fail(filename, line_no, problem) from None


# ---------------------------------------------------------------------------
# Pydantic schemas (extra="forbid" so unknown fields are rejected).
# ---------------------------------------------------------------------------


class BrandEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    official_domains: list[str]


class BrandsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    brands: dict[str, BrandEntry]


class TldsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suspicious_tlds: list[str]


class KeywordsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scam_keywords: list[str]


class UpiHandlesFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    known_upi_handles: list[str]


class SupportWordsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    support_words: list[str]


class LangGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    english: list[str] = Field(default_factory=list)
    hinglish: list[str] = Field(default_factory=list)


class SecretSubGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret_words: LangGroup
    request_verbs: LangGroup
    negations: LangGroup


class InstallAppGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    remote_apps: list[str]


class ShortLinkGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domains: list[str]


class MessagePatternsInner(BaseModel):
    model_config = ConfigDict(extra="forbid")
    URGENCY_LANGUAGE: LangGroup
    ACCOUNT_THREAT: LangGroup
    REWARD_BAIT: LangGroup
    ASKS_FOR_SECRET: SecretSubGroup
    ASKS_TO_INSTALL_APP: InstallAppGroup
    AUTHORITY_IMPERSONATION: LangGroup
    SHORT_LINK: ShortLinkGroup


class MessagePatternsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    patterns: MessagePatternsInner


class ComboEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_code: str
    bonus: int = Field(ge=1, le=50)
    group_a: list[str]
    group_b: list[str] = Field(default_factory=list)
    any_other: bool = False
    any_url: bool = False
    explanation: str


class CombosFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url_finding_codes: list[str]
    combos: list[ComboEntry]


# ---------------------------------------------------------------------------
# ReDoS checks.
# ---------------------------------------------------------------------------


def _check_pattern_text(filename: str, path: Path, raw: str) -> None:
    if not isinstance(raw, str) or not raw.strip():
        raise _fail(filename, _find_line(path, raw), "pattern must be a non-empty string")
    if len(raw) > MAX_PATTERN_LENGTH:
        raise _fail(
            filename,
            _find_line(path, raw),
            f"pattern too long ({len(raw)} chars, max {MAX_PATTERN_LENGTH})",
        )
    if _NESTED_QUANTIFIER_RE.search(raw) or _STACKED_QUANTIFIER_RE.search(raw):
        raise _fail(
            filename,
            _find_line(path, raw),
            f"pattern {raw!r} looks dangerous (nested quantifiers like (a+)+ can hang the server)",
        )


_TEST_STRINGS: list[str] = [
    "a" * 2000,
    "a" * 2000 + "!",
    "ab " * 1000,
]


def _search_with_timeout(compiled: re.Pattern, text: str, timeout: float) -> float:
    """Run compiled.search(text) with a hard timeout. Returns elapsed secs."""
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(compiled.search, text)
        try:
            future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(f"pattern {compiled.pattern!r} timed out") from None
    return time.perf_counter() - start


def _check_regex_safe(filename: str, path: Path, raw: str, compiled: re.Pattern) -> None:
    for test in _TEST_STRINGS:
        try:
            elapsed = _search_with_timeout(compiled, test, REGEX_TIMEOUT_SECONDS)
        except TimeoutError:
            raise _fail(
                filename,
                _find_line(path, raw),
                f"pattern {raw!r} is too slow (timed out after "
                f"{REGEX_TIMEOUT_SECONDS}s: possible catastrophic backtracking)",
            ) from None
        if elapsed > REGEX_SLOW_SECONDS:
            raise _fail(
                filename,
                _find_line(path, raw),
                f"pattern {raw!r} is too slow ({elapsed:.2f}s on a test string: "
                "possible catastrophic backtracking)",
            ) from None


def compile_phrase_regex(raw: str) -> re.Pattern:
    """Build the word-boundary regex used by the message analyzer."""
    return re.compile(r"\b" + re.escape(raw.lower()) + r"\b")


def validate_phrase(filename: str, path: Path, raw: str) -> re.Pattern:
    """Length + nested-quantifier + compile + timing checks. Returns compiled."""
    _check_pattern_text(filename, path, raw)
    try:
        compiled = compile_phrase_regex(raw)
    except re.error as exc:
        raise _fail(filename, _find_line(path, raw), f"pattern {raw!r} does not compile: {exc}") from None
    _check_regex_safe(filename, path, raw, compiled)
    return compiled


# ---------------------------------------------------------------------------
# Loaded container.
# ---------------------------------------------------------------------------


@dataclass
class LoadedRules:
    brand_domains: dict[str, list[str]] = field(default_factory=dict)
    suspicious_tlds: set[str] = field(default_factory=set)
    scam_keywords: set[str] = field(default_factory=set)
    known_upi_handles: set[str] = field(default_factory=set)
    support_words: set[str] = field(default_factory=set)
    urgency_patterns: list[str] = field(default_factory=list)
    account_threat_patterns: list[str] = field(default_factory=list)
    reward_patterns: list[str] = field(default_factory=list)
    secret_words: list[str] = field(default_factory=list)
    secret_request_verbs: list[str] = field(default_factory=list)
    negation_patterns: list[str] = field(default_factory=list)
    remote_apps: list[str] = field(default_factory=list)
    authority_patterns: list[str] = field(default_factory=list)
    shortener_domains: list[str] = field(default_factory=list)
    url_finding_codes: frozenset[str] = frozenset()
    combos: list[dict] = field(default_factory=list)
    # Compiled word-boundary regexes for every message phrase, built once.
    compiled_phrases: dict[str, re.Pattern] = field(default_factory=dict)


_CACHE: LoadedRules | None = None


def _validate_domain_value(filename: str, path: Path, domain: str) -> None:
    if not isinstance(domain, str) or not domain.strip():
        raise _fail(filename, 1, "domain must be a non-empty string")
    if domain != domain.lower():
        raise _fail(filename, _find_line(path, domain), f"domain {domain!r} must be lowercase")
    if "://" in domain or "/" in domain or " " in domain:
        raise _fail(
            filename,
            _find_line(path, domain),
            f"domain {domain!r} must not contain a scheme, path or spaces",
        )


def load_rules() -> LoadedRules:
    """Load and validate every YAML file once. Raises RuntimeError on error."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE

    brands_path = DATA_DIR / "brands.yaml"
    tlds_path = DATA_DIR / "suspicious_tlds.yaml"
    keywords_path = DATA_DIR / "scam_keywords.yaml"
    handles_path = DATA_DIR / "upi_handles.yaml"
    support_path = DATA_DIR / "support_words.yaml"
    messages_path = DATA_DIR / "message_patterns.yaml"
    combos_path = DATA_DIR / "combos.yaml"

    brands_data = _load_yaml_file(brands_path, BrandsFile)
    tlds_data = _load_yaml_file(tlds_path, TldsFile)
    keywords_data = _load_yaml_file(keywords_path, KeywordsFile)
    handles_data = _load_yaml_file(handles_path, UpiHandlesFile)
    support_data = _load_yaml_file(support_path, SupportWordsFile)
    messages_data = _load_yaml_file(messages_path, MessagePatternsFile)
    combos_data = _load_yaml_file(combos_path, CombosFile)

    out = LoadedRules()

    # Brands: every brand needs at least one official domain; domains must be
    # lowercase with no scheme or path.
    assert isinstance(brands_data, BrandsFile)
    for brand, entry in brands_data.brands.items():
        if not entry.official_domains:
            raise _fail(brands_path.name, _find_line(brands_path, brand), f"brand {brand!r} has no official domain")
        for d in entry.official_domains:
            _validate_domain_value(brands_path.name, brands_path, d)
        out.brand_domains[brand] = list(entry.official_domains)

    # TLDs: must start with a leading dot.
    assert isinstance(tlds_data, TldsFile)
    for tld in tlds_data.suspicious_tlds:
        if not isinstance(tld, str) or not tld.startswith("."):
            raise _fail(tlds_path.name, _find_line(tlds_path, str(tld)), f"TLD {tld!r} must start with a leading dot")
        if tld != tld.lower():
            raise _fail(tlds_path.name, _find_line(tlds_path, tld), f"TLD {tld!r} must be lowercase")
    if len(set(tlds_data.suspicious_tlds)) != len(tlds_data.suspicious_tlds):
        raise _fail(tlds_path.name, 1, "duplicate TLD entries found")
    out.suspicious_tlds = set(tlds_data.suspicious_tlds)

    # Keywords: no duplicates (case-insensitive).
    assert isinstance(keywords_data, KeywordsFile)
    lowered = [k.lower() for k in keywords_data.scam_keywords]
    if len(set(lowered)) != len(lowered):
        raise _fail(keywords_path.name, 1, "duplicate keyword entries found")
    for kw in keywords_data.scam_keywords:
        if not isinstance(kw, str) or not kw.strip():
            raise _fail(keywords_path.name, 1, "keyword must be a non-empty string")
        if len(kw) > MAX_PATTERN_LENGTH:
            raise _fail(keywords_path.name, _find_line(keywords_path, kw), f"keyword {kw!r} too long")
    out.scam_keywords = set(keywords_data.scam_keywords)

    # UPI handles + support words: lowercase, no duplicates.
    assert isinstance(handles_data, UpiHandlesFile)
    for h in handles_data.known_upi_handles:
        if not isinstance(h, str) or not h.strip():
            raise _fail(handles_path.name, 1, "UPI handle must be a non-empty string")
        if h != h.lower():
            raise _fail(handles_path.name, _find_line(handles_path, h), f"UPI handle {h!r} must be lowercase")
    if len(set(h.lower() for h in handles_data.known_upi_handles)) != len(handles_data.known_upi_handles):
        raise _fail(handles_path.name, 1, "duplicate UPI handle entries found")
    out.known_upi_handles = set(h.lower() for h in handles_data.known_upi_handles)

    assert isinstance(support_data, SupportWordsFile)
    for w in support_data.support_words:
        if not isinstance(w, str) or not w.strip():
            raise _fail(support_path.name, 1, "support word must be a non-empty string")
    if len(set(w.lower() for w in support_data.support_words)) != len(support_data.support_words):
        raise _fail(support_path.name, 1, "duplicate support-word entries found")
    out.support_words = set(w.lower() for w in support_data.support_words)

    # Message patterns: rebuild the original flat lists as english + hinglish
    # (english first, to preserve the original order), compiling each phrase.
    assert isinstance(messages_data, MessagePatternsFile)
    pats = messages_data.patterns
    out.urgency_patterns = list(pats.URGENCY_LANGUAGE.english) + list(pats.URGENCY_LANGUAGE.hinglish)
    out.account_threat_patterns = list(pats.ACCOUNT_THREAT.english) + list(pats.ACCOUNT_THREAT.hinglish)
    out.reward_patterns = list(pats.REWARD_BAIT.english) + list(pats.REWARD_BAIT.hinglish)
    out.secret_words = list(pats.ASKS_FOR_SECRET.secret_words.english) + list(
        pats.ASKS_FOR_SECRET.secret_words.hinglish
    )
    out.secret_request_verbs = list(pats.ASKS_FOR_SECRET.request_verbs.english) + list(
        pats.ASKS_FOR_SECRET.request_verbs.hinglish
    )
    out.negation_patterns = list(pats.ASKS_FOR_SECRET.negations.english) + list(
        pats.ASKS_FOR_SECRET.negations.hinglish
    )
    out.remote_apps = list(pats.ASKS_TO_INSTALL_APP.remote_apps)
    out.authority_patterns = list(pats.AUTHORITY_IMPERSONATION.english) + list(
        pats.AUTHORITY_IMPERSONATION.hinglish
    )
    out.shortener_domains = list(pats.SHORT_LINK.domains)

    for raw in (
        out.urgency_patterns
        + out.account_threat_patterns
        + out.reward_patterns
        + out.secret_words
        + out.secret_request_verbs
        + out.negation_patterns
        + out.remote_apps
        + out.authority_patterns
        + out.shortener_domains
    ):
        compiled = validate_phrase(messages_path.name, messages_path, raw)
        out.compiled_phrases[raw.lower()] = compiled

    # Shortener domains must be lowercase domains with no scheme/path.
    for d in out.shortener_domains:
        _validate_domain_value(messages_path.name, messages_path, d)

    # Combos.
    assert isinstance(combos_data, CombosFile)
    if not combos_data.url_finding_codes:
        raise _fail(combos_path.name, 1, "url_finding_codes must not be empty")
    out.url_finding_codes = frozenset(combos_data.url_finding_codes)
    for entry in combos_data.combos:
        if not entry.rule_code.startswith("COMBO_"):
            raise _fail(
                combos_path.name,
                _find_line(combos_path, entry.rule_code),
                f"combo rule_code {entry.rule_code!r} must start with COMBO_",
            )
        if not entry.group_a:
            raise _fail(
                combos_path.name,
                _find_line(combos_path, entry.rule_code),
                f"combo {entry.rule_code!r} needs a non-empty group_a",
            )
        if not entry.explanation or len(entry.explanation.split()) < 5:
            raise _fail(
                combos_path.name,
                _find_line(combos_path, entry.rule_code),
                f"combo {entry.rule_code!r} needs a plain-English explanation",
            )
        out.combos.append(
            {
                "rule_code": entry.rule_code,
                "bonus": entry.bonus,
                "group_a": tuple(entry.group_a),
                "group_b": tuple(entry.group_b),
                "any_other": bool(entry.any_other),
                "any_url": bool(entry.any_url),
                "explanation": entry.explanation,
            }
        )

    _CACHE = out
    return out


def reset_cache() -> None:
    """Only for tests: forget the cached rules so files are re-read."""
    global _CACHE
    _CACHE = None


# Thin getter helpers used by the wrapper modules below.
def get_brand_domains() -> dict[str, list[str]]:
    return load_rules().brand_domains


def get_suspicious_tlds() -> set[str]:
    return load_rules().suspicious_tlds


def get_scam_keywords() -> set[str]:
    return load_rules().scam_keywords


def get_known_upi_handles() -> set[str]:
    return load_rules().known_upi_handles


def get_support_words() -> set[str]:
    return load_rules().support_words
