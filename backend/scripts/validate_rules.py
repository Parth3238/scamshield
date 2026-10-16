"""Validate editable rule data files and print a friendly report.

Usage (from backend/):
    python scripts/validate_rules.py

Runs the same checks as backend/tests/test_rules_data.py plus a full
loader pass, without needing pytest or the whole app. Exit 0 when every
check passes, 1 when anything fails. Uses yaml.safe_load only.
"""

from __future__ import annotations

import concurrent.futures
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import yaml  # noqa: E402

DATA_DIR = Path(__file__).parent.parent / "app" / "rules" / "data"
MAX_PATTERN_LENGTH = 200
TIMEOUT = 1.0
SLOW = 0.5

_NESTED_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*]")
_STACKED_RE = re.compile(r"(?:\+\+|\*\*|\+\*|\*\+)")
_TEST_STRINGS = ["a" * 2000, "a" * 2000 + "!", "ab " * 1000]

CHECKS: list[tuple[str, bool, str]] = []


def _report(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}" + (f": {detail}" if detail and not ok else ""))


def _read(name: str):
    path = DATA_DIR / name
    if not path.exists():
        _report(f"{name} exists", False, "file is missing")
        return None
    try:
        with open(path, encoding="utf-8") as f:
            # NOTE: safe_load only. Never yaml.load here.
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        line = "?"
        try:
            mark = getattr(exc, "problem_mark", None)
            if mark is not None and getattr(mark, "line", None) is not None:
                line = int(mark.line) + 1
        except Exception:
            pass
        _report(f"{name} is valid YAML", False, f"line {line}: {exc}")
        return None
    if data is None:
        _report(f"{name} is valid YAML", False, "file is empty")
        return None
    _report(f"{name} is valid YAML", True)
    return data


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def main() -> int:
    print("Checking rule data files in backend/app/rules/data/ ...")
    ok_all = True

    def fail() -> None:
        nonlocal ok_all
        ok_all = False

    # 1. Loader pass (strict Pydantic + ReDoS checks). App refuses to start otherwise.
    try:
        from app.rules.loader import reset_cache

        reset_cache()
        from app.rules.loader import load_rules

        load_rules()
        _report("loader accepts all files (strict schema + ReDoS checks)", True)
    except RuntimeError as exc:
        _report("loader accepts all files (strict schema + ReDoS checks)", False, str(exc))
        fail()
        print("\nFix the error above, then re-run this script.")
        for _, ok, _ in CHECKS:
            if not ok:
                pass
        return 1

    # 2. Brands.
    brands = _read("brands.yaml")
    if brands is None:
        fail()
    else:
        if set(brands.keys()) != {"brands"}:
            _report("brands.yaml has no unknown fields", False, f"top keys: {set(brands.keys())}")
            fail()
        else:
            _report("brands.yaml has no unknown fields", True)
        bad = False
        for brand, entry in (brands.get("brands") or {}).items():
            if not isinstance(entry, dict) or not entry.get("official_domains"):
                _report("every brand has an official domain", False, f"brand {brand!r} is empty")
                fail()
                bad = True
                break
            for d in entry.get("official_domains", []):
                if not isinstance(d, str) or d != d.lower() or "://" in d or "/" in d or " " in d:
                    _report(
                        "brand domains are lowercase with no scheme/path",
                        False,
                        f"{d!r} (brand {brand!r})",
                    )
                    fail()
                    bad = True
                    break
            if bad:
                break
        else:
            _report("every brand has an official domain", True)
            _report("brand domains are lowercase with no scheme/path", True)

        # Cross-brand lookalike: one brand's domain must not be 1-2 edits
        # from another brand's domain (else the real site always flags).
        items = [
            (b, str(d).lower())
            for b, e in (brands.get("brands") or {}).items()
            for d in (e.get("official_domains") or [])
        ]
        clash = None
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                (b1, d1), (b2, d2) = items[i], items[j]
                if b1 == b2 or d1 == d2:
                    continue
                if len(d1.split(".")[0]) < 4 or len(d2.split(".")[0]) < 4:
                    continue
                dist = _levenshtein(d1, d2)
                if 1 <= dist <= 2:
                    clash = f"{d1!r} ({b1}) looks like {d2!r} ({b2})"
                    break
            if clash:
                break
        if clash:
            _report("no cross-brand lookalike domains", False, clash)
            fail()
        else:
            _report("no cross-brand lookalike domains", True)

    # 3. TLDs.
    tlds = _read("suspicious_tlds.yaml")
    if tlds is None:
        fail()
    else:
        vals = tlds.get("suspicious_tlds") or []
        bad = next((t for t in vals if not isinstance(t, str) or not t.startswith(".")), None)
        if bad is not None:
            _report("every TLD starts with a dot", False, f"{bad!r} lacks the leading dot")
            fail()
        else:
            _report("every TLD starts with a dot", True)
        lowered = [str(t).lower() for t in vals]
        if len(set(lowered)) != len(lowered):
            _report("no duplicate TLDs", False, "same TLD listed twice")
            fail()
        else:
            _report("no duplicate TLDs", True)

    # 4. Keywords / handles / support words.
    for fname, key, label in [
        ("scam_keywords.yaml", "scam_keywords", "scam keyword"),
        ("upi_handles.yaml", "known_upi_handles", "UPI handle"),
        ("support_words.yaml", "support_words", "support word"),
    ]:
        data = _read(fname)
        if data is None:
            fail()
            continue
        vals = data.get(key) or []
        lowered = [str(v).lower() for v in vals]
        if len(set(lowered)) != len(lowered):
            _report(f"no duplicate {label}s", False, "same entry listed twice")
            fail()
        else:
            _report(f"no duplicate {label}s", True)

    # 5. Message patterns: compile + timing.
    msgs = _read("message_patterns.yaml")
    if msgs is None:
        fail()
    else:
        pats = (msgs.get("patterns") or {})
        phrases: list[str] = []
        for g in ("URGENCY_LANGUAGE", "ACCOUNT_THREAT", "REWARD_BAIT", "AUTHORITY_IMPERSONATION"):
            for lang in ("english", "hinglish"):
                phrases.extend(((pats.get(g) or {}).get(lang) or []) or [])
        for sub in ("secret_words", "request_verbs", "negations"):
            for lang in ("english", "hinglish"):
                phrases.extend((((pats.get("ASKS_FOR_SECRET") or {}).get(sub) or {}).get(lang) or []) or [])
        phrases.extend(((pats.get("ASKS_TO_INSTALL_APP") or {}).get("remote_apps") or []) or [])
        phrases.extend(((pats.get("SHORT_LINK") or {}).get("domains") or []) or [])
        bad_phrase = None
        for raw in phrases:
            if not isinstance(raw, str) or not raw.strip() or len(raw) > MAX_PATTERN_LENGTH:
                bad_phrase = f"{raw!r} is empty or too long"
                break
            if _NESTED_RE.search(raw) or _STACKED_RE.search(raw):
                bad_phrase = f"{raw!r} has nested quantifiers like (a+)+"
                break
            try:
                compiled = re.compile(r"\b" + re.escape(raw.lower()) + r"\b")
            except re.error as exc:
                bad_phrase = f"{raw!r} does not compile: {exc}"
                break
            for test in _TEST_STRINGS:
                start = time.perf_counter()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    fut = pool.submit(compiled.search, test)
                    try:
                        fut.result(timeout=TIMEOUT)
                    except concurrent.futures.TimeoutError:
                        bad_phrase = f"{raw!r} timed out (possible ReDoS)"
                        break
                if time.perf_counter() - start > SLOW:
                    bad_phrase = f"{raw!r} is too slow (possible ReDoS)"
                    break
            if bad_phrase:
                break
        if bad_phrase:
            _report("every message pattern compiles and is fast", False, bad_phrase)
            fail()
        else:
            _report("every message pattern compiles and is fast", True)

    # 6. Combos unknown fields.
    combos = _read("combos.yaml")
    if combos is None:
        fail()
    else:
        if set(combos.keys()) != {"url_finding_codes", "combos"}:
            _report("combos.yaml has no unknown fields", False, f"keys: {set(combos.keys())}")
            fail()
        else:
            _report("combos.yaml has no unknown fields", True)

    print()
    if ok_all:
        print("All rule checks passed. You can run the backend tests next.")
        return 0
    print("Some checks failed. Fix the lines above and re-run: python scripts/validate_rules.py")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
