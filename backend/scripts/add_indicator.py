"""Add a known-bad indicator by hand. Usage: python add_indicator.py TYPE VALUE."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.database import Base, SessionLocal, engine
from app.models.db_models import Indicator  # noqa: F401 - register tables


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: python add_indicator.py TYPE VALUE")
        print("Example: python add_indicator.py upi badguy@oksbi")
        raise SystemExit(2)
    itype = sys.argv[1].strip().lower()
    value = sys.argv[2].strip().lower()
    if itype not in ("upi", "domain", "url"):
        print("TYPE must be one of: upi, domain, url")
        raise SystemExit(2)
    if not value:
        print("VALUE must not be empty")
        raise SystemExit(2)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = (
            db.query(Indicator)
            .filter(Indicator.type == itype, Indicator.value == value)
            .first()
        )
        if existing is not None:
            print(f"Already exists: {itype} {value}")
            return
        db.add(Indicator(type=itype, value=value, confidence=100, source="manual"))
        db.commit()
        print(f"Added: {itype} {value}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
