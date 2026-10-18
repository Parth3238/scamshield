"""Create the first admin user by hand.

Usage: python scripts/create_admin.py admin@example.com
The password is asked with a hidden prompt (getpass).
SECRET_KEY must be set in the environment before running.
"""

from __future__ import annotations

import getpass
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.database import Base, SessionLocal, engine
from app.core.security import hash_password  # noqa: F401 - also checks SECRET_KEY
from app.models.db_models import User  # noqa: F401 - register tables
from app.schemas.auth import normalize_email


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python scripts/create_admin.py admin@example.com")
        raise SystemExit(2)
    try:
        email = normalize_email(sys.argv[1])
    except ValueError:
        print("That email address does not look valid.")
        raise SystemExit(2)
    password = getpass.getpass("Admin password (10-128 characters): ")
    if not 10 <= len(password) <= 128:
        print("Password must be 10 to 128 characters long.")
        raise SystemExit(2)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing is not None:
            print("That email is already registered.")
            raise SystemExit(1)
        db.add(
            User(
                email=email,
                password_hash=hash_password(password),
                role="admin",
                is_active=True,
            )
        )
        db.commit()
        print(f"Admin created: {email}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
