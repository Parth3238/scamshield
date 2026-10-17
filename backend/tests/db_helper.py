"""Shared test-database factory.

In-memory SQLite by default. When the TEST_DATABASE_URL environment
variable is set, tests use that PostgreSQL database instead (with a
clean schema rebuilt for every fixture) so the whole suite can run
against real PostgreSQL.

Never point TEST_DATABASE_URL at the app database: the helper drops
and recreates every table on each call.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base

# Importing db_models registers every table on Base.metadata.
import app.models.db_models  # noqa: F401


def make_test_engine():
    """Create a fresh test engine with an empty schema."""
    url = os.getenv("TEST_DATABASE_URL", "").strip()
    if url:
        engine = create_engine(url)
        # Clean schema per fixture so tests never see each other's rows.
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        return engine
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _fk(dbapi_connection, connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    return engine


def make_testing_session(engine):
    """Session factory bound to a test engine."""
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)
