"""Migration-sync: models and migrations must never drift apart.

Upgrades a fresh temporary SQLite file to head, then compares the migrated
schema with Base.metadata using Alembic's autogenerate comparison. Any model
change without a matching migration shows up as a diff and fails this test.
"""

from __future__ import annotations

import os

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from app.core.database import Base

# Importing db_models registers every table on Base.metadata.
import app.models.db_models  # noqa: F401


def _alembic_config(db_url: str) -> Config:
    here = os.path.dirname(__file__)
    cfg = Config(os.path.join(here, "..", "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_models_match_migrations(tmp_path, monkeypatch):
    db_file = tmp_path / "sync_check.db"
    db_url = f"sqlite:///{db_file}"
    # env.py reads DATABASE_URL from the environment (it overwrites the ini
    # value), so point it at the temp file for this test.
    monkeypatch.setenv("DATABASE_URL", db_url)
    command.upgrade(_alembic_config(db_url), "head")

    engine = create_engine(db_url)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection, opts={"compare_type": True}
            )
            diffs = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()
    assert diffs == [], f"models and migrations drifted apart: {diffs!r}"
