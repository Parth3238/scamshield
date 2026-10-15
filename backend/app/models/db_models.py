"""SQLAlchemy ORM models for users, scans, reports, campaigns and API keys."""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy import JSON as SAJSON
from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    email: Mapped[str] = mapped_column(
        String(320), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    scans: Mapped[list[Scan]] = relationship(
        back_populates="user",
        passive_deletes=True,
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        default=None,
    )
    input_type: Mapped[str] = mapped_column(String(32), nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    raw_input: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    redirect_chain: Mapped[list] = mapped_column(SAJSON, nullable=False, default=list)
    notes: Mapped[list] = mapped_column(SAJSON, nullable=False, default=list)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    findings: Mapped[list[ScanFinding]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanFinding.id",
        passive_deletes=True,
    )

    user: Mapped[User | None] = relationship(back_populates="scans")


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_code: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[int] = mapped_column(nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Indicator(Base):
    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(
        String(320), nullable=False, unique=True, index=True
    )
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="manual")
    campaign_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("campaigns.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        default=None,
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    campaign: Mapped[Campaign | None] = relationship(back_populates="indicators")


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    scam_type: Mapped[str] = mapped_column(String(32), nullable=False)
    report_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    last_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    indicators: Mapped[list[Indicator]] = relationship(
        back_populates="campaign",
        passive_deletes=True,
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="campaign",
        passive_deletes=True,
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        default=None,
    )
    campaign_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("campaigns.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        default=None,
    )
    scam_type: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    reported_value_type: Mapped[str | None] = mapped_column(
        String(16), nullable=True, default=None
    )
    reported_value: Mapped[str | None] = mapped_column(
        String(320), nullable=True, index=True, default=None
    )
    # Who submitted this, for duplicate and rate-limit grouping only.
    # "user:<id>" when logged in, "ip:<sha256>" when anonymous. Never returned.
    reporter_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True, default=None
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    reviewed_by: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        default=None,
    )
    reviewed_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )

    campaign: Mapped[Campaign | None] = relationship(back_populates="reports")


class ApiKey(Base):
    """Developer API key. Only the sha256 hash is stored, never the raw key."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    # First 12 characters of the full key, shown in the UI for recognition.
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    # sha256 hex of the full key. Look keys up by this hash only.
    key_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    daily_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=200)
    per_minute_limit: Mapped[int] = mapped_column(
        Integer, nullable=False, default=20
    )
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    last_used_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )


class ApiUsage(Base):
    """One row per API-key request, for the 14-day usage chart."""
    __tablename__ = "api_usage"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    api_key_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("api_keys.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    endpoint: Mapped[str] = mapped_column(String(128), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )


class DomainAgeCache(Base):
    """Cached RDAP creation date per registered domain.

    created_on is the domain's registration date (None when the last lookup
    failed). checked_at records when we last asked RDAP: successes are reused
    for 7 days, failures for 1 hour.
    """

    __tablename__ = "domain_age_cache"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(
        String(320), nullable=False, unique=True, index=True
    )
    created_on: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    checked_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
