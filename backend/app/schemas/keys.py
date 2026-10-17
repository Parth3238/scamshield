"""Request and response shapes for developer API keys."""

from __future__ import annotations

import datetime

from pydantic import BaseModel, Field


class KeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=50)


class KeyCreatedOut(BaseModel):
    id: str
    name: str
    # First 12 chars of the full key, for UI recognition.
    prefix: str
    key_prefix: str
    # Shown exactly ONCE. Never stored, never returned again.
    full_key: str
    api_key: str
    daily_limit: int
    per_minute_limit: int


class KeyOut(BaseModel):
    id: str
    name: str
    prefix: str
    key_prefix: str
    daily_limit: int
    per_minute_limit: int
    revoked: bool
    # Human-friendly status plus the raw bool, for old and new clients.
    status: str
    created_at: datetime.datetime
    last_used_at: datetime.datetime | None
    last_used: datetime.datetime | None


class UsageDayOut(BaseModel):
    date: str
    count: int


class UsageOut(BaseModel):
    days: list[UsageDayOut]
    today_remaining: int
    daily_limit: int
