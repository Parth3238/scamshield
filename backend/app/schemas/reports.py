"""Request and response shapes for community reports and campaigns."""

from __future__ import annotations

import datetime
from typing import Literal

from pydantic import BaseModel, Field

ScamType = Literal[
    "phishing", "upi_fraud", "fake_kyc", "lottery", "digital_arrest", "other"
]


class ReportCreate(BaseModel):
    scam_type: ScamType
    content: str = Field(min_length=10, max_length=2000)
    target: str | None = Field(default=None, max_length=500)


class ReportCreatedOut(BaseModel):
    report_id: str
    status: str
    message: str


class CampaignOut(BaseModel):
    title: str
    scam_type: str
    report_count: int
    last_seen: datetime.datetime
    sample_targets: list[str]


class AdminReportOut(BaseModel):
    id: str
    scam_type: str
    content: str
    reported_value_type: str | None
    reported_value: str | None
    status: str
    created_at: datetime.datetime


class ReviewOut(BaseModel):
    report_id: str
    status: str
